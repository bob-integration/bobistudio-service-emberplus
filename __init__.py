# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 BOBI SAS, France
# Auteur : Cyril Mazouer, pour le compte de BOBI SAS
# Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.

"""Provider Ember+ minimal pour l'orchestrateur MXL.

L'arbre est celui des EMPLACEMENTS (table `production_roles`), pas des containers : un emplacement est
une fonction de production (« MULTIVIEW RÉGIE 1 ») dont le numéro n'est jamais réattribué,
servie par le conteneur qui lui est lié à cet instant. Réaffecter un emplacement à un autre
conteneur ne déplace aucun chemin Ember+ — c'est tout l'objet du modèle : le vmid est un
handle jetable, et un pupitre ne peut pas se reconfigurer parce qu'on a recréé une machine.

Expose en lecture l'état du conteneur servant (et, pour les multiviews, la position + taille
de chaque fenêtre). Permet l'écriture sur x/y/w/h des fenêtres multiview, les textes/chronos
d'overlay, et le rappel de preset (par nom ou par rang).

Pure Python : pas de dépendance, juste S101 framing + BER + Glow DTD.

Debug : exporter EMBERPLUS_DEBUG=1 pour logger tous les bytes échangés.
"""
import json
import logging
import math
import os
import socket
import struct
import threading
import time

log = logging.getLogger(__name__)
DEBUG = os.environ.get("EMBERPLUS_DEBUG") == "1"

# ─── S101 / Glow constantes (cf. libs101 + libember GlowType.hpp) ─────────

BOF, EOF, CE, XOR = 0xFE, 0xFF, 0xFD, 0x20
S101_INVALID_LO = 0xF8
S101_MSG_EMBER          = 0x0E
S101_CMD_PAYLOAD        = 0x00
S101_CMD_KEEPALIVE_REQ  = 0x01
S101_CMD_KEEPALIVE_RESP = 0x02
S101_VERSION            = 0x01
DTD_GLOW                = 0x01
GLOW_APP_BYTES = bytes([0x1F, 0x02])  # minor=31, major=2 → Glow 2.31

PKG_FIRST = 0x80
PKG_LAST  = 0x40
PKG_EMPTY = 0x20

S101_MAX_PAYLOAD_PER_PACKET = 1024  # cf. libs101

# Glow application tags (constructed)
G_PARAMETER             = 1
G_COMMAND               = 2
G_NODE                  = 3
G_ELEMENT_COLLECTION    = 4
G_QUAL_PARAMETER        = 9
G_QUAL_NODE             = 10
G_ROOT_ELEMENT_COLLECTION = 11

# Command numbers
CMD_SUBSCRIBE     = 30
CMD_UNSUBSCRIBE   = 31
CMD_GET_DIRECTORY = 32

# ParameterContents field tags (context)
PC_IDENTIFIER  = 0
PC_DESCRIPTION = 1
PC_VALUE       = 2
PC_MINIMUM     = 3
PC_MAXIMUM     = 4
PC_ACCESS      = 5
PC_FORMAT      = 6
PC_ENUMERATION = 7
PC_IS_ONLINE   = 9
PC_TYPE        = 13

# NodeContents field tags (context)
NC_IDENTIFIER = 0
NC_DESCRIPTION = 1
NC_IS_ROOT    = 2
NC_IS_ONLINE  = 3

ACCESS_READ      = 1
ACCESS_READWRITE = 3

PT_INTEGER = 1
PT_REAL    = 2
PT_STRING  = 3
PT_BOOLEAN = 4

# Matrix application tags (Glow DTD — source : libember_slim/Source/glow.h)
G_MATRIX       = 13   # GlowType_Matrix       (non-qualified, numéroté)
G_TARGET       = 14   # GlowType_Target       (signal target dans targets collection)
G_SOURCE_SIG   = 15   # GlowType_Source       (signal source dans sources collection)
G_CONNECTION   = 16   # GlowType_Connection   (connexion dans connections collection)
G_QUAL_MATRIX  = 17   # GlowType_QualifiedMatrix (matrice à chemin absolu RELATIVE-OID)

# MatrixContents field tags
MC_IDENTIFIER      = 0
MC_DESCRIPTION     = 1
MC_TYPE            = 2
MC_ADDRESSING_MODE = 3
MC_TARGET_COUNT    = 4
MC_SOURCE_COUNT    = 5

# Connection field tags
CN_TARGET     = 0
CN_SOURCES    = 1
CN_OPERATION  = 2

CN_OP_ABSOLUTE   = 0
CN_OP_CONNECT    = 1
CN_OP_DISCONNECT = 2

ROUTING_MATRIX_PATH  = [2, 1]   # QualifiedMatrix path (retourné sur GetDirectory([2]))
ROUTING_SOURCES_NODE = 2        # [2, 2] = nœud "sources" (Node+Param tree browser)
ROUTING_TARGETS_NODE = 3        # [2, 3] = nœud "targets"
ROUTING_PARAM_SOURCE = 1        # [2, 3, <tgt>, 1] = source num (écriture)
ROUTING_PARAM_SHM    = 2        # [2, 3, <tgt>, 2] = shm courant (lecture)

_SHM_PREFIX = "/dev/shm/"

def _shm_full(name):
    """Chemin absolu /dev/shm/<name>."""
    if not name: return ""
    return name if name.startswith(_SHM_PREFIX) else _SHM_PREFIX + name

def _shm_bare(name):
    """Nom sans le préfixe /dev/shm/. Utilisé pour stocker dans les params worker."""
    if not name: return ""
    return name[len(_SHM_PREFIX):] if name.startswith(_SHM_PREFIX) else name

# Universal BER tags (le bit constructed sera ajouté côté SEQUENCE/SET)
U_BOOL    = 1
U_INTEGER = 2
U_UTF8    = 12
U_REAL    = 9


# ═════════════════════════════════════════════════════════════════════
# BER encoder (le strict nécessaire pour Glow)
# ═════════════════════════════════════════════════════════════════════

def _ber_len(n):
    if n < 128:
        return bytes([n])
    out = bytearray()
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)

def _tlv(tag_byte, content):
    return bytes([tag_byte]) + _ber_len(len(content)) + content

def _universal_primitive(tag_num, content):
    return _tlv(tag_num & 0x1F, content)

def _universal_constructed(tag_num, content):
    return _tlv(0x20 | (tag_num & 0x1F), content)

def _app_constructed(tag_num, content):
    assert tag_num < 31, "tag application > 30 non supporté"
    return _tlv(0x60 | tag_num, content)

def _ctx_constructed(tag_num, content):
    assert tag_num < 31, "tag context > 30 non supporté"
    return _tlv(0xA0 | tag_num, content)

def _ctx_primitive(tag_num, content):
    """IMPLICIT context tag pour un type primitif (gardé pour le parsing tolérant)."""
    assert tag_num < 31, "tag context > 30 non supporté"
    return _tlv(0x80 | tag_num, content)

def _ctx_explicit(tag_num, universal_tlv):
    """EXPLICIT context tag : [Context N Constructed] wrappant un TLV universel complet.
    Format Glow.asn (EXPLICIT TAGS par défaut)."""
    return _ctx_constructed(tag_num, universal_tlv)

# Octets canoniques (sans tag/length) — utilisés pour IMPLICIT context tags
def _int_bytes(value):
    value = int(value)
    if value == 0:
        return b"\x00"
    nbytes = 1
    while True:
        try:
            data = value.to_bytes(nbytes, "big", signed=True); break
        except OverflowError:
            nbytes += 1
    while len(data) > 1 and ((data[0] == 0x00 and not (data[1] & 0x80)) or
                              (data[0] == 0xFF and (data[1] & 0x80))):
        data = data[1:]
    return data

def _bool_bytes(value):
    return b"\xff" if value else b"\x00"

def _utf8_bytes(s):
    return (s or "").encode("utf-8")

def _relative_oid_bytes(path):
    out = bytearray()
    for n in path:
        n = int(n)
        if n < 0:
            raise ValueError("RELATIVE-OID exige des entiers positifs")
        if n == 0:
            out.append(0); continue
        chunk = []
        while n:
            chunk.insert(0, n & 0x7F)
            n >>= 7
        for i in range(len(chunk) - 1):
            chunk[i] |= 0x80
        out.extend(chunk)
    return bytes(out)

# Primitives universelles (avec tag/length pour usage Value EXPLICIT)
def ber_int(value):
    return _universal_primitive(U_INTEGER, _int_bytes(value))

def ber_bool(value):
    return _universal_primitive(U_BOOL, _bool_bytes(value))

def ber_utf8(s):
    return _universal_primitive(U_UTF8, _utf8_bytes(s))

def _real_bytes(value):
    if value == 0.0:
        return b""
    if math.isinf(value):
        return b"\x40" if value > 0 else b"\x41"
    if math.isnan(value):
        return b"\x42"
    bits = struct.unpack(">Q", struct.pack(">d", value))[0]
    sign = (bits >> 63) & 1
    raw_exp = (bits >> 52) & 0x7FF
    raw_mant = bits & ((1 << 52) - 1)
    if raw_exp == 0:
        exponent = -1074; mantissa = raw_mant
    else:
        exponent = raw_exp - 1023 - 52; mantissa = raw_mant | (1 << 52)
    while mantissa and (mantissa & 1) == 0:
        mantissa >>= 1; exponent += 1
    if mantissa == 0:
        return b""
    nb_mant = max(1, (mantissa.bit_length() + 7) // 8)
    mantissa_bytes = mantissa.to_bytes(nb_mant, "big")
    if exponent >= 0:
        nb_exp = max(1, (exponent.bit_length() + 8) // 8)
    else:
        nb_exp = max(1, ((-exponent - 1).bit_length() + 8) // 8)
    exp_bytes = exponent.to_bytes(nb_exp, "big", signed=True)
    cb = 0x80
    if sign: cb |= 0x40
    if nb_exp == 1:   cb |= 0b00
    elif nb_exp == 2: cb |= 0b01
    elif nb_exp == 3: cb |= 0b10
    else:             cb |= 0b11
    if nb_exp <= 3:
        return bytes([cb]) + exp_bytes + mantissa_bytes
    return bytes([cb, nb_exp]) + exp_bytes + mantissa_bytes

def ber_real(value):
    return _universal_primitive(U_REAL, _real_bytes(value))

def ber_relative_oid(path):
    return _universal_primitive(13, _relative_oid_bytes(path))

def ber_sequence(*items):
    return _universal_constructed(16, b"".join(items))

def ber_set(*items):
    return _universal_constructed(17, b"".join(items))


# ═════════════════════════════════════════════════════════════════════
# BER decoder (juste ce qu'il faut pour parser les requêtes consumer)
# ═════════════════════════════════════════════════════════════════════

def _decode_len(buf, i):
    L = buf[i]; i += 1
    if L == 0x80:
        # indefinite — non géré côté entrée (les vrais consumers utilisent surtout définite)
        raise ValueError("BER indefinite length non supporté")
    if L & 0x80:
        n = L & 0x7F
        out = 0
        for _ in range(n):
            out = (out << 8) | buf[i]; i += 1
        return out, i
    return L, i

def _decode_tag(buf, i):
    """Renvoie (klass, constructed, tag_num, new_i). Pas de multi-byte tag (suffit pour Glow)."""
    b = buf[i]; i += 1
    klass = (b >> 6) & 0x3   # 0=univ 1=app 2=ctx 3=priv
    constructed = bool(b & 0x20)
    num = b & 0x1F
    if num == 0x1F:
        raise ValueError("BER tag long form non supporté")
    return klass, constructed, num, i

def ber_iter(buf, start=0, end=None):
    """Itère sur les TLVs successifs ; yield (klass, constructed, num, content_bytes)."""
    if end is None:
        end = len(buf)
    i = start
    while i < end:
        klass, constructed, num, i = _decode_tag(buf, i)
        L, i = _decode_len(buf, i)
        content = bytes(buf[i:i + L])
        i += L
        yield klass, constructed, num, content

def parse_int(content):
    return int.from_bytes(content, "big", signed=True) if content else 0

def parse_utf8(content):
    return content.decode("utf-8", errors="replace")

def parse_bool(content):
    return content != b"" and content[0] != 0

def parse_real(content):
    if not content:
        return 0.0
    cb = content[0]
    if cb == 0x40: return float("inf")
    if cb == 0x41: return -float("inf")
    if cb == 0x42: return float("nan")
    if not (cb & 0x80):
        # encodage décimal — flemme, parse en best-effort
        try: return float(content[1:].decode("ascii"))
        except Exception: return 0.0
    sign = -1 if (cb & 0x40) else 1
    base_code = (cb >> 4) & 0x3
    base = {0:2, 1:8, 2:16}.get(base_code, 2)
    exp_len_code = cb & 0x3
    if exp_len_code <= 2:
        exp_len = exp_len_code + 1
        exp_start = 1
    else:
        exp_len = content[1]
        exp_start = 2
    exp_bytes = content[exp_start:exp_start + exp_len]
    exponent = int.from_bytes(exp_bytes, "big", signed=True)
    mant_bytes = content[exp_start + exp_len:]
    mantissa = int.from_bytes(mant_bytes, "big") if mant_bytes else 0
    return sign * mantissa * (base ** exponent)

def parse_relative_oid(content):
    out, n = [], 0
    for b in content:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            out.append(n); n = 0
    return out


# ═════════════════════════════════════════════════════════════════════
# S101 framing
# ═════════════════════════════════════════════════════════════════════

def _crc16_ccitt(data):
    """CRC-16/X-25 (poly 0x1021 réfléchi=0x8408, init 0xFFFF, reflected I/O, final XOR 0xFFFF).
    C'est la variante utilisée par libs101 (vérifié empiriquement contre VSM)."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc & 1) else (crc >> 1)
    return (crc ^ 0xFFFF) & 0xFFFF

def _escape(buf):
    out = bytearray()
    for b in buf:
        if b >= S101_INVALID_LO:
            out.append(CE); out.append(b ^ XOR)
        else:
            out.append(b)
    return bytes(out)

def _encode_s101_packet(payload_chunk, flags):
    body = bytes([
        0x00,                # slot
        S101_MSG_EMBER,
        S101_CMD_PAYLOAD,
        S101_VERSION,
        flags,
        DTD_GLOW,
        len(GLOW_APP_BYTES)
    ]) + GLOW_APP_BYTES + payload_chunk
    crc = _crc16_ccitt(body)
    body_with_crc = body + bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    return bytes([BOF]) + _escape(body_with_crc) + bytes([EOF])

def s101_encode_ember(payload):
    """Emballe un payload BER Ember+ dans 1+ frames S101 (multi-packet si > S101_MAX_PAYLOAD_PER_PACKET)."""
    if len(payload) <= S101_MAX_PAYLOAD_PER_PACKET:
        return _encode_s101_packet(payload, PKG_FIRST | PKG_LAST)
    out = bytearray()
    pos = 0
    while pos < len(payload):
        chunk = payload[pos:pos + S101_MAX_PAYLOAD_PER_PACKET]
        flags = 0
        if pos == 0:
            flags |= PKG_FIRST
        if pos + len(chunk) >= len(payload):
            flags |= PKG_LAST
        out.extend(_encode_s101_packet(chunk, flags))
        pos += len(chunk)
    return bytes(out)

def s101_encode_keepalive_response():
    body = bytes([0x00, S101_MSG_EMBER, S101_CMD_KEEPALIVE_RESP, S101_VERSION])
    crc = _crc16_ccitt(body)
    body_with_crc = body + bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    return bytes([BOF]) + _escape(body_with_crc) + bytes([EOF])

class S101Reader:
    """Re-assemble les payloads Ember+ multi-packet depuis un stream TCP.
    Yield (kind, data) où kind ∈ {'payload', 'keepalive_req', 'keepalive_resp'}."""
    def __init__(self):
        self._buf = bytearray()
        self._in_frame = False
        self._escape = False
        self._payload_acc = bytearray()
        self._payload_active = False

    def feed(self, data):
        for b in data:
            if not self._in_frame:
                if b == BOF:
                    self._in_frame = True
                    self._buf.clear()
                continue
            if b == BOF:
                # nouveau frame en plein milieu — restart
                self._buf.clear(); self._escape = False
                continue
            if b == EOF:
                yield from self._process_frame_body()
                self._in_frame = False
                self._buf.clear()
                self._escape = False
                continue
            if self._escape:
                self._buf.append(b ^ XOR); self._escape = False
            elif b == CE:
                self._escape = True
            else:
                self._buf.append(b)

    def _process_frame_body(self):
        if len(self._buf) < 4:
            return
        payload_len = len(self._buf) - 2
        body = bytes(self._buf[:payload_len])
        crc_lo, crc_hi = self._buf[payload_len], self._buf[payload_len + 1]
        if (crc_lo | (crc_hi << 8)) != _crc16_ccitt(body):
            log.debug("emberplus: CRC mismatch sur frame entrant")
            return
        if body[1] != S101_MSG_EMBER:
            return
        cmd = body[2]
        if cmd == S101_CMD_KEEPALIVE_REQ:
            yield ("keepalive_req", b""); return
        if cmd == S101_CMD_KEEPALIVE_RESP:
            yield ("keepalive_resp", b""); return
        if cmd != S101_CMD_PAYLOAD or len(body) < 7:
            return
        flags = body[4]
        app_count = body[6]
        if len(body) < 7 + app_count:
            return
        payload = body[7 + app_count:]
        if flags & PKG_FIRST:
            self._payload_acc = bytearray(payload)
            self._payload_active = True
        elif self._payload_active:
            self._payload_acc.extend(payload)
        else:
            return
        if (flags & PKG_LAST) and self._payload_active:
            yield ("payload", bytes(self._payload_acc))
            self._payload_acc.clear()
            self._payload_active = False


# ═════════════════════════════════════════════════════════════════════
# Construction de l'arbre Ember+ depuis l'état DB
# ═════════════════════════════════════════════════════════════════════

# Indices dans le path Ember+ — choisis pour rester stables.
#
# Top-level : 1 = "emplacements"
#
# ⚠ L'arbre n'est PAS keyé sur le vmid (handle jetable : un recreate le change, un
# remplacement de conteneur encore plus) mais sur le NUMÉRO D'EMPLACEMENT — la fonction de
# production, persistée dans `production_roles` et jamais réattribuée. Réaffecter l'emplacement
# à un autre conteneur (nouveau multiview, machine remplacée) ne bouge AUCUN chemin : la
# config du pupitre en face continue de marcher, et rappeler un layout reste le même Set.
# Un emplacement sans conteneur lié reste PUBLIÉ avec isOnline=false.
#
# Sous emplacement : 1.<num>.<field>
#   1 hostname        2 status      3 ip          4 fps
#   5 type            6 script_path 7 source      8 shm_out
#   9 restarts       10 vmid       11 en_ligne
# Pour multiview : 1.<num>.100.<flux_idx>.<field>
#   1 x  2 y  3 w  4 h  5 tsl_index  6 name  7 path  8 show_label  9 show_tally

PATH_FIELD_CONTAINER = {
    1: ("hostname",   PT_STRING,  "Hostname"),
    2: ("status",     PT_STRING,  "Statut du conteneur"),
    3: ("ip",         PT_STRING,  "Adresse IP"),
    4: ("fps",        PT_REAL,    "FPS"),
    5: ("type",       PT_STRING,  "Type de script"),
    6: ("script",     PT_STRING,  "Chemin du script"),
    7: ("source",     PT_STRING,  "Source"),
    8: ("shm_out",    PT_STRING,  "SHM sortie"),
    9: ("restarts",   PT_INTEGER, "Redémarrages"),
    # vmid en LECTURE : diagnostic (« quel conteneur sert cet emplacement ? »), jamais une
    # adresse. 0 = emplacement hors ligne.
    10: ("vmid",      PT_INTEGER, "VMID servant (diagnostic)"),
    # Doublon explicite de isOnline : beaucoup de consommateurs ignorent le champ du protocole.
    11: ("en_ligne",  PT_BOOLEAN, "Emplacement servi"),
}

PATH_FIELD_FLUX = {
    1: ("x",          PT_INTEGER, "X",          True),
    2: ("y",          PT_INTEGER, "Y",          True),
    3: ("w",          PT_INTEGER, "Largeur",    True),
    4: ("h",          PT_INTEGER, "Hauteur",    True),
    5: ("tsl_index",  PT_INTEGER, "Index TSL",  False),
    6: ("name",       PT_STRING,  "Nom",        False),
    7: ("path",       PT_STRING,  "Source SHM", False),
    8: ("show_label", PT_BOOLEAN, "Label",      False),
    9: ("show_tally", PT_BOOLEAN, "Tally",      False),
}

FLUX_SUBTREE_ID = 100
# Paramètre « Recall » (rappel de preset) émis pour tout type déclarant control.recall.
# Énumération inscriptible : écrire l'index N rappelle le preset PUBLIÉ en position N.
# ⚠ L'index n'est PAS l'identité du preset : renommer/insérer un layout réordonne la liste, et
# un pupitre qui garde « 3 » rappellerait alors autre chose sans le savoir. On mémorise donc
# l'énumération telle que PUBLIÉE (_recall_snapshot) et on résout par NOM à l'écriture ; pour
# les systèmes qui préfèrent piloter par chaîne, `recall_nom` (104) prend le nom directement.
RECALL_PARAM_ID = 101
# Sous-arbre « Overlays texte » du multiview : 1.<vmid>.102.<overlay_idx> = texte (string, RW).
# Un seul champ éditable par overlay (le contenu texte). Path dédié pour ne pas collisionner
# avec les params container (1..9), le nœud flux (100) ni le recall (101).
OVERLAY_SUBTREE_ID = 102
# Sous-arbre « Chronos / décomptes » du multiview : 1.<vmid>.103.<overlay_idx>.<field>.
# Expose RÉGLAGES + DÉCLENCHEMENTS des horloges chrono/décompte. Path dédié (≠ 1..9 / 100 / 101 / 102).
#   field 1 depart  (string  RW) — point de départ HH:MM:SS (réglage, persisté + push /overlays)
#   field 2 marche  (bool    RW) — déclenche start(True)/stop(False) live via :8082/chrono
#   field 3 raz     (bool    RW) — déclenche reset live (momentané, toujours lu False)
CHRONO_SUBTREE_ID = 103
# Rappel PAR NOM : 1.<num>.104 (string, RW). Écrire « Layout demi-finale » rappelle ce
# layout-là, quel que soit son rang dans la liste. Adressage recommandé pour les scripts.
RECALL_NAME_PARAM_ID = 104

# Énumération de recall telle que PUBLIÉE, par emplacement : {num: [noms]}. Remplie à chaque
# construction d'arbre, lue à l'écriture pour traduire l'index reçu en NOM de preset.
_recall_snapshot = {}


def _gather_routing_sources():
    """Retourne [(num, label, shm_name, vmid)] — toutes les shm vidéo disponibles comme sources.
    Délégué aux hooks ember_sources de chaque plugin."""
    from app.database import db_get_containers
    from app import plugins as _plg
    result = []
    num = 1
    for c in sorted(db_get_containers(), key=lambda x: x["vmid"]):
        ctype = _container_type(c.get("deploy_config"))
        hook = _plg.get_hook(ctype, "ember_sources")
        if not hook:
            continue
        try:
            dc = json.loads(c["deploy_config"]) if c.get("deploy_config") else {}
            params = dc.get("params") or {}
            ctx = {"vmid": c["vmid"], "type": ctype, "hostname": c.get("hostname", "")}
            for s in hook(params, ctx):
                result.append((num, s["label"], _shm_full(s["shm"]), c["vmid"]))
                num += 1
        except Exception:
            pass
    return result


def _gather_routing_targets():
    """Retourne [(num, label, vmid, slot_type, slot_idx, current_shm)] — tous les consommateurs de shm.
    Délégué aux hooks ember_targets de chaque plugin."""
    from app.database import db_get_containers
    from app import plugins as _plg
    result = []
    num = 1
    for c in sorted(db_get_containers(), key=lambda x: x["vmid"]):
        ctype = _container_type(c.get("deploy_config"))
        hook = _plg.get_hook(ctype, "ember_targets")
        if not hook:
            continue
        try:
            dc = json.loads(c["deploy_config"]) if c.get("deploy_config") else {}
            params = dc.get("params") or {}
            ctx = {"vmid": c["vmid"], "type": ctype, "hostname": c.get("hostname", "")}
            for t in hook(params, ctx):
                result.append((num, t["label"], c["vmid"],
                               t["slot_type"], t["slot_idx"], _shm_full(t["shm"])))
                num += 1
        except Exception:
            pass
    return result


def _encode_value_explicit(ptype, raw):
    """Encode la Value en EXPLICIT [Context PC_VALUE] (CHOICE → exige explicit tagging)."""
    if ptype == PT_INTEGER:
        return ber_int(raw if raw is not None else 0)
    if ptype == PT_REAL:
        try: return ber_real(float(raw) if raw is not None else 0.0)
        except Exception: return ber_real(0.0)
    if ptype == PT_BOOLEAN:
        return ber_bool(bool(raw))
    return ber_utf8(str(raw) if raw is not None else "")

def _parameter_contents_set(identifier, description, raw_value, ptype, access, enumeration=None,
                            online=True):
    """ParameterContents = SET universel (tag 0x31) contenant chaque champ EXPLICIT-taggé.
    Convention Glow.asn (module EXPLICIT TAGS). `enumeration` = liste d'étiquettes ;
    si fournie, émet PC_ENUMERATION (entrées séparées par '\\n', l'index = la valeur entière)."""
    fields = (
        _ctx_explicit(PC_IDENTIFIER,  ber_utf8(identifier)) +
        _ctx_explicit(PC_DESCRIPTION, ber_utf8(description)) +
        _ctx_explicit(PC_VALUE,       _encode_value_explicit(ptype, raw_value)) +
        _ctx_explicit(PC_ACCESS,      ber_int(access))
    )
    if enumeration:
        fields += _ctx_explicit(PC_ENUMERATION, ber_utf8("\n".join(enumeration)))
    fields += (
        _ctx_explicit(PC_IS_ONLINE,   ber_bool(bool(online))) +
        _ctx_explicit(PC_TYPE,        ber_int(ptype))
    )
    return _universal_constructed(17, fields)  # SET universel

def _qual_parameter(path, identifier, description, raw_value, ptype, writeable, enumeration=None,
                    online=True):
    access = ACCESS_READWRITE if writeable else ACCESS_READ
    contents_set = _parameter_contents_set(identifier, description, raw_value, ptype, access,
                                           enumeration, online=online)
    return _app_constructed(G_QUAL_PARAMETER,
        _ctx_explicit(0, ber_relative_oid(path)) +
        _ctx_explicit(1, contents_set))

def _node_contents_set(identifier, description="", online=True):
    """NodeContents = SET universel contenant les champs EXPLICIT-taggés.
    `online=False` : la branche EXISTE mais n'est pas servie (emplacement sans conteneur lié).
    C'est le point du modèle par emplacements : une branche qui DISPARAÎT laisse le pupitre
    en face avec des boutons morts sans le savoir."""
    fields = _ctx_explicit(NC_IDENTIFIER, ber_utf8(identifier))
    if description:
        fields += _ctx_explicit(NC_DESCRIPTION, ber_utf8(description))
    fields += _ctx_explicit(NC_IS_ONLINE, ber_bool(bool(online)))
    return _universal_constructed(17, fields)  # SET universel

def _qual_node(path, identifier, description="", children_bytes=b"", online=True):
    """children_bytes : déjà-encodé séquence de [Context 0] EXPLICIT element wrappers."""
    body = (_ctx_explicit(0, ber_relative_oid(path)) +
            _ctx_explicit(1, _node_contents_set(identifier, description, online=online)))
    if children_bytes:
        # children [2] EXPLICIT ElementCollection ([App 4] IMPLICIT SEQUENCE OF [0] Element)
        ec = _app_constructed(G_ELEMENT_COLLECTION, children_bytes)
        body += _ctx_explicit(2, ec)
    return _app_constructed(G_QUAL_NODE, body)

def _container_type(deploy_config_json):
    if not deploy_config_json: return ""
    try:
        dc = json.loads(deploy_config_json) if isinstance(deploy_config_json, str) else deploy_config_json
        return (dc or {}).get("type", "") or ""
    except Exception:
        return ""

def _flux_list(deploy_config_json):
    try:
        dc = json.loads(deploy_config_json) if isinstance(deploy_config_json, str) else deploy_config_json
        return ((dc or {}).get("params") or {}).get("flux_config") or []
    except Exception:
        return []

def _overlay_list(deploy_config_json):
    try:
        dc = json.loads(deploy_config_json) if isinstance(deploy_config_json, str) else deploy_config_json
        return ((dc or {}).get("params") or {}).get("overlays") or []
    except Exception:
        return []

def _chrono_overlays(deploy_config_json):
    """[(idx, overlay)] des overlays horloge pilotables (chrono / décompte) d'un multiview.
    L'index est la position RÉELLE dans params.overlays (apply_setvalue le réutilise)."""
    out = []
    for i, ov in enumerate(_overlay_list(deploy_config_json)):
        if ov.get("kind") == "clock" and ov.get("clock_source") in ("chrono", "countdown"):
            out.append((i, ov))
    return out


def _enumerate_elements():
    """Itère sur tous les éléments de l'arbre sous forme (path, kind, *args).
    kind ∈ {'node', 'param'} ; args = (identifier, description[, raw_value, ptype, writeable]).

    L'arbre est celui des EMPLACEMENTS : une branche par ligne de `production_roles`, adressée par son
    numéro (jamais réattribué), et non par le vmid du conteneur qui la sert à cet instant."""
    from app.database import db_roles_with_containers
    yield ([1], 'node', 'emplacements', 'Emplacements de production')
    for role, c in db_roles_with_containers():
        num = role["num"]
        online = c is not None
        label = role.get("label") or role["key"]
        desc = label if online else f"{label} (hors ligne)"
        yield ([1, num], 'node', role["key"], desc, online)
        dcfg = c.get("deploy_config") if online else None
        ctype = _container_type(dcfg)
        for sub_id, (field, ptype, pdesc) in PATH_FIELD_CONTAINER.items():
            if field == "type":
                raw = ctype or (role.get("expect_type") or "")
            elif field == "vmid":
                raw = c.get("vmid") if online else 0
            elif field == "en_ligne":
                raw = online
            else:
                raw = c.get(field) if online else None
            yield ([1, num, sub_id], 'param', field, pdesc, raw, ptype, False, None, online)
        if not online:
            # Hors ligne : on s'arrête aux champs d'état. Publier des fenêtres/overlays d'un
            # conteneur absent inventerait une topologie — la branche existe, elle est vide.
            _recall_snapshot.pop(num, None)
            continue
        vmid = c["vmid"]
        # Paramètre « Recall » pour tout type déclarant control.recall (DVE, correcteur,
        # multiview…) : énumération des presets disponibles, écriture = rappel à chaud.
        names = _recall_names(vmid, ctype)
        if names is not None:
            _recall_snapshot[num] = list(names)
            yield ([1, num, RECALL_PARAM_ID], 'param', 'recall', 'Rappel preset (par rang)',
                   0, PT_INTEGER, True, names)
            yield ([1, num, RECALL_NAME_PARAM_ID], 'param', 'recall_nom',
                   'Rappel preset (par nom)', "", PT_STRING, True)
        else:
            _recall_snapshot.pop(num, None)
        flux = _flux_list(dcfg)
        if flux:
            yield ([1, num, FLUX_SUBTREE_ID], 'node', 'flux', 'Fenêtres multiview')
            for i, f in enumerate(flux):
                yield ([1, num, FLUX_SUBTREE_ID, i], 'node',
                       f.get("name") or f"flux_{i}", f"Fenêtre #{i}")
                for sub_id, (field, ptype, pdesc, writeable) in PATH_FIELD_FLUX.items():
                    yield ([1, num, FLUX_SUBTREE_ID, i, sub_id], 'param',
                           field, pdesc, f.get(field), ptype, writeable)
        # Overlays texte (text_source local) : un param string inscriptible par overlay.
        # Index = position RÉELLE dans params.overlays (pas l'index parmi les seuls texte),
        # pour que apply_setvalue retrouve le bon overlay sans ré-indexation.
        overlays = _overlay_list(dcfg)
        editable = [(i, ov) for i, ov in enumerate(overlays)
                    if ov.get("kind") == "text" and (ov.get("text_source") or "local") == "local"]
        if editable:
            yield ([1, num, OVERLAY_SUBTREE_ID], 'node', 'overlays', 'Overlays texte')
            for i, ov in editable:
                txt = ov.get("text") or ""
                odesc = txt.replace("\n", " ")[:32] or f"Overlay #{i}"
                yield ([1, num, OVERLAY_SUBTREE_ID, i], 'param',
                       f"texte_{i}", odesc, txt, PT_STRING, True)
        # Chronos / décomptes : réglages (départ) + déclenchements (marche/raz) inscriptibles.
        chronos = _chrono_overlays(dcfg)
        if chronos:
            yield ([1, num, CHRONO_SUBTREE_ID], 'node', 'chronos', 'Chronos / décomptes')
            for i, ov in chronos:
                is_cd = ov.get("clock_source") == "countdown"
                kind_lbl = "Décompte" if is_cd else "Chrono"
                nm = ov.get("name") or f"{kind_lbl} #{i}"
                yield ([1, num, CHRONO_SUBTREE_ID, i], 'node', f"{kind_lbl.lower()}_{i}", nm)
                yield ([1, num, CHRONO_SUBTREE_ID, i, 1], 'param',
                       'depart', 'Départ (HH:MM:SS)', ov.get("chrono_start") or "00:00:00",
                       PT_STRING, True)
                yield ([1, num, CHRONO_SUBTREE_ID, i, 2], 'param',
                       'marche', 'Marche (départ/arrêt)', bool(ov.get("chrono_running")),
                       PT_BOOLEAN, True)
                yield ([1, num, CHRONO_SUBTREE_ID, i, 3], 'param',
                       'raz', 'Réinitialiser', False, PT_BOOLEAN, True)


def _role_vmid(num):
    """vmid du conteneur servant l'emplacement `num`, ou None (emplacement hors ligne).
    Point de passage UNIQUE des écritures : le chemin Ember+ ne connaît que l'emplacement."""
    from app.database import db_role_container
    try:
        c = db_role_container(num)
    except Exception as e:
        log.warning(f"emberplus: résolution emplacement {num} échouée : {e}")
        return None
    if not c:
        log.warning(f"emberplus: emplacement {num} hors ligne — écriture ignorée")
        return None
    return c["vmid"]


def _recall_names(vmid, ctype):
    """Liste des noms de presets rappelables pour ce container, ou None si le type
    ne déclare pas control.recall. Best-effort (l'arbre ne doit jamais planter)."""
    try:
        from app.routes import recall_presets
        rc, presets = recall_presets(vmid, ctype)
        if not rc:
            return None
        return [str(p.get("name") or f"#{i}") for i, p in enumerate(presets)]
    except Exception as e:
        log.debug(f"emberplus: _recall_names({vmid},{ctype}) échec : {e}")
        return None

def _encode_element(path, kind, *args):
    if kind == 'node':
        # node : (identifier, description[, online])
        identifier, description = args[:2]
        online = args[2] if len(args) > 2 else True
        return _qual_node(path, identifier, description, online=online)
    # param : (identifier, description, raw_value, ptype, writeable[, enumeration[, online]])
    identifier, description, raw_value, ptype, writeable = args[:5]
    enumeration = args[5] if len(args) > 5 else None
    online = args[6] if len(args) > 6 else True
    return _qual_parameter(path, identifier, description, raw_value, ptype, writeable,
                           enumeration, online=online)

def _enumerate_routing_elements():
    """Génère les nœuds/paramètres du sous-arbre routing [2] en Node+Parameter standard.
    Évite le type Matrix [App 14] que VSM ne reconnaît pas au niveau nœud."""
    sources = _gather_routing_sources()
    targets = _gather_routing_targets()
    shm_to_src = {shm: num for num, label, shm, vmid in sources}

    yield ([2], 'node', 'routing', 'Routing MXL')

    yield ([2, ROUTING_SOURCES_NODE], 'node', 'sources', 'Sources disponibles')
    for num, label, shm, vmid in sources:
        yield ([2, ROUTING_SOURCES_NODE, num], 'node', label, f'Source {num}')
        yield ([2, ROUTING_SOURCES_NODE, num, 1], 'param', 'shm', 'SHM', shm, PT_STRING, False)

    yield ([2, ROUTING_TARGETS_NODE], 'node', 'targets', 'Destinations')
    for num, label, vmid, slot_type, slot_idx, current_shm in targets:
        src_num = shm_to_src.get(current_shm, 0)
        yield ([2, ROUTING_TARGETS_NODE, num], 'node', label, f'Destination {num}')
        yield ([2, ROUTING_TARGETS_NODE, num, ROUTING_PARAM_SOURCE], 'param',
               'source', 'Source (numéro)', src_num, PT_INTEGER, True)
        yield ([2, ROUTING_TARGETS_NODE, num, ROUTING_PARAM_SHM], 'param',
               'shm', 'SHM courant', current_shm, PT_STRING, False)


def _matrix_contents_set(identifier, description, n_targets, n_sources):
    """MatrixContents = SET universel avec champs EXPLICIT-taggés."""
    fields = (
        _ctx_explicit(MC_IDENTIFIER,      ber_utf8(identifier)) +
        _ctx_explicit(MC_DESCRIPTION,     ber_utf8(description)) +
        _ctx_explicit(MC_TYPE,            ber_int(0)) +   # oneToN
        _ctx_explicit(MC_ADDRESSING_MODE, ber_int(0)) +   # linear
        _ctx_explicit(MC_TARGET_COUNT,    ber_int(n_targets)) +
        _ctx_explicit(MC_SOURCE_COUNT,    ber_int(n_sources))
    )
    return _universal_constructed(17, fields)


def _signal_target(number, identifier):
    """Target signal — GlowType_Target = App 14."""
    body = _ctx_explicit(0, ber_int(number))
    if identifier:
        body += _ctx_explicit(1, ber_utf8(identifier))
    return _app_constructed(G_TARGET, body)


def _signal_source(number, identifier):
    """Source signal — App 15 dans le contexte d'une collection sources de matrix."""
    body = _ctx_explicit(0, ber_int(number))
    if identifier:
        body += _ctx_explicit(1, ber_utf8(identifier))
    return _app_constructed(G_SOURCE_SIG, body)


def _connection_ber(target_num, source_nums, operation=CN_OP_ABSOLUTE):
    """Connection BER — App 16 : target → liste de sources actuellement connectées."""
    src_content = b"".join(ber_int(s) for s in source_nums)
    body = (
        _ctx_explicit(CN_TARGET,    ber_int(target_num)) +
        _ctx_explicit(CN_SOURCES,   _universal_constructed(16, src_content)) +
        _ctx_explicit(CN_OPERATION, ber_int(operation))
    )
    return _app_constructed(G_CONNECTION, body)


def _encode_routing_matrix():
    """Construit le QualifiedMatrix complet (path [2,1]) avec sources, targets et connexions courantes."""
    sources = _gather_routing_sources()
    targets = _gather_routing_targets()

    contents = _matrix_contents_set(
        "mxl_matrix", "Matrice de routage MXL",
        len(targets), len(sources)
    )

    tgt_items = b"".join(
        _ctx_explicit(0, _signal_target(num, label))
        for num, label, *_ in targets
    )
    src_items = b"".join(
        _ctx_explicit(0, _signal_source(num, label))
        for num, label, *_ in sources
    )

    shm_to_src = {shm: num for num, label, shm, vmid in sources}
    conn_items = b""
    for num, label, vmid, slot_type, slot_idx, current_shm in targets:
        src_num = shm_to_src.get(current_shm)
        conn_items += _ctx_explicit(0, _connection_ber(num, [src_num] if src_num else []))

    body = (
        _ctx_explicit(0, ber_relative_oid(ROUTING_MATRIX_PATH)) +
        _ctx_explicit(1, contents) +
        _ctx_explicit(3, _app_constructed(G_ELEMENT_COLLECTION, tgt_items)) +
        _ctx_explicit(4, _app_constructed(G_ELEMENT_COLLECTION, src_items)) +
        _ctx_explicit(5, _app_constructed(G_ELEMENT_COLLECTION, conn_items))
    )
    return _app_constructed(G_QUAL_MATRIX, body)


def _wrap_single_element(element_bytes):
    """Encapsule un seul élément BER dans [App 0]→[App 11]→[Ctx 0]→element."""
    wrapped = _ctx_explicit(0, element_bytes)
    rec = _app_constructed(G_ROOT_ELEMENT_COLLECTION, wrapped)
    return _app_constructed(0, rec)


def _routing_matrix_response():
    """Réponse à GetDirectory([2]) ou GetDirectory([2,1]) : uniquement la QualifiedMatrix.
    Pas de nœud parent [App 10] dans la même réponse — VSM rejetait la combinaison
    nœud+matrice ; la matrice seule passe."""
    try:
        return _wrap_single_element(_encode_routing_matrix())
    except Exception as e:
        log.warning(f"emberplus: encode_routing_matrix échoué : {e}")
        return build_root_collection()


def build_directory_response(target_path):
    """Réponse à GetDirectory(path) :
    - path == [2] ou [2,1]   → uniquement la QualifiedMatrix path=[2,1]
    - sinon                  → arbre complet (emplacements)"""
    if target_path == [2] or target_path == ROUTING_MATRIX_PATH:
        return _routing_matrix_response()
    return build_root_collection()


def build_root_collection():
    """Arbre complet wrappé en [App 0] Root choice.
    Contient des QualifiedNode/QualifiedParameter (App 9/10) ET la QualifiedMatrix (App 17).
    Le tag 17 est le bon GlowType_QualifiedMatrix — plus de confusion avec Target (14)."""
    wrapped = b""
    for path, kind, *args in _enumerate_elements():
        wrapped += _ctx_explicit(0, _encode_element(path, kind, *args))
    # Routing Node+Param tree (visible dans le tree browser VSM)
    # QualifiedMatrix [App 17] NON incluse ici — VSM déconnecte si elle apparaît
    # dans la RootElementCollection initiale. Elle est retournée uniquement sur GetDirectory([2]).
    try:
        for path, kind, *args in _enumerate_routing_elements():
            wrapped += _ctx_explicit(0, _encode_element(path, kind, *args))
    except Exception as e:
        log.warning(f"emberplus: routing elements build échoué : {e}")
    rec = _app_constructed(G_ROOT_ELEMENT_COLLECTION, wrapped)
    return _app_constructed(0, rec)  # [App 0] Root wrapper


# ═════════════════════════════════════════════════════════════════════
# Décodage des requêtes consumer (GetDirectory, Subscribe, SetValue)
# ═════════════════════════════════════════════════════════════════════

def _ctx_unwrap(constructed, content, universal_tag):
    """Récupère le contenu primitif d'un champ context-taggé, qu'il soit IMPLICIT ou EXPLICIT.
    IMPLICIT (primitive) → content = octets bruts.
    EXPLICIT (constructed) → content contient un universal TLV ; on retourne son contenu."""
    if not constructed:
        return content
    for k, _, n, c in ber_iter(content):
        if k == 0 and n == universal_tag:
            return c
    return content

def _walk_elements(content):
    """Itère sur les éléments d'une ElementCollection (libember : wrappés en [Context 0]).
    Tolère aussi une SEQUENCE universelle qui contient les éléments."""
    for k, _, n, c in ber_iter(content):
        if k == 2 and n == 0:
            # [Context 0] : peut contenir directement l'app-tag, ou une SEQUENCE
            inner = list(ber_iter(c))
            if len(inner) == 1 and inner[0][0] == 0 and inner[0][2] == 16:
                # SEQUENCE → re-itérer ses entrées
                for k3, _, n3, c3 in ber_iter(inner[0][3]):
                    yield k3, n3, c3
            else:
                for k2, _, n2, c2 in inner:
                    yield k2, n2, c2
        elif k == 0 and n == 16:
            # SEQUENCE non-tagué (variante)
            for k2, _, n2, c2 in ber_iter(c):
                yield k2, n2, c2
        else:
            # Élément directement présent (sans wrapper)
            yield k, n, c

def parse_root(body):
    """Retourne une liste d'actions extraites du root reçu :
    [{"kind":"getdir","path":[...]},
     {"kind":"subscribe","path":[...]},
     {"kind":"unsubscribe","path":[...]},
     {"kind":"setvalue","path":[...],"value": <python value>, "ptype": int|None}]
    Accepte les messages wrappés en [Application 0] (Root) ou directement [App 11]."""
    actions = []
    for klass, _, num, content in ber_iter(body):
        if klass == 1 and num == 0:
            # Wrapper [App 0] Root : descendre dedans pour trouver la RootElementCollection
            for k, _, n, c in ber_iter(content):
                if k == 1 and n == G_ROOT_ELEMENT_COLLECTION:
                    _parse_root_collection(c, actions)
        elif klass == 1 and num == G_ROOT_ELEMENT_COLLECTION:
            _parse_root_collection(content, actions)
    return actions

def _parse_root_collection(content, actions):
    for k, n, c in _walk_elements(content):
        _handle_root_element(k, n, c, actions)

def _handle_root_element(klass, num, content, actions):
    if klass != 1: return
    if num == G_QUAL_PARAMETER:
        _handle_qual_parameter(content, actions)
    elif num == G_QUAL_NODE:
        _handle_qual_node(content, actions)
    elif num == G_QUAL_MATRIX:
        _handle_qual_matrix(content, actions)
    elif num == G_COMMAND:
        # Command directement à la racine = "act on root" (path vide)
        _scan_for_command(klass, num, content, [], actions)
    elif num in (G_NODE, G_PARAMETER):
        # Format non-qualifié (VSM) : hiérarchie imbriquée Node/Parameter avec integer number
        _handle_nonqual_element(klass, num, content, [], actions)

def _handle_nonqual_element(klass, num, content, path, actions):
    """Parser récursif pour le format non-qualifié (VSM) :
    Node=[App 3] et Parameter=[App 1] avec integer number dans [Ctx 0].
    Reconstruit le chemin absolu en descendant la hiérarchie imbriquée."""
    if klass != 1:
        return
    if num == G_NODE:
        node_num = None
        children_raw = None
        for k, constructed, n, c in ber_iter(content):
            if k == 2 and n == 0:
                node_num = parse_int(_ctx_unwrap(constructed, c, U_INTEGER))
            elif k == 2 and n == 2:
                children_raw = c
        if node_num is None or children_raw is None:
            return
        child_path = path + [node_num]
        for k, _, n, c in ber_iter(children_raw):
            if k == 1 and n == G_ELEMENT_COLLECTION:
                for k2, n2, c2 in _walk_elements(c):
                    _handle_nonqual_element(k2, n2, c2, child_path, actions)
    elif num == G_PARAMETER:
        param_num = None
        new_value = None
        ptype = None
        children_raw = None
        for k, constructed, n, c in ber_iter(content):
            if k == 2 and n == 0:
                param_num = parse_int(_ctx_unwrap(constructed, c, U_INTEGER))
            elif k == 2 and n == 1:
                inner = list(ber_iter(c))
                if len(inner) == 1 and inner[0][0] == 0 and inner[0][2] == 17:
                    fields_iter = ber_iter(inner[0][3])
                else:
                    fields_iter = ber_iter(c)
                for k2, c2_constructed, n2, c2 in fields_iter:
                    if k2 == 2 and n2 == PC_VALUE:
                        for k3, _, n3, c3 in ber_iter(c2):
                            if k3 == 0:
                                if n3 == U_INTEGER:  new_value, ptype = parse_int(c3), PT_INTEGER
                                elif n3 == U_REAL:   new_value, ptype = parse_real(c3), PT_REAL
                                elif n3 == U_UTF8:   new_value, ptype = parse_utf8(c3), PT_STRING
                                elif n3 == U_BOOL:   new_value, ptype = parse_bool(c3), PT_BOOLEAN
                    elif k2 == 2 and n2 == PC_TYPE and ptype is None:
                        ptype = parse_int(_ctx_unwrap(c2_constructed, c2, 2))
            elif k == 2 and n == 2:
                children_raw = c
        if param_num is not None and new_value is not None:
            actions.append({"kind": "setvalue", "path": path + [param_num],
                            "value": new_value, "ptype": ptype})
        if param_num is not None and children_raw is not None:
            param_path = path + [param_num]
            for k, _, n, c in ber_iter(children_raw):
                if k == 1 and n == G_ELEMENT_COLLECTION:
                    for k2, n2, c2 in _walk_elements(c):
                        _handle_nonqual_element(k2, n2, c2, param_path, actions)
    elif num == G_COMMAND:
        _scan_for_command(klass, num, content, path, actions)

def _handle_qual_node(content, actions):
    path = []
    children_content = None
    for k, constructed, n, c in ber_iter(content):
        if k == 2 and n == 0:
            path = parse_relative_oid(_ctx_unwrap(constructed, c, 13))
        elif k == 2 and n == 2:
            children_content = c
    if children_content is not None:
        for k, n, c in _walk_elements(children_content):
            _scan_for_command(k, n, c, path, actions)
            if k == 1 and n == G_ELEMENT_COLLECTION:
                for k2, n2, c2 in _walk_elements(c):
                    _scan_for_command(k2, n2, c2, path, actions)

def _handle_qual_matrix(content, actions):
    """Parse un QualifiedMatrix entrant (VSM → connexions de routage)."""
    path = []
    connections_raw = None
    for k, constructed, n, c in ber_iter(content):
        if k == 2 and n == 0:
            path = parse_relative_oid(_ctx_unwrap(constructed, c, 13))
        elif k == 2 and n == 5:  # [Ctx 5] connections
            connections_raw = c
    if connections_raw is None:
        # GetDirectory sur la matrice → on répond avec le full tree (déjà géré par subscribe)
        if path:
            actions.append({"kind": "getdir", "path": path})
        return
    # Itérer sur les Connection (App 16) dans la collection
    for k, n, c in _walk_elements(connections_raw):
        if k == 1 and n == G_CONNECTION:
            _parse_connection_element(path, c, actions)
    # Si la collection est vide, tenter un parcours direct
    if not any(a["kind"] == "connect" for a in actions):
        for k, constructed, n, c in ber_iter(connections_raw):
            if k == 1 and n == G_CONNECTION:
                _parse_connection_element(path, c, actions)
            elif k == 1 and n == G_ELEMENT_COLLECTION:
                for k2, n2, c2 in _walk_elements(c):
                    if k2 == 1 and n2 == G_CONNECTION:
                        _parse_connection_element(path, c2, actions)


def _parse_connection_element(matrix_path, content, actions):
    target_num = None
    source_nums = []
    operation = CN_OP_ABSOLUTE
    for k, constructed, n, c in ber_iter(content):
        if k == 2 and n == CN_TARGET:
            target_num = parse_int(_ctx_unwrap(constructed, c, U_INTEGER))
        elif k == 2 and n == CN_SOURCES:
            # [Ctx 1] EXPLICIT contient une SEQUENCE universelle d'INTEGERs
            inner = c if not constructed else None
            if constructed:
                for k2, _, n2, c2 in ber_iter(c):
                    if k2 == 0 and n2 == 16:  # SEQUENCE
                        for k3, _, n3, c3 in ber_iter(c2):
                            if k3 == 0 and n3 == U_INTEGER:
                                source_nums.append(parse_int(c3))
                    elif k2 == 0 and n2 == U_INTEGER:
                        source_nums.append(parse_int(c2))
            else:
                for k2, _, n2, c2 in ber_iter(c):
                    if k2 == 0 and n2 == U_INTEGER:
                        source_nums.append(parse_int(c2))
        elif k == 2 and n == CN_OPERATION:
            operation = parse_int(_ctx_unwrap(constructed, c, U_INTEGER))
    if target_num is not None:
        actions.append({
            "kind": "connect",
            "matrix_path": matrix_path,
            "target": target_num,
            "sources": source_nums,
            "operation": operation,
        })


def _handle_qual_parameter(content, actions):
    path = []
    new_value = None
    ptype = None
    children_content = None
    for k, constructed, n, c in ber_iter(content):
        if k == 2 and n == 0:
            path = parse_relative_oid(_ctx_unwrap(constructed, c, 13))
        elif k == 2 and n == 1:
            # ParameterContents : peut être EXPLICIT (contient universal SET) ou IMPLICIT (champs directs).
            inner = list(ber_iter(c))
            if len(inner) == 1 and inner[0][0] == 0 and inner[0][2] == 17:
                fields_iter = ber_iter(inner[0][3])
            else:
                fields_iter = ber_iter(c)
            for k2, c2_constructed, n2, c2 in fields_iter:
                if k2 == 2 and n2 == PC_VALUE:
                    # VALUE est EXPLICIT (CHOICE) : c2 contient un universal TLV
                    for k3, _, n3, c3 in ber_iter(c2):
                        if k3 == 0:
                            if n3 == U_INTEGER:  new_value, ptype = parse_int(c3), PT_INTEGER
                            elif n3 == U_REAL:   new_value, ptype = parse_real(c3), PT_REAL
                            elif n3 == U_UTF8:   new_value, ptype = parse_utf8(c3), PT_STRING
                            elif n3 == U_BOOL:   new_value, ptype = parse_bool(c3), PT_BOOLEAN
                elif k2 == 2 and n2 == PC_TYPE and ptype is None:
                    ptype = parse_int(_ctx_unwrap(c2_constructed, c2, 2))
        elif k == 2 and n == 2:
            children_content = c
    if path and new_value is not None:
        actions.append({"kind": "setvalue", "path": path, "value": new_value, "ptype": ptype})
    if children_content is not None:
        for k, n, c in _walk_elements(children_content):
            _scan_for_command(k, n, c, path, actions)
            if k == 1 and n == G_ELEMENT_COLLECTION:
                for k2, n2, c2 in _walk_elements(c):
                    _scan_for_command(k2, n2, c2, path, actions)

def _scan_for_command(klass, num, content, path, actions):
    if klass != 1 or num != G_COMMAND: return
    cmd_num = None
    for k, constructed, n, c in ber_iter(content):
        if k == 2 and n == 0:
            cmd_num = parse_int(_ctx_unwrap(constructed, c, 2))
    if cmd_num == CMD_GET_DIRECTORY:
        actions.append({"kind": "getdir", "path": path})
    elif cmd_num == CMD_SUBSCRIBE:
        actions.append({"kind": "subscribe", "path": path})
    elif cmd_num == CMD_UNSUBSCRIBE:
        actions.append({"kind": "unsubscribe", "path": path})


# ═════════════════════════════════════════════════════════════════════
# Application d'un SetValue venant d'Ember+ : on n'autorise QUE x/y/w/h flux
# ═════════════════════════════════════════════════════════════════════

def _push_overlays(vmid, overlays):
    """Pousse à chaud la liste d'overlays au script multiview (:8082/overlays, remplacement atomique)."""
    try:
        from app.addressing import get_container_ip
        import requests as _req
        ip = get_container_ip(vmid)
        if ip:
            _req.post(f"http://{ip}:8082/overlays", json={"overlays": overlays}, timeout=2)
    except Exception as e:
        log.warning(f"emberplus: push /overlays {vmid} échec : {e}")


def _push_chrono(vmid, cid, action):
    """Déclenche un chrono/décompte à chaud (:8082/chrono, {id, action}). True si 200."""
    try:
        from app.addressing import get_container_ip
        import requests as _req
        ip = get_container_ip(vmid)
        if not ip:
            return False
        r = _req.post(f"http://{ip}:8082/chrono", json={"id": cid, "action": action}, timeout=2)
        return r.status_code == 200
    except Exception as e:
        log.warning(f"emberplus: push /chrono {vmid} échec : {e}")
        return False


def _recall_by_name(vmid, ctype, name):
    """Rappelle le preset dont le NOM correspond (insensible à la casse/espaces de bord).
    Retourne (ok, detail). Le nom est l'identité stable d'un preset : le RANG, lui, bouge
    dès qu'on insère ou renomme un layout — un pupitre qui garde un rang se trompe alors
    de rappel sans aucun signal."""
    try:
        from app.routes import recall_presets, recall_preset
        _rc, presets = recall_presets(vmid, ctype)
    except Exception as e:
        return False, f"liste des presets illisible : {e}"
    want = str(name).strip().lower()
    idx = next((i for i, p in enumerate(presets)
                if str(p.get("name") or "").strip().lower() == want), None)
    if idx is None:
        dispo = ", ".join(str(p.get("name")) for p in presets) or "aucun"
        return False, f"preset « {name} » introuvable (disponibles : {dispo})"
    try:
        return recall_preset(vmid, ctype, idx)
    except Exception as e:
        return False, f"rappel échoué : {e}"


def apply_setvalue(path, value):
    """Applique une écriture Ember+ autorisée À CHAUD (sans redeploy) :
    routing, géométrie multiview x/y/w/h, et rappel de preset. Retourne True si appliqué."""
    # Routing : [2, 3, target_num, ROUTING_PARAM_SOURCE]
    if len(path) == 4 and path[0] == 2 and path[1] == ROUTING_TARGETS_NODE and path[3] == ROUTING_PARAM_SOURCE:
        target_num = path[2]
        source_num = int(value)
        if source_num == 0:
            return apply_connect(ROUTING_MATRIX_PATH, target_num, [], CN_OP_DISCONNECT)
        return apply_connect(ROUTING_MATRIX_PATH, target_num, [source_num], CN_OP_ABSOLUTE)

    # Rappel de preset : [1, num, 101] par RANG (traduit en nom via l'énumération publiée),
    # [1, num, 104] par NOM directement. Dans les deux cas c'est le NOM qui décide.
    if len(path) == 3 and path[0] == 1 and path[2] in (RECALL_PARAM_ID, RECALL_NAME_PARAM_ID):
        num = path[1]
        vmid = _role_vmid(num)
        if not vmid:
            return False
        from app.database import db_get_container
        c = db_get_container(vmid)
        if not c:
            return False
        ctype = _container_type(c.get("deploy_config"))
        if path[2] == RECALL_NAME_PARAM_ID:
            name = str(value)
        else:
            # Rang → nom, d'après l'énumération TELLE QUE PUBLIÉE à cet emplacement. Sans ce
            # détour, un layout inséré ou renommé décale ce que « 3 » rappelle, en silence.
            snap = _recall_snapshot.get(num) or []
            idx = int(value)
            if not (0 <= idx < len(snap)):
                log.warning(f"emberplus: recall emplacement {num} rang {idx} hors énumération "
                            f"publiée ({len(snap)} entrées)")
                return False
            name = snap[idx]
        ok, detail = _recall_by_name(vmid, ctype, name)
        if ok:
            notify_change()
        else:
            log.warning(f"emberplus: recall emplacement {num} (#{vmid} {ctype}) "
                        f"« {name} » : {detail}")
        return ok

    # Texte d'overlay multiview à chaud : [1, num, 102, overlay_idx]
    if len(path) == 4 and path[0] == 1 and path[2] == OVERLAY_SUBTREE_ID:
        vmid, overlay_idx = _role_vmid(path[1]), path[3]
        if not vmid:
            return False
        from app.database import db_get_container, db_update_deploy_config
        c = db_get_container(vmid)
        if not c:
            return False
        try:
            dc = json.loads(c["deploy_config"]) if c.get("deploy_config") else None
        except Exception:
            return False
        if not dc or dc.get("type") != "multiview":
            return False
        params = dc.get("params") or {}
        overlays = params.get("overlays") or []
        if not (0 <= overlay_idx < len(overlays)):
            return False
        if overlays[overlay_idx].get("kind") != "text":
            return False
        overlays[overlay_idx]["text"] = str(value)
        # 1) persister (durabilité au prochain redeploy) SANS relancer le script
        db_update_deploy_config(vmid, dc["type"], params)
        # 2) pousser à chaud via :8082/overlays — remplacement ATOMIQUE de toute la liste
        # (contrat du plugin, pas de patch partiel). POST direct (cf. note _mixer_proxy plus bas).
        try:
            from app.addressing import get_container_ip
            import requests as _req
            ip = get_container_ip(vmid)
            if ip:
                _req.post(f"http://{ip}:8082/overlays",
                          json={"overlays": overlays}, timeout=2)
        except Exception as e:
            log.warning(f"emberplus: push /overlays {vmid} échec : {e}")
        # 3) ack immédiat aux subscribers
        notify_change()
        return True

    # Chrono / décompte multiview : [1, num, 103, overlay_idx, field_id]
    #   1 depart (réglage : persiste + push /overlays) ; 2 marche (start/stop) ; 3 raz (reset)
    if len(path) == 5 and path[0] == 1 and path[2] == CHRONO_SUBTREE_ID:
        vmid, overlay_idx, field_id = _role_vmid(path[1]), path[3], path[4]
        if not vmid:
            return False
        from app.database import db_get_container, db_update_deploy_config
        c = db_get_container(vmid)
        if not c:
            return False
        try:
            dc = json.loads(c["deploy_config"]) if c.get("deploy_config") else None
        except Exception:
            return False
        if not dc or dc.get("type") != "multiview":
            return False
        params = dc.get("params") or {}
        overlays = params.get("overlays") or []
        if not (0 <= overlay_idx < len(overlays)):
            return False
        ov = overlays[overlay_idx]
        if ov.get("kind") != "clock" or ov.get("clock_source") not in ("chrono", "countdown"):
            return False
        cid = ov.get("id")

        if field_id == 1:   # départ (réglage) : persister + push atomique de la liste
            ov["chrono_start"] = str(value)
            db_update_deploy_config(vmid, dc["type"], params)
            _push_overlays(vmid, overlays)
            notify_change()
            return True
        # marche / raz = déclenchements LIVE via :8082/chrono (comme les boutons de l'éditeur)
        if field_id == 2:
            action = "start" if value else "stop"
            ov["chrono_running"] = bool(value)   # refléter l'état lu dans l'arbre
            db_update_deploy_config(vmid, dc["type"], params)
        elif field_id == 3:
            action = "reset"
            ov["chrono_running"] = False         # raz = arrêt : refléter dans l'arbre (marche → false)
            db_update_deploy_config(vmid, dc["type"], params)
        else:
            return False
        ok = _push_chrono(vmid, cid, action)
        notify_change()
        return ok

    # Géométrie multiview à chaud : [1, num, 100, flux_idx, field_id]
    if len(path) != 5 or path[0] != 1 or path[2] != FLUX_SUBTREE_ID:
        return False
    vmid, flux_idx, field_id = _role_vmid(path[1]), path[3], path[4]
    if not vmid:
        return False
    if field_id not in (1, 2, 3, 4):  # x, y, w, h uniquement
        return False
    field = PATH_FIELD_FLUX[field_id][0]

    from app.database import db_get_container, db_update_deploy_config
    c = db_get_container(vmid)
    if not c: return False
    try:
        dc = json.loads(c["deploy_config"]) if c.get("deploy_config") else None
    except Exception:
        return False
    if not dc or dc.get("type") != "multiview":
        return False
    flux = (dc.get("params") or {}).get("flux_config") or []
    if not (0 <= flux_idx < len(flux)):
        return False

    # Largeur/hauteur paires (cf. contraintes YUV)
    nv = int(value)
    if field in ("w", "h"):
        nv = max(2, nv - (nv % 2))
    if field in ("x", "y"):
        nv = max(0, nv)
    flux[flux_idx][field] = nv
    # 1) persister (durabilité au prochain redeploy) SANS relancer le script
    db_update_deploy_config(vmid, dc["type"], dc["params"])
    # 2) pousser la géométrie à chaud via :8082/window (pas de redeploy → pas de glitch).
    # POST direct (pas _mixer_proxy : il renvoie du Flask/jsonify, hors contexte d'app ici).
    try:
        from app.addressing import get_container_ip
        import requests as _req
        ip = get_container_ip(vmid)
        if ip:
            _req.post(f"http://{ip}:8082/window",
                      json={"idx": flux_idx, field: nv}, timeout=2)
    except Exception as e:
        log.warning(f"emberplus: push /window {vmid} échec : {e}")
    # 3) ack immédiat aux subscribers (VSM attend un retour)
    notify_change()
    return True


def apply_connect(matrix_path, target_num, source_nums, operation):
    """Applique un routage Ember+ À CHAUD en réutilisant le câblage de la page Câbles
    (`routes._apply_wire`, qui persiste + décide hot/redeploy par type). Déconnexion =
    détacher à chaud (`_try_unwire_hot`, fallback redeploy). Retourne True si appliqué."""
    if matrix_path != ROUTING_MATRIX_PATH:
        return False
    targets = _gather_routing_targets()
    target_info = next((t for t in targets if t[0] == target_num), None)
    if not target_info:
        log.warning(f"emberplus: connect: target {target_num} introuvable")
        return False
    _, _, vmid, slot_type, slot_idx, _ = target_info
    to_slot = slot_idx if slot_type == "multiview_window" else None

    disconnect = operation == CN_OP_DISCONNECT or not source_nums

    # ── Connexion : délègue au câblage à chaud (shm bare, _apply_wire préfixe au besoin) ──
    if not disconnect:
        source_info = next((s for s in _gather_routing_sources() if s[0] == source_nums[0]), None)
        if not source_info:
            log.warning(f"emberplus: connect: source {source_nums[0]} introuvable")
            return False
        from_vmid, new_shm = source_info[3], source_info[2]
        from app.routes.cabling import _apply_wire
        ok, status, payload = _apply_wire(from_vmid, vmid, _shm_bare(new_shm), "video", to_slot=to_slot)
        if ok:
            notify_change()
            log.info(f"emberplus: connect vmid={vmid} {slot_type}[{slot_idx}] ← shm={new_shm!r} ({payload})")
        else:
            log.warning(f"emberplus: connect vmid={vmid} échec : {payload}")
        return ok

    # ── Déconnexion : détacher à chaud, fallback redeploy ──
    from app.database import db_get_container, db_update_deploy_config
    from app.routes.cabling import _try_unwire_hot
    c = db_get_container(vmid)
    if not c:
        return False
    try:
        dc = json.loads(c["deploy_config"]) if c.get("deploy_config") else None
    except Exception:
        return False
    if not dc:
        return False
    from app import plugins as _plg
    ctype = dc.get("type")
    hook = _plg.get_hook(ctype, "ember_clear_slot")
    if not hook:
        return False
    result = hook(slot_type, slot_idx, dict(dc.get("params") or {}),
                  {"vmid": vmid, "type": ctype})
    if not result:
        return False
    params = result["params"]
    body   = result["body"]

    if _try_unwire_hot(vmid, c, dc["type"], params, body) is None:
        # pas de détach à chaud possible → persister + redéployer
        db_update_deploy_config(vmid, dc["type"], params)
        def _redeploy():
            try:
                from app.deploy import deployer_script
                deployer_script(vmid, dc["type"], params)
            except Exception as e:
                log.error(f"emberplus: disconnect redeploy {vmid} échoué : {e}")
        threading.Thread(target=_redeploy, daemon=True).start()
    notify_change()
    log.info(f"emberplus: disconnect vmid={vmid} {slot_type}[{slot_idx}]")
    return True


# ═════════════════════════════════════════════════════════════════════
# Serveur TCP avec gestion des connexions / subscriptions
# ═════════════════════════════════════════════════════════════════════

_lock = threading.Lock()
_clients = set()               # connexions actives
_subscribed = set()            # sockets ayant souscrit au broadcast
_server_thread = None
_server_socket = None
_running = False
_notify_timer = None           # threading.Timer pour debounce notify_change
_notify_pending = False
NOTIFY_DEBOUNCE_S = 1.0        # max 1 broadcast / seconde
_status = {
    "running": False,
    "port": 0,
    "clients": 0,
    "subscribed": 0,
    "last_error": None,
    "started_at": None,
}

def status_dict():
    with _lock:
        _status["clients"] = len(_clients)
        _status["subscribed"] = len(_subscribed)
        return dict(_status)

def _send_frame(sock, body):
    try:
        wire = s101_encode_ember(body)
        if DEBUG:
            log.info(f"emberplus: → {sock.getpeername()} {len(wire)} bytes ({len(body)} BER)")
        sock.sendall(wire)
        return True
    except Exception as e:
        log.debug(f"emberplus: send échoué : {e}")
        return False

def _echo_param(sock, path):
    """Renvoie IMMÉDIATEMENT (hors débounce) l'élément à `path` avec sa valeur courante,
    en réponse directe à un SetValue accepté. Beaucoup de consommateurs (arbre de gadgets)
    ne rafraîchissent leur affichage qu'au reçu de ce report ciblé du paramètre modifié ;
    le broadcast full-tree débouncé ne suffit pas. Best-effort, ne lève jamais."""
    try:
        gens = (_enumerate_elements(), _enumerate_routing_elements())
        for gen in gens:
            for p, kind, *args in gen:
                if p == path:
                    _send_frame(sock, _wrap_single_element(_encode_element(p, kind, *args)))
                    return True
    except Exception as e:
        log.debug(f"emberplus: echo param {path} échoué : {e}")
    return False

def _broadcast_full_tree():
    """Envoie le root collection à tous les clients abonnés (push après changement)."""
    try:
        body = build_root_collection()
    except Exception as e:
        log.error(f"emberplus: build_root_collection échoué : {e}")
        return
    with _lock:
        dead = []
        for s in list(_subscribed):
            if not _send_frame(s, body):
                dead.append(s)
        for s in dead:
            _subscribed.discard(s)

def notify_change():
    """À appeler quand l'état d'un container change. Débounce : max 1 broadcast/sec."""
    global _notify_timer, _notify_pending
    if not _running:
        return
    with _lock:
        if _notify_timer is not None:
            _notify_pending = True
            return
        _notify_pending = False
        def _fire():
            global _notify_timer, _notify_pending
            try:
                _broadcast_full_tree()
            finally:
                with _lock:
                    _notify_timer = None
                    repeat = _notify_pending
                    _notify_pending = False
                if repeat:
                    notify_change()
        _notify_timer = threading.Timer(NOTIFY_DEBOUNCE_S, _fire)
        _notify_timer.daemon = True
        _notify_timer.start()

def _handle_client(sock, addr):
    log.info(f"emberplus: client {addr} connecté")
    reader = S101Reader()
    sock.settimeout(60.0)
    try:
        # Push initial de l'arbre containers + nœud routing [2]
        full = build_root_collection()
        log.info(f"emberplus: push initial à {addr} ({len(full)} bytes BER)")
        _send_frame(sock, full)
        while _running:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            if not data:
                break
            if DEBUG:
                log.info(f"emberplus: ← {addr} {len(data)} bytes: {data.hex()}")
            for kind, payload in reader.feed(data):
                _process_message(sock, addr, kind, payload)
    except Exception as e:
        log.warning(f"emberplus: client {addr} erreur : {e}")
    finally:
        with _lock:
            _clients.discard(sock)
            _subscribed.discard(sock)
        try: sock.close()
        except Exception: pass
        log.info(f"emberplus: client {addr} déconnecté")

def _process_message(sock, addr, kind, payload):
    if kind == "keepalive_req":
        log.debug(f"emberplus: keepalive ← {addr}")
        try: sock.sendall(s101_encode_keepalive_response())
        except Exception: pass
        return
    if kind != "payload":
        return
    if DEBUG:
        log.info(f"emberplus: payload BER {addr} ({len(payload)} bytes): {payload.hex()}")
    try:
        actions = parse_root(payload)
    except Exception as e:
        log.warning(f"emberplus: parse root erreur depuis {addr} : {e}")
        return
    log.info(f"emberplus: {addr} → actions {actions}")
    for a in actions:
        if a["kind"] == "getdir":
            with _lock:
                _subscribed.add(sock)
            response = build_directory_response(a["path"])
            log.info(f"emberplus: GetDirectory({a['path']}) → réponse {len(response)} bytes BER")
            _send_frame(sock, response)
        elif a["kind"] == "subscribe":
            with _lock:
                _subscribed.add(sock)
            # Subscribe seul : on accuse réception en renvoyant le subtree demandé
            _send_frame(sock, build_directory_response(a["path"]))
        elif a["kind"] == "unsubscribe":
            with _lock:
                _subscribed.discard(sock)
        elif a["kind"] == "setvalue":
            if apply_setvalue(a["path"], a["value"]):
                # Report ciblé du paramètre modifié à l'émetteur (l'arbre de gadgets en a besoin
                # pour rafraîchir sa valeur affichée — départ, texte, états marche/raz).
                _echo_param(sock, a["path"])
        elif a["kind"] == "connect":
            apply_connect(a["matrix_path"], a["target"], a["sources"], a["operation"])

def _server_loop(port):
    global _server_socket, _running
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        s.listen(8)
        s.settimeout(1.0)
    except Exception as e:
        _status["last_error"] = f"bind: {e}"
        _status["running"] = False
        _running = False
        log.error(f"emberplus: bind sur {port} échoué : {e}")
        return
    _server_socket = s
    _status["running"] = True
    _status["port"] = port
    _status["last_error"] = None
    _status["started_at"] = time.time()
    log.info(f"emberplus: serveur lancé sur :{port}")
    while _running:
        try:
            conn, addr = s.accept()
        except socket.timeout:
            continue
        except Exception as e:
            if _running:
                log.warning(f"emberplus: accept erreur : {e}")
            break
        with _lock:
            _clients.add(conn)
        threading.Thread(target=_handle_client, args=(conn, addr), daemon=True).start()
    try: s.close()
    except Exception: pass
    _status["running"] = False
    log.info("emberplus: serveur arrêté")

def start(port):
    """Démarre le serveur. Si déjà actif sur un autre port, le redémarre."""
    global _server_thread, _running
    stop()
    _running = True
    _server_thread = threading.Thread(target=_server_loop, args=(int(port),), daemon=True)
    _server_thread.start()

def stop():
    """Arrête le serveur ; les clients sont fermés."""
    global _running, _server_thread
    if not _running:
        return
    _running = False
    with _lock:
        for sock in list(_clients):
            try: sock.close()
            except Exception: pass
        _clients.clear()
        _subscribed.clear()
    if _server_socket:
        try: _server_socket.close()
        except Exception: pass
    if _server_thread:
        _server_thread.join(timeout=2)
    _server_thread = None
    _status["running"] = False

def is_running():
    return _running


# ─── Core plugin manifest ─────────────────────────────────────────────

__manifest__ = {
    "id":            "emberplus",
    "label":         "Ember+",
    "nav_tab":       "protocoles",
    "tab_group":     "protocoles",
    "tab_order":     1,
    "tab_template":  "settings_tabs/emberplus_sub.html",
    "settings_keys": {
        "emberplus_enabled": {"type": "bool", "default": False},
        "emberplus_port":    {"type": "int",  "default": 9000},
    },
}


def register_routes(bp):
    from flask import request, jsonify
    from app.auth import require_login, require_perm
    from app.database import db_get_setting, db_set_setting

    @bp.route("/api/emberplus/status", methods=["GET"])
    @require_login
    def emberplus_status():
        st = status_dict()
        st["enabled_setting"] = bool(db_get_setting("emberplus_enabled", False))
        st["port_setting"] = int(db_get_setting("emberplus_port", 9000) or 9000)
        return jsonify(st)

    @bp.route("/api/emberplus/apply", methods=["POST"])
    @require_perm("settings.edit")
    def emberplus_apply():
        data = request.json or {}
        enabled = bool(data.get("enabled"))
        port = int(data.get("port") or 9000)
        if not (1 <= port <= 65535):
            return jsonify({"error": "port invalide"}), 400
        db_set_setting("emberplus_enabled", enabled)
        db_set_setting("emberplus_port", port)
        if enabled:
            start(port)
        else:
            stop()
        return jsonify(status_dict())
