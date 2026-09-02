# Ember+

*[Version française](README.md)*

An **Ember+** provider for [Bobi.Studio](https://github.com/bob-integration/bobistudio), a
broadcast orchestrator built on the ST 2110 / MXL bus. It exposes the installation as an Ember+
tree, readable and writable, for a third-party broadcast controller.

---

## The tree describes SLOTS, not containers

This is the one thing to take away, and it settles everything else.

A **slot** is a production function — "MULTIVIEW GALLERY 1" — served at any given moment by the
container assigned to it. Its number is never reassigned. The Ember+ tree is built on these
slots: the path `emplacements.<num>` names the function, not the machine.

The consequence is direct. **A container can be destroyed and re-created without the controller
opposite seeing anything change** — neither path nor identifier. A machine replaced, migrated to
another node, or rebuilt after an incident keeps its Ember+ address, because that address never
named the machine.

Without this abstraction, the exposed identifier would be the container's internal handle:
disposable, changed by a mere re-creation. A controller programmed the day before would find
itself driving something else, or nothing at all — and would find out on air.

> A slot with no container assigned stays in the tree, marked `isOnline: false`, rather than
> vanishing from it. A controller therefore sees the function as offline, instead of buttons gone
> silent without it knowing.

---

## What is exposed

**Readable** — the state of the container serving each slot: hostname, status, address, type,
output flow, restart count. For a video wall, the position and size of every window are added.

**Writable** — the geometry of a wall's windows (`x`, `y`, `w`, `h`), overlay texts and
countdowns, and preset recall, by name or by rank.

**The principle extends**: any Bobi.Studio parameter can be carried into the tree. Whatever is
plugged in then inherits, at no extra cost, the property that matters — the address holds across
re-creations and replacements, because it is the slot's address.

---

## Enabling it

Settings → **Protocols → Ember+**. Two settings: the switch, and the listening port (9000 by
default). Slots are created from the same tab.

> A slot is a **production position**, therefore a decision: it is created explicitly. Nothing
> seeds slots automatically on first deployment — automatic seeding did exist, it produced slots
> by the hundred for a handful actually served, and used the hostname as the label, which is
> precisely what a slot must not be.

---

## Reading it

- `__init__.py` — the whole provider: S101 framing, BER encoding, Glow DTD, tree and server.
- `manifest.json` — the settings tab and configuration keys.
- `meta.json` — the version log.
- `settings_tab.html` — the Settings tab, slots included.

Environment variable `EMBERPLUS_DEBUG=1` logs every byte exchanged.

---

## Licence

GPL-3.0-or-later — see [LICENSE](LICENSE). Copyright © 2026 BOBI SAS, France.
