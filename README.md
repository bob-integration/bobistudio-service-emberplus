# Ember+

*[English version](README.en.md)*

Provider **Ember+** pour [Bobi.Studio](https://github.com/bob-integration/bobistudio), un
orchestrateur broadcast bâti sur le bus ST 2110 / MXL. Expose l'installation sous forme d'arbre
Ember+, en lecture et en écriture, pour un contrôleur broadcast tiers.

---

## L'arbre décrit des EMPLACEMENTS, pas des conteneurs

C'est le seul point à retenir, et il décide de tout le reste.

Un **emplacement** est une fonction de production — « MULTIVIEW RÉGIE 1 » — servie à un instant
donné par le conteneur qui lui est affecté. Son numéro n'est jamais réattribué. L'arbre Ember+
est bâti sur ces emplacements : le chemin `emplacements.<num>` désigne la fonction, pas la
machine.

La conséquence est directe. **On peut détruire et recréer un conteneur sans que le contrôleur
d'en face voie quoi que ce soit changer** — ni chemin, ni identifiant. Une machine remplacée,
migrée sur un autre nœud, ou reconstruite après incident garde son adresse Ember+, parce que
cette adresse n'a jamais désigné la machine.

Sans cette abstraction, l'identifiant exposé serait le handle interne du conteneur : jetable,
modifié par une simple recréation. Un contrôleur programmé la veille se retrouverait à piloter
autre chose, ou plus rien — et il l'apprendrait en direct.

> Un emplacement dont aucun conteneur n'est affecté reste dans l'arbre, marqué `isOnline: false`,
> au lieu d'en disparaître. Un contrôleur voit ainsi la fonction éteinte plutôt que des boutons
> devenus muets sans qu'il en sache rien.

---

## Ce qui est exposé

**En lecture** — l'état du conteneur servant chaque emplacement : nom d'hôte, statut, adresse,
type, flux de sortie, nombre de redémarrages. Pour un mur d'images, s'ajoutent la position et la
taille de chaque fenêtre.

**En écriture** — la géométrie des fenêtres d'un mur (`x`, `y`, `w`, `h`), les textes et les
chronos d'incrustation, et le rappel de preset, par nom ou par rang.

**Le principe est extensible** : tout paramètre de Bobi.Studio peut être porté dans l'arbre. Ce
qui vient d'être branché hérite alors, sans travail supplémentaire, de la propriété qui compte —
l'adresse tient au travers des recréations et des remplacements, parce qu'elle est celle de
l'emplacement.

---

## La matrice de routage — une exception à ce principe

L'arbre porte aussi une **matrice de routage vidéo** (chemin `[2, 1]`, avec les nœuds `sources`
`[2, 2]` et `targets` `[2, 3]`) : sources et cibles sont celles que les plugins déclarent
(crochets `ember_sources` / `ember_targets`) — au 2026-11-01 : la sortie du multiview comme source,
ses fenêtres et l'entrée du streamer comme cibles. Une connexion passe
par le câblage à chaud de la page Câbles ; une déconnexion détache l'entrée (à chaud si le plugin
le permet, sinon par redéploiement).

⚠ **Cette matrice n'est PAS adressée par emplacement.** Sources et cibles sont numérotées dans
l'ordre des conteneurs triés par leur handle interne : créer, détruire ou recréer un conteneur
peut décaler les numéros de toute la matrice. Le principe énoncé plus haut ne vaut donc que pour
l'arbre `emplacements.<num>` ; un contrôleur qui programme la matrice doit relire ses sources et
cibles après tout changement de parc.

---

## L'activer

Réglages → **Protocoles → Ember+**. Deux réglages : l'activation, et le port d'écoute
(9000 par défaut). Les emplacements se créent dans le même onglet.

> Un emplacement est une **position de production**, donc une décision : il se crée
> explicitement. Rien ne les sème automatiquement au premier déploiement — un semage automatique
> a existé, il produisait des emplacements par centaines pour une poignée réellement servis, et
> donnait pour libellé le nom d'hôte, c'est-à-dire précisément ce qu'un emplacement ne doit
> pas être.

---

## Le lire

- `__init__.py` — le provider entier : cadrage S101, encodage BER, DTD Glow, arbre et serveur.
- `manifest.json` — l'onglet de réglages et les clés de configuration.
- `meta.json` — le journal des versions.
- `settings_tab.html` — l'onglet Réglages, emplacements compris.

Variable d'environnement `EMBERPLUS_DEBUG=1` : journalise tous les octets échangés.

---

## Licence

GPL-3.0-or-later — voir [LICENSE](LICENSE). Copyright © 2026 BOBI SAS, France.
