# FluxSync — Analyse complète du projet

> Document de référence généré depuis l'analyse de l'ensemble du dépôt.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Structure du dépôt](#2-structure-du-dépôt)
3. [Crates Rust](#3-crates-rust)
4. [Architecture technique](#4-architecture-technique)
5. [Protocole réseau](#5-protocole-réseau)
6. [Protocole IPC](#6-protocole-ipc)
7. [Machine à états (FSM)](#7-machine-à-états-fsm)
8. [Politique de batterie](#8-politique-de-batterie)
9. [Sécurité et modèle de menaces](#9-sécurité-et-modèle-de-menaces)
10. [Application Android](#10-application-android)
11. [Dépendances](#11-dépendances)
12. [Tests](#12-tests)
13. [Guide de contribution](#13-guide-de-contribution)
14. [Roadmap et limitations connues](#14-roadmap-et-limitations-connues)
15. [Licence](#15-licence)

---

## 1. Vue d'ensemble

| Attribut         | Valeur                                                      |
|------------------|-------------------------------------------------------------|
| **Nom**          | FluxSync                                                    |
| **Version**      | 0.4.2                                                       |
| **Auteur**       | Dethie \<maxleboss261@gmail.com\>                           |
| **Dépôt**        | https://github.com/dethie/fluxsync                          |
| **Licence**      | MIT                                                         |
| **Langage**      | Rust (MSRV 1.75, édition 2021)                              |
| **Description**  | Presse-papiers universel, local-first, pair-à-pair, chiffré de bout en bout |
| **Platformes**   | macOS, Windows, Linux, Android                              |

**Philosophie** : un seul daemon Rust, zéro serveur, zéro compte, zéro dépendance GUI dans le daemon. Toutes les données restent chiffrées entre les appareils explicitement appariés par l'utilisateur.

### Comparaison avec les alternatives

| Besoin                                         | KDE Connect | Apple UC | Syncthing | **FluxSync** |
|------------------------------------------------|:-----------:|:--------:|:---------:|:------------:|
| macOS / Win / Linux / Android                  | ✅           | ❌        | ✅         | ✅            |
| Chiffrement de bout en bout par défaut         | ✅           | ✅        | ✅         | ✅            |
| Zéro serveur / zéro compte                     | ✅           | ❌        | ✅         | ✅            |
| Conçu pour le presse-papiers (pas la synchro fichiers) | ✅  | ✅        | ❌         | ✅            |
| Pause automatique selon la batterie            | ❌           | partiel  | ❌         | ✅            |
| Un seul daemon Rust, pas de dépendance GUI     | ❌           | —        | ✅         | ✅            |
| Open source MIT                                | GPL         | ❌        | MPL       | ✅            |

---

## 2. Structure du dépôt

```
fluxsync/
├── Cargo.toml                  # Workspace Rust (resolver v2)
├── Cargo.lock                  # Versions exactes des dépendances
├── rust-toolchain.toml         # Canal stable, composants rustfmt + clippy
├── LICENSE                     # MIT 2026
├── README.md                   # Quickstart + architecture mermaid
├── CHANGELOG.md                # Historique semver
│
├── crates/
│   ├── fluxsync-proto/         # Types de fil et codec CBOR
│   ├── fluxsync-crypto/        # Noise IK + ChaCha20-Poly1305
│   ├── fluxsync-core/          # Logique pure : FSM, policy, dedup, horloge, classifieur
│   ├── fluxsyncd/              # Daemon tokio : UDP, IPC, presse-papiers, batterie
│   ├── fluxctl/                # CLI (parle à fluxsyncd via IPC)
│   └── fluxsync-mobile-ffi/    # Bindings UniFFI pour Kotlin/Android
│
├── apps/
│   └── android/                # Squelette Kotlin/Compose (charge le .so)
│
├── docs/
│   ├── ARCHITECTURE.md         # Architecture détaillée
│   ├── PROTOCOL.md             # Protocoles réseau et IPC
│   ├── SECURITY.md             # Modèle de menaces
│   └── CONTRIBUTING.md         # Guide de contribution
│
└── design/
    ├── README.md
    ├── project/                # Fichiers de conception (HTML, JSX, prompts)
    └── chats/                  # Historique de conception
```

---

## 3. Crates Rust

### 3.1 `fluxsync-proto` — Types de fil et codec CBOR

**Rôle** : définit tous les types partagés sur le réseau et le codec CBOR.  
**Dépendances** : `serde`, `ciborium`, `thiserror`  
**Fichiers sources** :

| Fichier        | Contenu                                         |
|----------------|-------------------------------------------------|
| `types.rs`     | `Frame`, `Msg`, `ClipboardItem`, `Chunk`, `Ack`, `Heartbeat`, `BatteryStatus`, `HandshakeInit`, `HandshakeResp`, `Kind` |
| `codec.rs`     | Encodage/décodage CBOR (longueur définie, pas de streaming indéfini) |
| `error.rs`     | `ProtoError`                                    |
| `lib.rs`       | Réexportations publiques                        |

**Tests** : `tests/` — tests de propriétés proptest (round-trip CBOR obligatoire pour chaque type)

**Contraintes de format** :
- Payload max : 256 Kio
- Chunks max : 256
- Données par chunk : 1024 octets max
- Discriminant enum : nom de variante comme texte CBOR dans une map à une clé

---

### 3.2 `fluxsync-crypto` — Identité, Noise IK, transport ChaCha20

**Rôle** : toute la cryptographie du projet.  
**Dépendances** : `snow 0.9`, `x25519-dalek 2`, `rand_core 0.6`, `blake3 1.5`, `thiserror`  
**Feature flag** : `test-util` — expose `pair_for_test` pour les tests d'intégration (jamais en production)

| Fichier           | Contenu                                             |
|-------------------|-----------------------------------------------------|
| `identity.rs`     | Génération/chargement de la paire de clés X25519 depuis le keychain |
| `session.rs`      | Wrapper Noise IK : `open_initiator`, `open_responder`, `encrypt`, `decrypt` |
| `handshake.rs`    | Drive du handshake Noise en 2 messages              |
| `fingerprint.rs`  | Dérivation de l'empreinte 6 mots (BLAKE3 → sous-ensemble BIP-39) |
| `wordlist.rs`     | 1 024 mots BIP-39 (~60 bits d'entropie)             |
| `test_util.rs`    | `pair_for_test` (derrière la feature `test-util`)   |
| `error.rs`        | `CryptoError`                                       |

**Pile cryptographique** :

| Préoccupation     | Algorithme                                          |
|-------------------|-----------------------------------------------------|
| Accord de clés    | X25519 (dans Noise IK)                              |
| AEAD              | ChaCha20-Poly1305 (RFC 8439)                        |
| Hash              | BLAKE2s (Noise interne), BLAKE3 (contenu + empreinte) |
| Patron Noise      | `Noise_IK_25519_ChaChaPoly_BLAKE2s`                 |
| Identité long terme | Paire de clés X25519 dans le keychain OS          |

**Note Android** : `blake3` est compilé en mode `pure` (Rust pur) pour Android afin d'éviter de nécessiter le NDK lors du typecheck.

---

### 3.3 `fluxsync-core` — Logique pure

**Rôle** : toute la logique métier sans I/O, sans tokio, sans horloge propre.  
**Dépendances** : `serde`, `fluxsync-proto`, `regex 1.10`, `blake3`, `thiserror`

| Fichier         | Contenu                                                          |
|-----------------|------------------------------------------------------------------|
| `app.rs`        | `App` — seul détenteur de l'état mutable                        |
| `fsm.rs`        | Machine à états à 6 états (`Idle`, `Discovering`, `Handshaking`, `Linked`, `Paused`, `Halted`) |
| `policy.rs`     | `status_for(state)` — source unique de vérité pour le statut UI |
| `dedup.rs`      | Ring buffer de 50 hashes BLAKE3 (déduplication)                 |
| `clock.rs`      | Horloge de Lamport (`u64`)                                      |
| `classify.rs`   | Classifieur de contenu : `text` / `url` / `code` + détecteur de secrets sensibles |
| `events.rs`     | Enum `Event` (entrée dans `App`) et `Action` (sortie de `App`)  |
| `state.rs`      | Struct `State` (sérialisable JSON pour les UIs)                 |
| `error.rs`      | `CoreError`                                                     |

**Détecteur de secrets sensibles** : JWT, Stripe `sk_*`, OpenAI `sk-*`, GitHub `ghp_*`, AWS `AKIA*`, hex64.

**Couverture** : 99% lignes ; 100% sur `policy.rs` et `fsm.rs`.

---

### 3.4 `fluxsyncd` — Daemon tokio

**Rôle** : runtime tokio, transport UDP, IPC, presse-papiers, batterie.  
**Dépendances** : `tokio 1` (rt-multi-thread, macros, net, sync, time, io-util, signal, fs), `serde_json`, `ciborium`, `tracing`, `tracing-subscriber`, `chrono`, `clap 4`, `anyhow`, `nix 0.28` (Unix uniquement)

| Fichier          | Contenu                                                     |
|------------------|-------------------------------------------------------------|
| `main.rs`        | Point d'entrée, parse des arguments CLI (clap), démarre le runtime |
| `driver.rs`      | Tâche `app` — fusionne tous les streams `Event`, mute l'état, émet des `Action` |
| `transport.rs`   | Tâches `transport_rx`/`transport_tx` — UDP port 41889       |
| `ipc.rs`         | Tâche `ipc_listener` + `ipc_session` — UNIX socket (Linux/macOS) / Named Pipe (Windows) |
| `cmd.rs`         | Parsing des commandes IPC et génération des réponses        |
| `config.rs`      | `DaemonConfig` (chemin IPC, port UDP, config test)          |
| `logs.rs`        | Macro `friendly!()` — double émission tracing + canal IPC `logs` |
| `wall.rs`        | Abstraction de l'heure murale                               |
| `lib.rs`         | Réexportations (pour les tests d'intégration et le FFI)     |

**Tâches tokio** :

| Tâche            | Déclencheur                | Produit / Consomme                            |
|------------------|----------------------------|-----------------------------------------------|
| `clipboard_in`   | Poll 500 ms (arboard)      | → `Event::LocalClipboardChange`               |
| `battery`        | Poll 30 s (starship-battery) | → `Event::BatteryChanged`                  |
| `discovery`      | Rescan mDNS 30 s           | → `Event::PeerSeen` / `PeerLost`              |
| `transport_rx`   | Boucle recv UDP            | déchiffre + décode → `Event::FrameReceived`   |
| `heartbeat`      | Tick 5 s                   | → `Event::Tick`                               |
| `net_change`     | Événement if-watch         | → `Event::NetworkChanged`                     |
| `ipc_listener`   | Boucle accept              | Spawne des tâches `ipc_session` par client    |
| `ipc_session`    | Par connexion CLI          | Lit `Cmd`, demande à `App`, optionnelle sub   |
| `app`            | Fusionne tous les streams  | Mute l'état, émet `Action`                    |
| `transport_tx`   | Draine `Action::Send`      | Chiffre + encode → envoi UDP                  |

**Arrêt** : un seul `tokio::sync::Notify` sur SIGINT/SIGTERM (Unix) ou Ctrl-C (Win). Aucun `unwrap()` dans le corps des tâches.

**Sécurité IPC** : socket UNIX créé avec `umask(0o077)`, permissions `0600`, répertoire parent forcé à `0700`.

---

### 3.5 `fluxctl` — CLI

**Rôle** : binaire CLI qui parle à `fluxsyncd` via IPC.  
**Dépendances** : `clap 4` (derive), `serde_json`, `tokio 1`, `anyhow`

**Commandes disponibles** :

| Commande                        | Description                                      |
|---------------------------------|--------------------------------------------------|
| `status`                        | Affiche l'état complet du daemon                 |
| `peers`                         | Liste les peers connus                           |
| `push <text>`                   | Envoie du texte au peer                          |
| `pull`                          | Récupère le dernier item du peer                 |
| `tail [--n N]`                  | Affiche les N dernières entrées de logs          |
| `set-threshold <value>`         | Définit le seuil de batterie (5..=50)            |
| `set-charge-override <bool>`    | Active/désactive le charge override              |
| `revoke <peer-id>`              | Révoque un peer (supprime sa clé du keychain)    |
| `debug-capture`                 | Capture l'état de débogage                       |
| `pair --qr`                     | Initie l'appariement par QR (stub en v0.1)       |
| `pair --accept`                 | Accepte un appariement (stub en v0.1)            |

Toutes les commandes supportent `--json` pour une sortie JSON.

---

### 3.6 `fluxsync-mobile-ffi` — Bindings UniFFI Android

**Rôle** : expose le daemon comme une bibliothèque Kotlin via UniFFI 0.27.  
**Type de crate** : `cdylib + staticlib + rlib`  
**Dépendances** : `uniffi 0.27`, `tokio 1`, `serde_json`, `base64 0.22`, `anyhow`, `tracing`, + tous les crates internes

**6 points d'entrée exposés** :

```kotlin
val h = FluxsyncHandle.start(peerName, ipcPath, udpPort, identitySecretB64)
h.observeState(observer)        // JSON verbatim par changement d'état
h.pushText("hello")
h.setBatteryThreshold(20u)      // 5..=50
h.setChargeOverride(true)
h.stop()
```

L'état est livré en JSON verbatim pour la stabilité ABI (pas de types Kotlin générés depuis la struct Rust).

---

## 4. Architecture technique

### Graphe de dépendances des crates

```
fluxsync-proto      (aucune dépendance interne)
       ▲
       ├─────────────────────┐
       │                     │
fluxsync-crypto        fluxsync-core
       ▲                     ▲
       └──────────┬──────────┘
                  │
              fluxsyncd
                  ▲
       ┌──────────┴──────────┐
       │                     │
   fluxctl           fluxsync-mobile-ffi
```

**Règle stricte** : les flèches ne vont que vers le bas. `fluxsync-core` ne connaît pas tokio. `fluxctl` ne connaît que le proto (parle à fluxsyncd via IPC, pas via du code partagé).

### Flux de données (envoi presse-papiers)

```
[Utilisateur copie "github.com"]
          ↓
fluxsyncd::clipboard     (arboard, poll 500 ms)
          ↓
fluxsync-core::classify  (kind=url, sensitive=false)
  + dedup (BLAKE3 hash)  (drop si hash dans le ring de 50)
          ↓
fluxsync-proto::Frame    (encodage CBOR)
          ↓
fluxsync-crypto::Session (chiffrement ChaCha20-Poly1305)
          ↓
fluxsyncd::transport     (UDP port 41889)
          ↓
         [LAN]
          ↓
peer fluxsyncd::transport
          ↓  (déchiffrement, décodage, dédup)
peer fluxsyncd::clipboard  (écriture arboard → StateChanged → fanout IPC)
```

### Surface d'état (format JSON pour les UIs)

```json
{
  "on": true,
  "batteryLevel": 87,
  "batteryThreshold": 15,
  "charging": false,
  "peerName": "Galaxy S21 Ultra",
  "peerBattery": 64,
  "peerCharging": false,
  "history": [
    { "kind": "url|text|code", "preview": "...", "time": "HH:MM" }
  ],
  "status": "inactive|syncing|paused|critical",
  "version": "0.4.2",
  "linkLatencyMs": 12,
  "cipher": "chacha20-poly1305"
}
```

`history` : ring buffer 50 items en RAM, le layer IPC n'en sérialise que 5 vers les UIs.

---

## 5. Protocole réseau

### Transport

- **UDP, port 41889** (`_fluxsync._udp.local` annoncé via mDNS)
- Datagramme max : 1232 octets payload (MTU IPv6 1280 − headers − overhead Noise)
- Pas de TCP ni QUIC en v0.1

### Enveloppe chiffrée (par datagramme)

```
| nonce: 12 octets | ciphertext + tag: N octets |
```

AD = `peer_id_local || peer_id_remote`

### Frame CBOR (une par datagramme décrypté)

```rust
struct Frame { version: u8, msg: Msg }

enum Msg {
    HandshakeInit(HandshakeInit),
    HandshakeResp(HandshakeResp),
    ClipboardItem(ClipboardItem),
    BatteryStatus(BatteryStatus),
    Heartbeat(Heartbeat),
    Chunk(Chunk),
    Ack(Ack),
    Bye,
}
```

### Fiabilité

- Retry `ClipboardItem` jusqu'à `Ack` correspondant, ou 5 tentatives max
- Backoff : `1s × 2^tentatives`, plafonné à 60s
- `Heartbeat` : fire-and-forget toutes les 5s
- Peer considéré hors ligne après 3 heartbeats manqués (~15s)

### Horloge de Lamport

- Compteur `u64` par pair, début à 0
- Sortant : `clock += 1`
- Entrant : `clock = max(clock, frame.lamport) + 1`
- Résolution de conflits : hash identique des deux côtés → la plus haute valeur Lamport gagne ; égalité → comparaison lexicographique du `peer_id`

---

## 6. Protocole IPC

### Transport

| Plateforme       | Implémentation                      | Chemin / nom               |
|------------------|--------------------------------------|----------------------------|
| Linux / macOS    | AF_UNIX SOCK_STREAM                  | `~/.fluxsync/sock`         |
| Windows          | Named Pipe                           | `\\.\pipe\fluxsync`        |

Format : **NDJSON** (un objet JSON par ligne).

### Canaux

Une connexion ouvre avec une ligne d'initialisation :
```json
{ "subscribe": "cmd" }     // ou "state" ou "logs"
```

**Canal `cmd`** : requête/réponse synchrone. Chaque requête a un `id` numérique qui est retourné dans la réponse.

**Canal `state`** : push serveur. Une ligne JSON complète de `State` par changement. La première ligne est toujours le snapshot courant.

**Canal `logs`** : push serveur. NDJSON `{time, level, msg}` avec niveaux `OK | INFO | SYNC | WARN | ERR`.

### Exemples de commandes IPC

```json
{ "id": 7,  "op": "status" }
{ "id": 8,  "op": "peers" }
{ "id": 9,  "op": "push",               "text": "https://github.com" }
{ "id": 10, "op": "pull" }
{ "id": 11, "op": "tail",               "n": 20 }
{ "id": 12, "op": "set_threshold",      "value": 30 }
{ "id": 13, "op": "set_charge_override","value": true }
{ "id": 16, "op": "revoke",             "peer_id": "..." }
```

### Versioning IPC

CLI et daemon sont toujours publiés ensemble. Un mismatch de version retourne :
```json
{ "ok": false, "err": "version_mismatch", "expected": "0.4.2", "got": "0.4.1" }
```

---

## 7. Machine à états (FSM)

6 états dans `fluxsync-core::fsm` :

```
boot, on=false ──▶ Idle
                     │ ToggleOn
                   Discovering ◀── PeerLost
                     │ PeerSeen
                   Handshaking
                     │ HandshakeOk
                   Linked ──── batterie basse ──▶ Paused
                     │                              │ rechargé/seuil OK
                     │ ◀─────────────────────────────┘
                     │ batterie ≤5%
                   Halted ──── ToggleOff ──▶ Idle
```

| De           | Événement                        | Vers          | Action                               |
|--------------|----------------------------------|---------------|--------------------------------------|
| Idle         | ToggleOn                         | Discovering   | Démarrer mDNS                        |
| Discovering  | PeerSeen                         | Handshaking   | Envoyer HandshakeInit                |
| Discovering  | NetworkChanged                   | Discovering   | Vider peers, redémarrer mDNS         |
| Handshaking  | FrameReceived(HandshakeResp)     | Linked        | Ouvrir Session, EmitState            |
| Handshaking  | timeout 5s                       | Discovering   | EmitLog WARN                         |
| Linked       | BatteryChanged                   | Linked/Paused | Appliquer policy                     |
| Linked       | LocalClipboardChange             | Linked        | Classifier, déduper, Envoyer         |
| Linked       | FrameReceived(ClipboardItem)     | Linked        | Déduper, écrire presse-papiers, Ack  |
| Linked       | PeerLost                         | Discovering   | EmitState (status=inactive)          |
| Linked       | batterie ≤5%                     | Halted        | EmitState (status=critical)          |
| Paused       | BatteryChanged → au-dessus seuil | Linked        | EmitState (status=syncing)           |
| Paused       | Reconnexion après offline        | Linked        | **mode burst** : envoyer 5 derniers items |
| Halted       | BatteryChanged → >5%             | Linked        | EmitState                            |
| N'importe    | ToggleOff                        | Idle          | Fermer Session, EmitState            |

---

## 8. Politique de batterie

Logique dans `fluxsync-core::policy::status_for(state)` :

```
inactive  → si !on
critical  → si peerBattery <= 5
paused    → si on && peerBattery <= threshold && !peerCharging
syncing   → sinon
```

- `charge_override` (défaut : `true`) : si le device en dessous du seuil est en charge (`peerCharging == true`), le lien reste `syncing`.
- Les deux côtés (local + peer) appliquent la même règle ; le **pire des deux** prévaut.
- Sur Android (v0.1) : réseau limité (metered) force `paused` indépendamment de la batterie.

---

## 9. Sécurité et modèle de menaces

### Pile cryptographique

| Préoccupation      | Algorithme / bibliothèque                        |
|--------------------|--------------------------------------------------|
| Accord de clés     | X25519 (Noise IK)                                |
| AEAD               | ChaCha20-Poly1305 (RFC 8439)                     |
| Hash réseau        | BLAKE2s (interne Noise)                          |
| Hash contenu       | BLAKE3                                           |
| Patron Noise       | `Noise_IK_25519_ChaChaPoly_BLAKE2s` via `snow`   |
| Identité long terme| X25519, stockée dans le keychain OS              |

### Menaces adressées

| Menace                             | Mitigation                                           |
|------------------------------------|------------------------------------------------------|
| Attaquant passif LAN               | Chiffrement E2E obligatoire, pas de fallback plaintext |
| MITM actif (ARP spoof)             | Noise IK + empreinte 6 mots (~66 bits) confirmée par l'utilisateur |
| Appareil perdu/volé                | `fluxctl revoke <peer-id>` → clé supprimée du keychain |
| Malware local (même UID)           | Clé privée jamais sur disque ; socket IPC à `0600`   |
| Replay de handshake                | Ephemerals frais à chaque session Noise              |

### Hors scope v0.1

- Attaquant root sur le host
- Side-channels (timing, analyse de puissance)
- Adversaires quantiques (X25519 non post-quantum)

### Stockage des clés par plateforme

| Plateforme | Backend                                                    |
|------------|------------------------------------------------------------|
| macOS      | Security framework, `kSecClassGenericPassword`             |
| Windows    | DPAPI / Credential Manager, `LegacyGeneric:target=app.fluxsync.identity` |
| Linux      | Secret Service (libsecret), collection `Default`           |
| Android    | Keystore, alias `fluxsync.identity` (hardware-backed si dispo) |

### Surface auditable

- Tous les appels cryptographiques : `crates/fluxsync-crypto/src/` (2 fichiers : `identity.rs`, `session.rs`)
- `unsafe` interdit partout sauf dans le shim FFI (`fluxsync-mobile-ffi/src/lib.rs`), toujours avec `// SAFETY:` explicatif
- `cargo deny` en CI refuse les crates avec vulnérabilités connues et licences incompatibles

---

## 10. Application Android

**Chemin** : `apps/android/`  
**État** : squelette v0.1 — l'UI Compose complète arrive en v0.1.1

**Ce qui est livré en v0.1** :
- Projet Gradle chargeant `libfluxsync_mobile_ffi.so` pour `arm64-v8a`
- `MainActivity` appelant `FluxsyncHandle.start(...)` et affichant le JSON d'état dans un `TextView`
- Pas de persistance, pas de notifications, pas d'UI de pairing QR

**Processus de build** :
```sh
# 1. Compiler le .so Rust pour Android
cargo install cargo-ndk
cargo ndk -t arm64-v8a build --release -p fluxsync-mobile-ffi
cp target/aarch64-linux-android/release/libfluxsync_mobile_ffi.so \
   apps/android/app/src/main/jniLibs/arm64-v8a/

# 2. Générer les bindings Kotlin
cargo install uniffi-bindgen-cli
uniffi-bindgen-cli generate --library <.so> --language kotlin --out-dir <dir>

# 3. Assembler
./gradlew assembleDebug
```

---

## 11. Dépendances

### Workspace (partagées)

| Crate        | Version | Usage                             |
|--------------|---------|-----------------------------------|
| `serde`      | 1.0     | Sérialisation (feature `derive`)  |
| `ciborium`   | 0.2     | Codec CBOR                        |
| `thiserror`  | 1.0     | Erreurs typées dans les libs      |
| `proptest`   | 1.4     | Tests de propriétés (dev)         |

### Principales dépendances par crate

**fluxsync-crypto**
- `snow 0.9` — implémentation Noise Protocol
- `x25519-dalek 2` — clés X25519
- `blake3 1.5` — hachage (mode `pure` sur Android)

**fluxsync-core**
- `regex 1.10` — détection de secrets sensibles

**fluxsyncd**
- `tokio 1` (rt-multi-thread, macros, net, sync, time, io-util, signal, fs)
- `tracing 0.1` + `tracing-subscriber 0.3` — logs structurés JSON
- `clap 4` — arguments CLI (derive)
- `chrono 0.4` — timestamps
- `nix 0.28` — permissions UNIX (umask, chmod)
- `anyhow 1` — gestion d'erreurs dans les binaires

**fluxctl**
- `clap 4` — CLI (derive)
- `tokio 1` — async IPC
- `anyhow 1`

**fluxsync-mobile-ffi**
- `uniffi 0.27` — génération bindings Kotlin
- `base64 0.22` — encodage des clés

---

## 12. Tests

### Vue d'ensemble

- **Total** : 101 tests à travers tout le workspace (v0.1.0)
- **Couverture `fluxsync-core`** : ≥ 80% lignes (gate CI : `cargo llvm-cov --fail-under-lines 80`)
- **Couverture `policy.rs` et `fsm.rs`** : 100%

### Types de tests

| Type              | Localisation                              | Description                               |
|-------------------|-------------------------------------------|-------------------------------------------|
| Unit tests        | Même fichier, `#[cfg(test)] mod tests`    | Un par module `fluxsync-core`             |
| Property tests    | Côté des types exercés (`proptest`)       | Round-trip CBOR obligatoire pour `proto`  |
| Integration tests | `crates/fluxsyncd/tests/two_daemons.rs`   | Deux daemons en loopback                  |

### Test d'intégration `two_daemons.rs`

Asserts :
- Sync < 2 secondes
- Shutdown < 500 ms
- Zéro panic (capture de `std::panic::set_hook`)

Utilise `fluxsync_crypto::pair_for_test` (feature `test-util`) pour injecter une session pré-appariée.

### Tests RFC 8439

Tests à réponse connue (KAT) pour ChaCha20-Poly1305 : §2.8.2 de la RFC 8439 verbatim.

### Commandes de test

```sh
# Tout le workspace
cargo test --workspace

# Un crate spécifique
cargo test -p fluxsync-core

# Couverture
cargo llvm-cov --workspace --fail-under-lines 80
```

---

## 13. Guide de contribution

### Prérequis

```sh
# Composants Rust
rustup component add rustfmt clippy llvm-tools-preview
cargo install cargo-llvm-cov cargo-deny

# Cross-build Android (optionnel)
rustup target add aarch64-linux-android
cargo install cross
```

**Toolchain** : stable, MSRV 1.75, épinglé dans `rust-toolchain.toml`. Pas de nightly.

### Cheatsheet quotidienne

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p fluxsyncd
cargo run -p fluxctl -- status
```

### Règles de style

- **Format** : `cargo fmt` est la loi
- **Lints** : `clippy::all` deny, `clippy::pedantic` warn
- **Erreurs** : `thiserror` pour les libs, `anyhow` pour les binaires
- **Logs** : `tracing` uniquement, JSON vers stderr
- **`unsafe`** : interdit hors FFI, toujours accompagné de `// SAFETY:`
- **Pas de `unwrap()`/`panic!()` hors `#[cfg(test)]`**

### Règle de layering (ne pas briser)

```
fluxsync-proto    →  aucun crate interne
fluxsync-crypto   →  proto
fluxsync-core     →  proto
fluxsyncd         →  core, crypto, proto
fluxctl           →  proto seulement
fluxsync-mobile-ffi → core, crypto, proto, fluxsyncd
```

### Définition de "terminé" (PR)

- [ ] `cargo fmt --check` passe
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passe
- [ ] `cargo test --workspace` passe
- [ ] La couverture du code touché ne régresse pas
- [ ] La description de PR explique le *pourquoi*
- [ ] Docs mises à jour si le comportement change

---

## 14. Roadmap et limitations connues

### Limitations v0.1

| Limitation                     | Détail                                                     |
|--------------------------------|------------------------------------------------------------|
| Pas de driver mDNS             | La FSM a les transitions mais le daemon ne trouve jamais de peer automatiquement |
| Pas de vrai `pair --qr`        | Seul `DaemonConfig::test_pair` fonctionne (intégration tests) |
| Pas de polling clipboard/batterie | `arboard` et `starship-battery` prévus pour v0.1.1      |
| Pas de persistance identité    | Nouvelle paire de clés à chaque démarrage du daemon        |
| Windows IPC stub               | Retourne `io::Error::Unsupported` ; Named Pipes en v0.1.1  |
| Android .so nécessite NDK      | Pour le build effectif (typecheck OK sans NDK)             |
| Pas d'UI Compose Android       | Seulement `MainActivity` + `TextView`                      |
| Pas de réassemblage de chunks  | `Chunk` existe dans le proto, mais le daemon ne fragmente pas encore |
| Pas de workflow CI             | Pas encore commité                                         |

### Roadmap v0.1.1

- Driver mDNS réel
- Vrai flux `pair --qr` / `--accept`
- Polling clipboard (`arboard`) et batterie (`starship-battery`) dans le daemon
- Persistance de l'identité via `keyring`
- Named Pipes Windows
- UI Compose Android
- Réassemblage de chunks pour items > MTU

### Vision v0.2+

- Mesh > 2 appareils
- Relay externe (avec les mêmes ciphertexts opaques)
- Padding et trafic de couverture (metadata)
- Suite hybride post-quantique (X25519 + Kyber768)
- Icône dans la barre système (Tauri/Qt)

### Anti-objectifs (ne pas proposer)

- Dépendance GUI dans `fluxsyncd` (daemon headless by design)
- Appel réseau hors du canal Noise documenté
- Télémétrie (d'aucune sorte)
- Feature flags qui cachent des shims de compat

---

## 15. Licence

**MIT License** — Copyright (c) 2026 Dethie

Permission accordée gratuitement d'utiliser, copier, modifier, fusionner, publier, distribuer, sous-licencier et/ou vendre des copies du logiciel, sous réserve d'inclure la notice de copyright dans toutes les copies.

---

*Document généré le 2026-05-01 depuis l'analyse complète du dépôt `flowerpower584/fluxsync`.*
