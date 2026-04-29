# PROMPT BACKEND — FluxSync v0.1
# À coller tel quel dans une nouvelle session Claude Code.

═══════════════════════════════════════════════════════════════
  FLUXSYNC — PROMPT BACKEND POUR CLAUDE CODE
  v0.1 · scope : 2 devices LAN, clipboard text/url, pause batterie
═══════════════════════════════════════════════════════════════

Tu es Claude Code. Tu vas implémenter le backend de FluxSync, un
presse-papiers universel cross-platform local-first peer-to-peer.

Le frontend (UI macOS/Windows/Linux/Android) a déjà été conçu et
défini par l'équipe design. Tu n'écris PAS d'UI. Tu écris le
daemon Rust + la CLI + le FFI Android. Les apps natives sont
des télécommandes par-dessus.

═══════════════════════════════════════════════════════════════
  ORDRE D'EXÉCUTION — STRICT
═══════════════════════════════════════════════════════════════

ÉTAPE 0 — LIRE AVANT D'ÉCRIRE
  1. Lis le frontend dans ./design/ (FluxSync.html + frame-*.jsx
     + components.jsx). Identifie le state shape exact que les UI
     attendent. Liste-le-moi.
  2. Lis docs/ARCHITECTURE.md et docs/PROTOCOL.md (ci-dessous,
     tu vas les rédiger toi-même comme premier livrable AVANT
     tout code Rust).
  3. Présente-moi un plan en 6 étapes avec checkpoints. Attends
     mon "GO" avant de coder.

ÉTAPE 1 — DOCS D'ABORD (pas de code Rust encore)
  Crée :
    docs/ARCHITECTURE.md  → vue d'ensemble, crates, dataflow
    docs/PROTOCOL.md      → wire format CBOR, frames, états
    docs/SECURITY.md      → threat model (cf. plus bas)
  CHECKPOINT 1 : montre-moi les 3 docs. Attends validation.

ÉTAPE 2 — fluxsync-proto (types + sérialisation)
  Définis tous les types CBOR : Frame, HandshakeInit, ClipboardItem,
  PeerInfo, BatteryStatus, Ack. Property-tests proptest.
  CHECKPOINT 2 : montre la structure du crate + les tests verts.

ÉTAPE 3 — fluxsync-crypto (wrapper)
  X25519 pour échange de clés, ChaCha20-Poly1305 pour symétrique,
  Noise IK pattern pour handshake. Wrapper sur `ring` ou `snow`.
  Tests : known-answer tests + round-trip.
  CHECKPOINT 3.

ÉTAPE 4 — fluxsync-core (logique métier pure, no_std si possible)
  Machine à états du sync : Idle → Discovering → Handshaking →
  Linked → Paused → Halted. Politique batterie. Dédup par hash.
  Buffer ring 50 items en mémoire.
  CHECKPOINT 4.

ÉTAPE 5 — fluxsyncd (daemon) + fluxctl (CLI)
  Daemon : tokio, mDNS via `mdns-sd`, transport UDP custom (QUIC
  reporté v0.2). Socket Unix `~/.fluxsync/sock` pour CLI ↔ daemon
  (PAS de port HTTP en v0.1).
  CLI : status, peers, tail, push, pull, pair --qr, revoke.
  Integration test : 2 daemons qui se parlent en local.
  CHECKPOINT 5.

ÉTAPE 6 — fluxsync-mobile-ffi (UniFFI pour Android)
  Expose une API Kotlin-friendly : start, stop, observe_state,
  push_text, set_battery_threshold. Pas plus.
  CHECKPOINT 6 final.

═══════════════════════════════════════════════════════════════
  STACK IMPOSÉE
═══════════════════════════════════════════════════════════════

  - Rust stable (MSRV = 1.75)
  - tokio (runtime)
  - serde + serde_cbor (sérialisation)
  - snow OU ring (crypto)
  - mdns-sd (découverte LAN)
  - clap (CLI)
  - tracing + tracing-subscriber (logs JSON)
  - uniffi 0.27+ (FFI Kotlin)
  - proptest (property tests)

  Pas de dépendance GUI. Pas de tokio-tungstenite. Pas d'axum
  (en v0.1). Socket Unix uniquement.

═══════════════════════════════════════════════════════════════
  STATE SHAPE — IMPOSÉ PAR LE FRONTEND
═══════════════════════════════════════════════════════════════

Le daemon doit exposer (via socket Unix, JSON-encoded) cet objet
exactement, parce que c'est ce que les UI consomment :

{
  "on": bool,
  "batteryLevel": u8,         // 0-100, this device
  "batteryThreshold": u8,     // 5-50, configurable
  "charging": bool,
  "peerName": String,         // ex "Galaxy S21 Ultra"
  "peerBattery": u8,
  "peerCharging": bool,
  "history": [
    { "kind": "text"|"url"|"code", "preview": String, "time": "HH:MM" }
  ],                          // max 5 retournés à l'UI, 50 en RAM
  "status": "inactive"|"syncing"|"paused"|"critical",
  "version": "0.4.2",
  "linkLatencyMs": u32,       // RTT au peer
  "cipher": "chacha20-poly1305"
}

Tout changement publie un event sur le subscribe socket — l'UI
ne fait jamais de polling.

═══════════════════════════════════════════════════════════════
  THREAT MODEL — EXPLICITE
═══════════════════════════════════════════════════════════════

  Attaquant LAN passif (sniff WiFi)
    → Ne doit voir QUE des bytes chiffrés ChaCha20.
    → Mitigation : chiffrement E2E par défaut, pas de fallback
      en clair, jamais.

  Attaquant LAN actif (MITM, ARP spoof)
    → Détecté via key fingerprint (4 safe-words style WhatsApp)
      affichés à l'appairage.
    → Mitigation : Noise IK pattern, refus de handshake sans
      fingerprint validé.

  Device compromis (téléphone volé)
    → Doit être révocable depuis un autre device sans tout
      reset.
    → Mitigation : `fluxctl revoke <peer-id>` invalide la clé
      publique du peer dans la liste locale. Au prochain
      handshake, refusé.

  Malware local (process tier sur la machine)
    → Ne doit pas pouvoir lire les clés privées.
    → Mitigation : keys dans Keychain/DPAPI/Secret Service/
      Android Keystore. Jamais en clair sur disque.

  Serveur relay (futur, pas en v0.1)
    → Zero-knowledge : ne voit que du ciphertext + métadonnées
      minimales (peer_id source/dest).

  HORS SCOPE :
    - Attaquant avec accès root sur la machine (perdu d'avance)
    - Side-channels (timing, power) — pas notre niveau
    - Quantum (on rotera vers des suites post-quantum en v2)

═══════════════════════════════════════════════════════════════
  NON-GOALS V0.1 — NE PAS IMPLÉMENTER
═══════════════════════════════════════════════════════════════

  ✗ Cloud sync centralisé
  ✗ Comptes utilisateurs
  ✗ Telemetry / analytics
  ✗ Mises à jour silencieuses (les updates sont MANUELLES)
  ✗ Browser extension
  ✗ Clipboard images/binaires (text + url + code only)
  ✗ Mesh N>2 devices (2 only en v0.1, mesh en v0.2)
  ✗ HTTP REST API publique (Unix socket only)
  ✗ SQLite chiffré (in-memory ring buffer 50 items)
  ✗ QUIC (UDP custom suffit en v0.1)
  ✗ GUI Linux dédiée (CLI + tray icon générique seulement)
  ✗ Cosign signing (v1)
  ✗ Reproducible builds (v1)
  ✗ i18n (English only)
  ✗ WASM plugin system

═══════════════════════════════════════════════════════════════
  KILLER MOVES — À IMPLÉMENTER EN V0.1
═══════════════════════════════════════════════════════════════

  [SYNC INTELLIGENT]
    - Pause auto sous seuil batterie (peer ET self)
    - Override en charge configurable (par défaut ON)
    - Pause auto sur réseau metered détecté (4G/5G)
    - Mode "burst" : à la reconnexion, ne sync que les 5 derniers
    - Conflict resolution : last-write-wins via timestamps Lamport
    - Dédup par BLAKE3 hash du contenu

  [CLIPBOARD CLASSIFIER]
    - Détection auto du `kind` :
        url   = regex /^https?:\/\// stricte
        code  = heuristique (présence \n + tokens code-like)
        text  = défaut
    - Détection "secret-like" (regex API keys, JWT, hex 64 chars)
      → flag `sensitive: true` dans l'item, jamais persisté en
      ring buffer.

  [NETWORK SELF-HEAL]
    - mDNS rescan toutes les 30s si peer offline
    - Backoff exponentiel sur échec connexion (1s, 2s, 4s, ...,
      capped 60s)
    - Détection changement réseau (network interface change)
      → flush + redécouverte
    - Heartbeat toutes les 5s, peer marqué offline après 15s

═══════════════════════════════════════════════════════════════
  STRUCTURE REPO — FIXE
═══════════════════════════════════════════════════════════════

fluxsync/
├── Cargo.toml            (workspace)
├── crates/
│   ├── fluxsync-core/        logique pure
│   ├── fluxsync-proto/       types CBOR
│   ├── fluxsync-crypto/      noise + chacha20
│   ├── fluxsyncd/            daemon
│   ├── fluxctl/              CLI
│   └── fluxsync-mobile-ffi/  UniFFI Android
├── apps/
│   └── android/              Kotlin/Compose (squelette only v0.1)
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PROTOCOL.md
│   ├── SECURITY.md
│   └── CONTRIBUTING.md
├── design/                   ne pas modifier (frontend)
├── .github/workflows/
│   └── ci.yml                build matrix Linux/macOS/Win
└── README.md

═══════════════════════════════════════════════════════════════
  CLI fluxctl — SURFACE EXACTE
═══════════════════════════════════════════════════════════════

  fluxctl status                  → state JSON (cf. shape ci-dessus)
  fluxctl peers                   → table des peers + RTT + battery
  fluxctl tail [-n 20]            → derniers events (ndjson)
  fluxctl push <text>             → injecte item dans le sync
  fluxctl pull                    → dernier item du peer (stdout)
  fluxctl pair --qr               → ASCII QR + safe-words
  fluxctl pair --code <6digits>   → fallback hors LAN (relay STUN
                                     reporté v0.2 ; v0.1 = manuel)
  fluxctl revoke <peer-id>
  fluxctl debug capture           → bundle .tar.gz redacted

  Toutes les commandes : `--json` pour output machine-readable.

═══════════════════════════════════════════════════════════════
  README — STRUCTURE OBLIGATOIRE
═══════════════════════════════════════════════════════════════

  1. Logo ASCII + tagline en une ligne
  2. Quickstart 3 commandes (install, pair, run)
  3. Schéma mermaid de l'architecture (daemon ↔ daemon)
  4. Comparaison rapide vs alternatives (tableau) :
     KDE Connect, Universal Clipboard, syncthing
  5. Threat model — résumé en 4 lignes + lien vers SECURITY.md
  6. Licence : MIT
  7. Footer, une seule ligne, sobre :
       Crafted in Kaolack, Senegal 🇸🇳

═══════════════════════════════════════════════════════════════
  TESTS — MINIMUM REQUIS
═══════════════════════════════════════════════════════════════

  - Unit tests sur fluxsync-core (>80% coverage)
  - Property tests proptest sur fluxsync-proto (round-trip CBOR)
  - Integration test : 2 daemons en process séparés se parlent
    via loopback, échangent un item, ferment proprement
  - Fuzzing cargo-fuzz sur le parser CBOR (script seulement,
    pas de run en CI v0.1)

═══════════════════════════════════════════════════════════════
  CI — V0.1 MINIMALE
═══════════════════════════════════════════════════════════════

  - Build matrix : ubuntu-latest, macos-latest, windows-latest
  - Toolchain : stable + MSRV (1.75)
  - cargo fmt --check, clippy -D warnings
  - cargo test --workspace
  - Cross Android : aarch64-linux-android (build only, pas run)
  - Release sur tag : binaires Linux/macOS/Windows en .tar.gz
  - PAS de cosign en v0.1
  - PAS de SBOM en v0.1

═══════════════════════════════════════════════════════════════
  STYLE
═══════════════════════════════════════════════════════════════

  - Anglais dans le code, commentaires, docs
  - rustfmt par défaut, clippy strict
  - Errors : `thiserror` côté lib, `anyhow` côté binaire
  - Logging : `tracing` JSON, niveaux INFO en prod, DEBUG sur
    `--verbose`
  - Pas de `unwrap()` ni `panic!()` hors tests
  - Pas d'unsafe sans commentaire SAFETY:

═══════════════════════════════════════════════════════════════
  PROCESS — RAPPEL
═══════════════════════════════════════════════════════════════

  Tu fais des CHECKPOINTS après chaque crate. Tu attends mon
  "GO" avant de passer au suivant. Tu ne génères pas tout d'un
  coup.

  Si quelque chose dans ce prompt te paraît contradictoire ou
  irréaliste, signale-le AVANT de coder.

  GO.
