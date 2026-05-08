#[cfg(test)]
mod elite_sandbox {
    use fluxsync_core::clock::WallClock;
    use fluxsync_core::{Action, App, Clock, Config, Event, Kind};

    struct StubWall(String);
    impl WallClock for StubWall {
        fn hhmm(&self) -> String {
            self.0.clone()
        }
        fn unix_millis(&self) -> u64 {
            0
        }
    }

    #[test]
    fn test_lamport_replay_guard() {
        let mut app = App::new(Config::default());
        let wall = StubWall("12:00".into());

        // 1. Establish current clock at 150.
        app.handle(
            Event::LocalClipboardChange {
                hash: [1; 32],
                kind: Kind::Text,
                preview: "Secret A".into(),
                sensitive: true,
                lamport: 150,
            },
            &wall,
        );

        assert!(app.clock.now() >= 150);

        // 2. Receive an event from the past (Lamport 10).
        // Current clock is ~151. 10 is way outside the 100-tick window.
        let actions = app.handle(
            Event::FrameReceivedClipboard {
                hash: [2; 32],
                kind: Kind::Text,
                preview: "Old Secret B (Leaked)".into(),
                lamport: 10,
                sensitive: false,
            },
            &wall,
        );

        // Verify that WriteClipboard was NOT emitted.
        let write_emitted = actions
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. }));
        assert!(!write_emitted, "Stale Lamport event should be rejected");

        // Verify we got a warning log instead.
        let log_emitted = actions
            .iter()
            .any(|a| matches!(a, Action::EmitLog(l) if l.msg.contains("Rejected stale item")));
        assert!(
            log_emitted,
            "Should emit a warning log for rejected stale items"
        );
    }

    #[test]
    fn test_fsm_guard_on_duplicates() {
        let mut app = App::new(Config::default());
        let wall = StubWall("12:00".into());

        // Go to Linked
        app.handle(Event::ToggleOn, &wall);
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Peer".into(),
            },
            &wall,
        );
        app.handle(Event::HandshakeOk, &wall);
        assert_eq!(app.phase, fluxsync_core::Phase::Linked);

        // Receive an item
        let hash = [123u8; 32];
        let actions = app.handle(
            Event::FrameReceivedClipboard {
                hash,
                kind: Kind::Text,
                preview: "First".into(),
                lamport: 10,
                sensitive: false,
            },
            &wall,
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. })));

        // Receive the SAME item again (duplicate)
        let actions2 = app.handle(
            Event::FrameReceivedClipboard {
                hash,
                kind: Kind::Text,
                preview: "First".into(),
                lamport: 11,
                sensitive: false,
            },
            &wall,
        );

        // Should ONLY return AckItem, no WriteClipboard, no EmitState
        assert!(actions2.iter().any(|a| matches!(a, Action::AckItem { .. })));
        assert!(!actions2
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. })));
        assert!(!actions2.iter().any(|a| matches!(a, Action::EmitState)));
    }

    #[test]
    fn test_trimming_normalization() {
        let mut app = App::new(Config::default());
        let wall = StubWall("12:00".into());

        // Push an item with trailing spaces
        app.handle(
            Event::LocalClipboardChange {
                hash: [1; 32],
                kind: Kind::Text,
                preview: "  Hello World  ".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall,
        );

        // History should contain trimmed version
        assert_eq!(app.state.history[0].preview, "Hello World");
    }
}
