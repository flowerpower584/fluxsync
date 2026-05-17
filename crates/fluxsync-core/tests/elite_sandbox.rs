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
    fn test_old_lamport_frame_is_accepted() {
        // FS-045: the Lamport replay window was removed. A frame carrying an
        // old Lamport stamp is a legitimate post-restart retransmit, not an
        // attack — `observe()` jumps our clock to the peer's value, so any
        // older retransmit would otherwise fail the window. Replay is already
        // covered by Noise nonces and content-hash dedup.
        let mut app = App::new(Config::default());
        let wall = StubWall("12:00".into());

        // Reach Linked so clipboard writes are produced.
        app.handle(Event::ToggleOn, &wall);
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Peer".into(),
            },
            &wall,
        );
        app.handle(Event::HandshakeOk, &wall);

        // Advance the local Lamport clock far ahead.
        app.handle(
            Event::FrameReceivedClipboard {
                hash: [1; 32],
                kind: Kind::Text,
                preview: "recent".into(),
                lamport: 150,
                sensitive: false,
            },
            &wall,
        );
        assert!(app.clock.now() >= 150);

        // A frame from far in the past must NOT be rejected.
        let actions = app.handle(
            Event::FrameReceivedClipboard {
                hash: [2; 32],
                kind: Kind::Text,
                preview: "old retransmit".into(),
                lamport: 10,
                sensitive: false,
            },
            &wall,
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::WriteClipboard { .. })),
            "old-Lamport retransmit should be written, not rejected"
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
