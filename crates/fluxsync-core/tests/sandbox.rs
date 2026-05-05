use fluxsync_core::app::App;
use fluxsync_core::clock::StubWallClock;
use fluxsync_core::events::Event;
use fluxsync_core::fsm::Phase;
use fluxsync_core::state::Config;

#[test]
fn test_zero_day_timeout_sandbox() {
    let mut app = App::new(Config::default());
    let wall = StubWallClock::new("12:00", 0);

    // Initial state: User toggles ON
    app.handle(Event::ToggleOn, &wall);
    assert_eq!(app.phase, Phase::Discovering);

    // User pairs with a peer
    app.handle(Event::PeerSeen { peer_id: [1; 32], name: "MacBook".into() }, &wall);
    assert_eq!(app.phase, Phase::Handshaking);

    // Handshake successful
    app.handle(Event::HandshakeOk, &wall);
    assert_eq!(app.phase, Phase::Linked);
    assert_eq!(app.state.peer_name, "MacBook");

    // Peer drops (e.g. macOS closes or resets)
    app.handle(Event::PeerLost, &wall);
    
    // We are back in Discovering, BUT peer_name is persistent so Android UI shows "Reconnecting..."
    assert_eq!(app.phase, Phase::Discovering);
    assert_eq!(app.state.peer_name, "MacBook");

    // ZERO-DAY SCENARIO: 10 seconds pass. The driver emits a Timeout.
    // We want the app to stay in Discovering (so it can find new peers)
    // but clear the peer_name (so Android UI jumps to QR code).
    
    // app.handle(Event::DiscoveringTimeout, &wall);
    // assert_eq!(app.phase, Phase::Discovering);
    // assert_eq!(app.state.peer_name, "");
}
