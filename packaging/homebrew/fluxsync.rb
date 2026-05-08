# typed: true
# frozen_string_literal: true

# Homebrew formula for FluxSync.
#
# Lives in this repo so the source-of-truth + the install pipeline stay
# in lock-step. The published copy lives in the tap at
# `flowerpower584/homebrew-fluxsync` so that
# `brew install flowerpower584/fluxsync/fluxsync` resolves.
#
# Until pre-built bottles ship, this is a from-source build via
# `cargo install` (the workspace resolves deps once, links static).
#
# Usage:
#   brew tap flowerpower584/fluxsync
#   brew install fluxsync
#   brew services start fluxsync
class Fluxsync < Formula
  desc "Universal clipboard, local-first, peer-to-peer"
  homepage "https://github.com/flowerpower584/fluxsync"
  url "https://github.com/flowerpower584/fluxsync/archive/refs/tags/v0.5.0.tar.gz"
  sha256 "a00574c0143a316943f8dddd5c39b94d8e6b594c20b271c2444b6a689ee0280e"
  license "MIT"
  head "https://github.com/flowerpower584/fluxsync.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/fluxsyncd")
    system "cargo", "install", *std_cargo_args(path: "crates/fluxctl")

    (var/"fluxsync").mkpath
  end

  service do
    run [opt_bin/"fluxsyncd"]
    keep_alive true
    log_path var/"log/fluxsync.log"
    error_log_path var/"log/fluxsync.err"
    working_dir var/"fluxsync"
    environment_variables HOME: Dir.home
  end

  test do
    assert_match "fluxctl", shell_output("#{bin}/fluxctl --help")
    assert_match "fluxsyncd", shell_output("#{bin}/fluxsyncd --help")
  end
end
