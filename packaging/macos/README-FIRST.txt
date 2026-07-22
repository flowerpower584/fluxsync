FluxSync for macOS — easy install

macOS blocks apps that are not Apple-notarized: double-clicking
FluxSync.app straight from this download shows a "damaged" warning.
The app is fine — the installer below clears the flag in one step.

How to install (30 seconds):
1. Open Terminal (Cmd+Space, type "Terminal", press Return).
2. Type:  bash
   (the word bash followed by a space)
3. Drag "Install FluxSync.command" from this folder into the Terminal
   window and press Return.
4. Done — FluxSync installs to Applications and launches. From now on,
   open it from Applications like any other app.

(Right-click -> Open on "Install FluxSync.command" can work too, but
newer macOS versions sometimes block that as well — the Terminal way
always works.)

Already saw the "damaged — move to Trash" dialog? Click Cancel (NOT
Move to Trash) and follow the steps above.

Optional: verify your download against SHA256SUMS.txt on the release
page (shasum -a 256 <file>).
