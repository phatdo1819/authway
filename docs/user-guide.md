# User guide

## Install

- **Windows**: open `authway-<version>-x64-unsigned.msi` (`-arm64-unsigned.msi` on Windows on ARM), click **Next**,
  **Install** and accept the administrator prompt. When SmartScreen says *Windows protected your PC*, click **More
  info**, then **Run anyway**. With Smart App Control on, Windows refuses the package.
- **macOS** 15 or later: open `authway-<version>-macos-unsigned.pkg`, click **Continue**, **Install** and type an
  administrator password. The package isn't notarized: when macOS says it can't check it, open **System Settings →
  Privacy & Security** and click **Open Anyway**.

The packages are in the [releases](https://github.com/phatdo1819/authway/releases).

## Add a VPN and connect

1. Click **Add VPN** and choose the `.conf` file from your administrator, or drop the file on the window. Then pick
   **Connect and delete the file** (recommended: the file holds the keys), **Connect and keep the file** or **Not
   now**. A second file for the same server asks first: **Keep both** adds it as `Office 2`, **Replace** replaces the
   one there.
2. Turn on the switch of the VPN. The login window first checks the server, then asks for what the server needs:
   username and password, and the authenticator code when required. Typing the sixth digit connects.

## The app

- **The window** has a card per VPN: its switch, the server, its state (green connected; amber waiting for the login
  or the server; red refused, with what to do), and its speed and time while on. **Log in** opens the login when
  the VPN waits for it.
- **The page of a VPN** (click its card): the traffic graph, speeds, bytes, the address of the computer in the VPN
  and the routing; its name (rename it while it's off); the saved username and password, with **Forget it**; **All
  details** and **Remove this VPN**.
- **All details** shows everything, live: state, last handshake, bytes, routing, addresses, DNS, MTU, the public
  keys, the server and its fallback addresses, the login page and the session. Never a private or preshared key.
  **Copy all** copies it as text for your administrator; Ctrl+C copies the selected rows.
- **Next to the clock**: closing the window keeps the app running. Click its icon to open the window, or right-click
  for the menu: **Open Authway**, a line per VPN (a click turns it on or off, or opens the login), **Add a VPN from
  its file...** and **Quit**. With more than eight VPNs, all of them are under **All the VPNs**.
- **⋯** in the window: **Add a VPN from its file...**, the logs, **Open the window at sign-in** (on by default) and
  **Quit**.
- The window follows the text size and the display scale, works with Tab, Space and Enter, and uses the system
  colors in high contrast.

## What to expect

- **When the session ends** (it expired, or the computer changed network), the login window opens again with the
  saved password: only the code is needed. **Cancel** or **Disconnect** logs out and turns the tunnel off. Quitting
  the app turns all the tunnels off.
- **Before the login**, the VPN carries only the login page and the private networks of the office, without its DNS
  servers. The internet keeps using your own connection, so a VPN that waits for the login, or whose server doesn't
  answer, never cuts the internet. After the login, a full tunnel takes all the traffic and the DNS servers of the
  VPN. When the session ends, or the login page doesn't answer for 30 seconds, the VPN goes back to the state before
  the login.
- **Device binding**, when the server uses it: the first login enrolls this computer, and the VPN then works only
  here. Right after, the app gives the VPN a WireGuard key made by this computer (**All details** shows *Key: Made by
  this computer*); the tunnel reconnects once, within seconds. From then on the `.conf` file connects nowhere, not
  even in the official WireGuard apps. On another computer, the app says the VPN is enrolled on another device, or
  that the server doesn't answer. On a new computer, after a reinstall or after removing the VPN, ask your
  administrator to allow a new device, then add the VPN again from its file.

## On a Mac

The same window, menu and login as on Windows, with these differences:

- The app is in the menu bar. It shows in the Dock and Cmd+Tab only while its window is open; Cmd+Q quits.
- The window follows light and dark mode, and Esc goes back from the page of a VPN.
- Every user can add VPNs without an administrator password, unless the administrator chose otherwise.
- Notices go to the Notification Center: macOS asks once whether the app can show them.
- **Logs** in the menu opens them in Console.
