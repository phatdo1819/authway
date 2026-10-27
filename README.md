# Authway

A WireGuard VPN client for Windows 10 and 11, and macOS 11 or later ([below](#macos)), in one app: it connects the
tunnel and, for the servers that require it, logs in with username, password and the code of an authenticator app,
then keeps watching the session. It works
with the WireGuard servers of a NethSecurity firewall that use the login of
[ns-wgauth](https://github.com/phatdo1819/nethsecurity/tree/ci-wgauth/packages/ns-wgauth), and with any other
WireGuard server, without a login.

> [!WARNING]
> **This project was written by an AI** (Claude, by Anthropic), directed and tested by one person. No security
> expert has reviewed it, and it hasn't been tested against a real NethSecurity server yet. A VPN client handles
> your traffic and your passwords: read the code before you trust it, and use it at your own risk.

To set up the firewall side and test both together, follow
[WGAUTH-TESTING.md](https://github.com/phatdo1819/nethsecurity/blob/ci-wgauth/WGAUTH-TESTING.md) on the
`ci-wgauth` branch of the NethSecurity fork: steps 1–7 for the login, step 8 for the fallback addresses.

All the names of the app are in [src/product.rs](src/product.rs), and the name of the exe is in
[Cargo.toml](Cargo.toml): to rename it, change them there.

## For the users

1. Open `authway-<version>-x64.msi`, or `-arm64.msi` on a Windows on ARM computer, and click **Next**,
   **Install**. Windows asks for the permission of an administrator, once.
2. The app is next to the clock, and starts at every sign-in. Right-click its icon, **Add a VPN from its file...**,
   and choose the `.conf` file of the administrator. The app saves it protected and offers to delete the file.
3. **Connect**: the window asks for username, password and code while the tunnel comes up. The sixth digit of the
   code connects.

When the session ends on the firewall (it expired, or the computer changed network), the window opens again with the
username and the saved password: only the code is needed. **Cancel** or **Disconnect** turns the tunnel off; the
app logs out first. Quitting the app turns the tunnels off.

**Details...**, under each VPN in the menu, shows all of it, live: the state, the last handshake and the bytes; the
routing, a full tunnel (all the traffic) or a split tunnel with its networks; the addresses, DNS servers, MTU, listen
port and public key of the computer; the address, port and public key of the server, its fallback addresses and the
one in use, its keepalive, whether it has a preshared key; the login page and the session. Never a private or
preshared key. **Copy all** puts it in the clipboard as text, for the administrator; Ctrl+C copies the rows
selected.

## For the administrators

The MSI package installs for the whole computer, so Intune, Group Policy or any tool that deploys MSI packages
can install it. As administrator, without windows:

```
msiexec /i authway-0.1.0-x64.msi /qn
"C:\Program Files\Authway\authway.exe" --import "C:\path\office.conf" --name "Office"
"C:\Program Files\Authway\authway.exe" --remove "Office"
msiexec /x authway-0.1.0-x64.msi /qn
```

- **Install**: the app starts at once for every user signed in, and at every sign-in after.
- **Update**: install the new package over the old one: it replaces it, even at the same version. The VPNs are kept;
  the app of each user logs out, turns its tunnels off and quits, then starts again.
- **Remove**: from **Settings > Apps**, or `msiexec /x`. It takes away the service, the VPNs, the logs and the
  driver, and the settings and passwords of the user who removes it. Other users' saved passwords stay in their
  Credential Manager.
- The package is for x64 or ARM64 Windows 10 version 2004 or later, or Windows 11: it refuses the wrong computer.
  The folder is always `C:\Program Files\Authway`.

**Who can add and remove VPNs.** By default only an administrator: a VPN can route all the traffic of the computer
and change its DNS, so a user who isn't one sees the permission of Windows when adding or removing a VPN. Any user
can connect and disconnect the VPNs that are there; no group membership is needed. To let every user add and remove
them without that permission:

- check **Every user of this computer** on the page *Who can add VPNs* of the setup, or install with
  `msiexec /i authway-0.1.0-x64.msi /qn ALLOWUSERIMPORT=1`. An update keeps the choice; `ALLOWUSERIMPORT=0`
  takes it back. The setup saves it as `AllowUserImport` = 1 in `HKLM\SOFTWARE\Authway`.
- or the policy `AllowUserImport` = 1, below: it applies at once, and the policy, 0 or 1, wins over the setup.

Policies, as DWORD values in `HKLM\SOFTWARE\Policies\Authway`:

| Value | Effect |
|---|---|
| `RememberPassword` = 0 | the app never saves the passwords, only the usernames |
| `AllowUserImport` = 1 | the users who aren't administrators can add and remove VPNs, without asking for permission |
| `AllowUserImport` = 0 | only the administrators can, whatever the setup chose |

```
reg add "HKLM\SOFTWARE\Policies\Authway" /v AllowUserImport /t REG_DWORD /d 1 /f
```

## How it works

```
 the user                                   SYSTEM
┌──────────────────────┐   named pipe   ┌────────────────────────┐  wireguard.dll   ┌─────────────┐
│ authway.exe          │◄──────────────►│ authway.exe            │◄────────────────►│ WireGuardNT │
│ icon, login, details │  JSON, a line  │ --service              │  adapters, keys  │ (driver)    │
└──────────┬───────────┘                └────────────────────────┘                  └─────────────┘
           │ HTTP through the tunnel: /api/status, /api/login, /api/logout of ns-wgauth
           ▼
     the login page of the firewall, e.g. http://10.103.1.1:8181/
```

- **One exe, two roles.** The service (`--service`, LocalSystem, started with Windows) owns the tunnels; the app
  of each user talks to it through the pipe `\\.\pipe\Authway`. The users can start the service, not stop it.
- **The setup** is the MSI package of [installer/package.wxs](installer/package.wxs): Windows Installer
  installs the files, the service with its rights and its restarts, the start at the sign-in and the Start menu
  entry. The exe does the rest, with `--msi-...` options: the apps quit before the service stops, they start again
  after the setup, and the data goes when the app is removed, not updated ([src/setup.rs](src/setup.rs)).
- **The tunnels** are WireGuardNT adapters, made by the official `wireguard.dll` of WireGuard LLC, shipped next to
  the exe as it is downloaded ([tools/fetch-wireguard.ps1](tools/fetch-wireguard.ps1) checks its hash and its
  signature). The service sets the addresses, the routes of `AllowedIPs` (metric 0), the MTU (the one of the
  configuration, or of the network to the server less 80) and the DNS servers. A tunnel goes off when the user who
  turned it on signs out, and when the service stops.
- **Fallback addresses**: the firewall writes the other addresses of a server, a second internet line for example,
  in a `# Fallback = host:port, ...` line after `Endpoint` (on NethSecurity, the *Fallback endpoints* of the server;
  by hand, a fallback without a port takes the one of `Endpoint`). The service reads the counters of the driver every
  second ([src/failover.rs](src/failover.rs)). When this computer keeps sending and nothing comes back for 20
  seconds, it gives the driver the next address, in place. A keepalive is the only message that WireGuard never
  answers, so a quiet tunnel doesn't move. The tunnel stays on, with its routes, its DNS and its login session (the
  public IP of the computer doesn't change). It goes around the list while none answers. The one that answers stays,
  and the next connection starts with `Endpoint` again. A name is looked up again at each change, for 5 seconds at
  most, else its last address is used, so an `Endpoint` alone with a name follows a dynamic DNS too. The other
  WireGuard apps ignore the line.
- **The configurations** are in `HKLM\SOFTWARE\Authway\Tunnels`, encrypted by DPAPI for SYSTEM: the users can't
  read the private keys back. `PreUp`, `PostUp` and the other scripts of wg-quick never run. For **Details...** the
  service gives the app the rest of the configuration and the counters of the driver, and the public key of the
  computer, which it works out from the private one ([src/x25519.rs](src/x25519.rs), checked with the vectors of
  RFC 7748).
- **The login**: the page is the `# Login = ...` line that the firewall writes in the configuration; without it the
  app looks for the page on the first address of the network of the tunnel, port 8181, then through the redirect of
  port 80. The app asks `/api/status` every 20 seconds while logged in, every second while connecting. The password
  goes only through the tunnel:
  - the login page is always an address of the routes of the tunnel (`AllowedIPs`): the service refuses a
    `# Login` line out of them, the app never looks for the page out of them nor follows a redirect out of them, and
    it forgets a page found on an earlier connection once a new configuration leaves it out;
  - the requests go out only through the network adapter of the tunnel, whatever the routes of the computer say
    (`IP_UNICAST_IF`, with the index the service gives): a more specific route of the local network, as a DHCP
    server can push with option 121 ("TunnelVision", CVE-2024-3661), can't take them. A connection that comes from
    an address that isn't one of the adapter is closed before anything is sent.
- **The passwords** are in the Credential Manager of the user (`Authway/http://10.103.1.1:8181`), on this
  computer only, if the user checked "Remember my password".
- **The pipe** lets the signed-in users read and write, not create another instance of it; the app checks that the
  process at the other end is the service before talking. The service checks the groups of the caller for the
  administrator rights.

The logs, without passwords, codes or keys: `%LOCALAPPDATA%\Authway\client.log` for the app,
`C:\Program Files\Authway\log\service.log` for the service and the driver. Both are in the menu, under **Logs**.

## Build

Rust stable with the MSVC toolchain (Visual Studio or its Build Tools, with the Windows SDK), the x64 and ARM64
targets, and [WiX Toolset 3.14](https://github.com/wixtoolset/wix3/releases) for `candle` and `light`:

```
rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc
powershell -File tools\fetch-wireguard.ps1     # wireguard.dll for x64 and ARM64, checked
powershell -File tools\dist.ps1                # dist\authway-<version>-x64.msi and -arm64.msi
```

`dist.ps1` finds WiX through `%WIX%`, set by its setup, or `-Wix <its bin folder>`. It passes the names of
`src\product.rs` and the version of `Cargo.toml` to the package: change them there, never in the `.wxs`. Keep
`UPGRADE_CODE` forever, or a new version doesn't replace the installed one.

`tools\make-icons.cmd` draws the icons of `assets\` and the pictures of the setup again, with the C# compiler of
Windows.

## Tests

```
cargo test --features testing
```

The `testing` feature makes a build for the tests only: the service runs as the user (`--service-console`) with
fake tunnels, its pipe, its keys in `HKCU\Software\Authway test` and its credentials have other names, so it never
touches an installed app. The end-to-end test drove that build against the real code of the ns-wgauth daemon: import,
login with a wrong password then the right one, the session ended by the server, the saved password, cancel, quit
with logout, removal, and a saved login page out of the routes, dropped.

The way out of the login: the unit tests check that discovery never goes out of the routes, the redirect included,
and that nothing is sent through another network adapter. On the real driver, two WireGuardNT adapters on 127.0.0.1
played the tunnel and a local network that pushes a more specific route to the login page: a plain connection went
out through the local network, the ones of the login of the app through the tunnel, as the counters of the driver
showed.

The fallback addresses: the unit tests replay the counters second by second (an answer, silence, keepalives only,
names that can't be found). In the test build a fake server answers at any port but 9. In the run of that build,
the Endpoint and a first fallback on port 9 were each left after 21 seconds, and a second fallback, a name, was kept.
On the real driver, two WireGuardNT adapters on 127.0.0.1 were used, the Endpoint on a port where nothing listens:
- the switch came after 21 seconds, and the handshake at the next retry of the driver, 5 seconds later;
- the tunnel stayed there for 2 minutes of unanswered keepalives, then the rekey.

The MSI package for ARM64 was tested as administrator on Windows 11: the x64 one refused, the install, the rights
and restarts of the service, two tunnels through the installed `wireguard.dll`, the steps for the apps as SYSTEM, an
update that keeps the VPNs and restarts the app, and a removal that leaves nothing, the driver included.

## macOS

The same app for macOS 11 or later, Apple silicon and Intel in one package: the same menu, login window, details,
fallback addresses and rules for the password, from the same code ([src/client](src/client),
[src/manager.rs](src/manager.rs)); what differs is in [src/macos](src/macos).

> [!IMPORTANT]
> The macOS version is written and compiles for both processors, but it **hasn't run on a Mac yet**: expect bugs
> on the first runs, and keep a way back to your usual network (`sudo …/uninstall.sh`).

**For the users.** Open `authway-<version>-macos.pkg` and click **Continue**, **Install**: macOS asks for the
password of an administrator, once. The icon is in the menu bar, and the app starts at every login; click the
icon for the menu. Adding a VPN works as on Windows, and macOS asks for an administrator when the user isn't
allowed. The notices are in the Notification Center: macOS asks once whether the app can show them.

**For the administrators.**

```
sudo installer -pkg authway-0.1.0-macos.pkg -target /
sudo /Applications/Authway.app/Contents/MacOS/authway --import ~/Downloads/office.conf --name "Office"
sudo /Applications/Authway.app/Contents/MacOS/authway --remove "Office"
sudo "/Library/Application Support/Authway/uninstall.sh"
```

- **Update**: install the new package over the old one. The VPNs are kept; the app of each user logs out, turns its
  tunnels off and quits, then the service and the app of the user at the screen start again.
- **Remove**: `uninstall.sh`, as above (it's also in [installer/macos](installer/macos)). It takes away the app,
  the service, the VPNs, the logs, and the settings and passwords of every user; the saved passwords of a user who
  isn't logged in stay in their locked keychain.
- **Policies**: the same values as on Windows, in `/Library/Preferences/io.github.phatdo1819.authway.plist` or in
  a configuration profile (MDM) for that domain, read again within 15 seconds:

  ```
  sudo defaults write /Library/Preferences/io.github.phatdo1819.authway AllowUserImport -bool true
  sudo defaults write /Library/Preferences/io.github.phatdo1819.authway RememberPassword -bool false
  ```

**How it works on macOS.**

```
 the user                                   root (launchd)
┌──────────────────────┐  Unix socket   ┌────────────────────────┐  control socket  ┌──────────────┐
│ Authway.app          │◄──────────────►│ authway --service      │◄────────────────►│ wireguard-go │
│ menu, login, details │  JSON, a line  │ /Library/Application   │  /var/run/       │ one per      │
└──────────────────────┘                │ Support/Authway        │  wireguard/      │ tunnel, utun │
                                        └────────────────────────┘                  └──────────────┘
```

- **The service** is a launchd daemon, as root, from a copy of the program in `/Library/Application Support/Authway`,
  which only root can change: an administrator could replace `/Applications/Authway.app` without a password. It
  listens on `/var/run/authway.sock`; the app checks that root owns the socket and answers on it. Only root, or every
  user with `AllowUserImport`, can add and remove VPNs: the app asks macOS for an administrator and runs the same
  `--import` as root.
- **The tunnels** are `wireguard-go`, the WireGuard of WireGuard LLC in user space, as the WireGuard tools of macOS
  use it: one process per tunnel on a free `utun` interface, configured through its control socket, never given the
  keys on its command line. The service sets the addresses and the routes as `wg-quick` does (a default route as two
  halves, the server kept out of the tunnel through the gateway of the network), and the DNS servers on every
  network service, put back when the tunnel goes off, and at the start of the service after a crash. It looks at
  them again when the network changes.
- **The session of a tunnel** is the user who turned it on. macOS doesn't tell a service when a user logs out: the
  app lists the tunnels at least every 10 seconds, and the service turns off the tunnels of a user whose app stopped
  asking for 2 minutes.
- **The login** goes only through the tunnel, as on Windows, with `IP_BOUND_IF` in place of `IP_UNICAST_IF`.
- **The configurations** are files of root, `/Library/Application Support/Authway/tunnels/<name>.conf`, readable by
  root only. **The passwords** are in the login keychain of the user, under `Authway/http://10.103.1.1:8181`.
- **The logs**: `~/Library/Logs/Authway/client.log` for the app, `/Library/Logs/Authway/service.log` for the service
  and `wireguard-go`. **Logs** in the menu opens them in Console.

**Build**, on a Mac with the Command Line Tools of Xcode, Rust and Go 1.23.1 or later:

```
rustup target add aarch64-apple-darwin x86_64-apple-darwin
tools/fetch-wireguard-go.sh      # wireguard-go from its source, checked, for both processors
tools/dist-macos.sh              # dist/authway-<version>-macos.pkg
```

The package is signed ad hoc, which is enough for the Mac that builds it. For other Macs, sign it with the
certificates of an Apple developer account (`SIGN_APP="Developer ID Application: ..."`, `SIGN_PKG="Developer ID
Installer: ..."`) and notarize it, or Gatekeeper refuses the downloaded package. With ad-hoc signatures, macOS can ask
once again for the saved passwords after an update: the keychain knows the app by its signature.

**Tests**: `cargo test --features testing` on a Mac too. The test build runs the service as the user
(`--service-console`, socket `/tmp/authway-test.sock`, data in `~/Library/Application Support/Authway test`) with fake
tunnels; the test of the login on `127.0.0.2` needs `sudo ifconfig lo0 alias 127.0.0.2` first.

## Not done yet

- Tested with a real NethSecurity server: not yet (the real driver only on 127.0.0.1).
- macOS: never run on a Mac yet, see above.
- No kill switch: when the tunnel is down, the traffic goes out of it; no block of the DNS outside of the tunnel.
- The packages and the programs aren't signed by a known publisher: SmartScreen and Gatekeeper warn when they're
  downloaded.
- No reconnection by itself at the sign-in, no tunnels per user, English only.
- iOS and Android: not started.

## Licenses

The app is under the MIT license of [LICENSE](LICENSE), installed next to it as `LICENSE.txt`. `wireguard.dll` is under the license of WireGuard LLC in `wireguard-LICENSE.txt`, which allows to ship it unchanged
next to an app that uses its API. `wireguard-go` is under the MIT license, in `wireguard-go-LICENSE.txt` next to it
on macOS. "WireGuard" is a registered trademark of Jason A. Donenfeld: the app doesn't use it in its name.
