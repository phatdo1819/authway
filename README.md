# Authway

A WireGuard VPN client for Windows 10 and 11, in one app: it connects the tunnel and, for the servers that require
it, logs in with username, password and the code of an authenticator app, then keeps watching the session. It works
with the WireGuard servers of a NethSecurity firewall that use the login of
[ns-wgauth](https://github.com/phatdo1819/nethsecurity/tree/ci-wgauth/packages/ns-wgauth), and with any other
WireGuard server, without a login.

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
  port 80. The service refuses a configuration whose login page isn't reached through the tunnel, so the password
  goes only through it. The app asks `/api/status` every 20 seconds while logged in, every second while connecting.
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
with logout, removal.

The fallback addresses: the unit tests replay the counters second by second (an answer, silence, keepalives only,
names that can't be found). In the test build a fake server answers at any port but 9. In the run of that build,
the Endpoint and a first fallback on port 9 were each left after 21 seconds, and a second fallback, a name, was kept.
On the real driver, two WireGuardNT adapters on 127.0.0.1 were used, the Endpoint on a port where nothing listens:
- the switch came after 21 seconds, and the handshake at the next retry of the driver, 5 seconds later;
- the tunnel stayed there for 2 minutes of unanswered keepalives, then the rekey.

The MSI package for ARM64 was tested as administrator on Windows 11: the x64 one refused, the install, the rights
and restarts of the service, two tunnels through the installed `wireguard.dll`, the steps for the apps as SYSTEM, an
update that keeps the VPNs and restarts the app, and a removal that leaves nothing, the driver included.

## Not done yet

- Tested with a real NethSecurity server: not yet (the real driver only on 127.0.0.1).
- Two findings of the security review of 2026-10-26, both about the password leaving the tunnel: a login page
  that the app finds by itself (no `# Login` line) isn't checked against the routes of the tunnel, and the login
  connections follow the routing table only, so a more specific route of the local network (DHCP option 121)
  can take them.
- No kill switch: when the tunnel is down, the traffic goes out of it; no block of the DNS outside of the tunnel.
- The package and the exe aren't signed: SmartScreen warns when they're downloaded.
- No reconnection by itself at the sign-in, no tunnels per user, English only.
- macOS, iOS and Android: not started.

## Licenses

The app is under the GPL 2.0 of [LICENSE](LICENSE), installed next to it as `LICENSE.txt`. `wireguard.dll` is under the license of WireGuard LLC in `wireguard-LICENSE.txt`, which allows to ship it unchanged
next to an app that uses its API. "WireGuard" is a registered trademark of Jason A. Donenfeld: the app doesn't use it
in its name.
