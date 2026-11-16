# How Authway works

For how to use it, see the [user guide](user-guide.md) and the [administrator guide](administrators.md).

## Windows

```
 the user                                   SYSTEM
┌──────────────────────┐   named pipe   ┌────────────────────────┐  wireguard.dll   ┌─────────────┐
│ authway.exe          │◄──────────────►│ authway.exe            │◄────────────────►│ WireGuardNT │
│ window, icon, login  │  JSON, a line  │ --service              │  adapters, keys  │ (driver)    │
└──────────┬───────────┘                └────────────────────────┘                  └─────────────┘
           │ HTTP through the tunnel: /api/status, /api/login, /api/logout of ns-wgauth
           ▼
     the login page of the firewall, e.g. http://10.103.1.1:8181/
```

- **One exe, two roles.** The service (`--service`, LocalSystem, started with Windows) owns the tunnels. The app of
  each user talks to it through the pipe `\\.\pipe\Authway`. Users can start the service, not stop it.
- **The pipe**: signed-in users can read and write it, but can't create another instance of it. The app checks that
  the process at the other end is the service. The service checks the groups of the caller for administrator rights.
- **A tunnel belongs to the user who turned it on**, by the Windows session of their app. The other users see it
  on, but its login, its routes and its keys are the owner's: the service refuses them the requests on them, and
  their apps never look at its login page. They can't turn it off, nor turn on another VPN in its place, unless
  they can add and remove VPNs (administrators, or everyone with `AllowUserImport`), since they could remove it
  anyway.
- **The service never waits on the network with its lock**: when a tunnel turns on, the names of its servers are
  looked up without it (10 seconds at most each), so the apps of every user get their answers meanwhile. A
  configuration replaced during the lookups is looked up again.
- **The setup** is the MSI package of [installer/package.wxs](../installer/package.wxs): the files, the service
  with its rights and restarts, the start at sign-in and the Start menu entry. The exe does the rest with `--msi-...`
  options ([src/setup.rs](../src/setup.rs)): the apps quit before the service stops and start again after the
  setup, and the data is removed when the app is removed, not when it's updated.
- **The tunnels** are WireGuardNT adapters, made by the official `wireguard.dll` of WireGuard LLC, shipped unchanged
  ([tools/fetch-wireguard.ps1](../tools/fetch-wireguard.ps1) checks its hash and signature). The service sets the
  addresses, the routes of `AllowedIPs` (metric 0), the MTU (the configuration's, or the network's to the server
  minus 80) and the DNS servers. A tunnel goes off when the user who turned it on signs out, and when the service
  stops.
- **The configurations** are in `HKLM\SOFTWARE\Authway\Tunnels`, encrypted with DPAPI for SYSTEM: users can't read
  the private keys back. The wg-quick scripts (`PreUp`, `PostUp`, ...) never run. The public key of the computer in
  the details is derived from the private one ([src/x25519.rs](../src/x25519.rs), checked with the RFC 7748
  vectors).
- **The passwords** are in the Credential Manager of the user (`Authway/http://10.103.1.1:8181`), only when
  **Remember my password** is checked.

## Two steps with a login

`Steps` in [src/manager.rs](../src/manager.rs), the same on Windows and macOS. When the configuration has a
`# Login =` line:

1. **Before the login**, the tunnel gets only the routes of the private networks (10.0.0.0/8, 172.16.0.0/12,
   192.168.0.0/16, 100.64.0.0/10, the link-local ones, fc00::/7) and a route to the login page, without the DNS
   servers. The other routes wait: `0.0.0.0/0` and `::/0` of a full tunnel, or a public network.
2. **After the login**, the app tells the service (`logged_in` on the pipe), which adds them with the DNS servers.

When the status says the session ended, or the login page didn't answer for 30 seconds, the service takes them back.
Only the routes and the DNS of the computer change, never the WireGuard configuration: the firewall still lets only
the login page through before the login.

A split tunnel keeps all its routes: only its DNS servers wait, since the firewall would answer them with the
address of the login page before the login. A tunnel without the line, even one whose page the app found, gets
everything at once.

## The login

- **The page** is the `# Login = ...` line that the firewall writes in the configuration. Without it, the app looks
  on the first address of the tunnel's network, port 8181, then through the redirect of port 80.
- **The status** (`/api/status`) is asked every second while connecting, every 20 seconds while logged in.
- **The password goes only through the tunnel:**
  - The login page must be inside the routes of the tunnel (`AllowedIPs`). The service refuses a `# Login` line
    outside them, the app never looks for the page or follows a redirect outside them, and it forgets a page found
    earlier once a new configuration leaves it out.
  - The requests are bound to the tunnel's adapter (`IP_UNICAST_IF` on Windows, `IP_BOUND_IF` on macOS), whatever
    the routes of the computer say. A more specific route pushed by a DHCP server with option 121 ("TunnelVision",
    CVE-2024-3661) can't take them. A connection from an address that isn't the adapter's is closed before anything
    is sent.

## Fallback addresses

[src/failover.rs](../src/failover.rs). The firewall writes the other addresses of a server, a second internet line
for example, in a `# Fallback = host:port, ...` line after `Endpoint` (on NethSecurity: the *Fallback endpoints* of
the server). By hand, a fallback without a port takes the port of `Endpoint`. The other WireGuard apps ignore the
line.

- The service reads the driver's counters every second. When the computer keeps sending and nothing comes back for
  20 seconds, it gives the driver the next address, in place. WireGuard never answers a keepalive, so keepalives
  alone don't count: a quiet tunnel doesn't move.
- The tunnel stays on, with its routes, its DNS and its login session (the public IP of the computer doesn't
  change). It goes around the list while none answers. The one that answers stays, and the next connection starts
  with `Endpoint` again.
- At the connection, the `Endpoint` then the fallbacks are looked up in order, 10 seconds at most each, until one
  is found: the names after it wait until the tunnel moves to them.
- A name is looked up again at each change, for 5 seconds at most, else its last address is used. So an `Endpoint`
  name alone also follows a dynamic DNS.

## Device binding

[src/device.rs](../src/device.rs), [src/devkey.rs](../src/devkey.rs). For a server with `device_binding` in
ns-wgauth:

- **The device key**: one ECDSA P-256 key per tunnel, made at the first such login. On Windows it's a key of the
  computer in the Microsoft Software Key Storage Provider, which can't be exported and only SYSTEM and the
  administrators can use. On macOS it's a file readable by root only. Removing the VPN removes its key.
- **The login**: the status gives a challenge. The service signs it with the address of the computer in the VPN, the
  keys of both sides and the user name, and the app sends the signature with the login. The first login enrolls the
  key.
- **The machine ID**, when the server asks for it: the service adds an HMAC of the hardware ID (the SMBIOS UUID, else
  `MachineGuid`; `IOPlatformUUID` on macOS), keyed with the public key of the server, so the server never sees the
  ID itself.
- **Another device**: every status asks with the ID of the key, its SHA-256 (empty when the tunnel has none, and no
  key is made for that). When the page answers that another device is enrolled (`this_device` false), the app takes
  the tunnel down at once and doesn't connect again by itself. A firewall without this answer changes nothing.

### The WireGuard key of this computer

- Once logged in on a server whose status says `"wireguard_key": "configuration"`, the app asks the service for a new
  WireGuard key. The service makes it with the random generator of the system, keeps it as *pending* with the tunnel
  (encrypted like the configuration: a `Keys` value, or a `<name>.keys` file on macOS), and signs it with the device
  key ([device::wireguard_key](../src/device.rs)). Only while the tunnel works with the key of the configuration
  file, a handshake proving it: then the firewall has no other key of the tunnel.
- The app sends it (`POST /api/device-key`). On `200` the app tells the service, which tries the key at once: the
  next packet makes a handshake. What the app says is only a hint, any program of the user could say it. The key
  becomes the key of the tunnel with its first handshake, never before; without one, the tunnel goes back to the
  key of the file.
- The configuration stays as it was imported, so its key comes back if the firewall takes it again.
- While a key gets no handshake although packets go out (30 seconds, or 200 for a key that worked), the service
  tries the other keys of the tunnel: the pending one when the firewall's answer was lost, the one of the file after
  a new enrollment. A handshake decides ([src/manager.rs](../src/manager.rs)).
- A key the firewall may have is never forgotten: the key a new one replaces stays pending, and the service tries it
  too when the new one stops working.
- Importing a new file for the VPN forgets the keys made for the old one.

## macOS

```
 the user                                   root (launchd)
┌──────────────────────┐  Unix socket   ┌────────────────────────┐  control socket  ┌──────────────┐
│ Authway.app          │◄──────────────►│ authway --service      │◄────────────────►│ wireguard-go │
│ window, menu, login  │  JSON, a line  │ /Library/Application   │  /var/run/       │ one per      │
└──────────────────────┘                │ Support/Authway        │  wireguard/      │ tunnel, utun │
                                        └────────────────────────┘                  └──────────────┘
```

The window, the menu, the login, the details, the fallback addresses and the two steps come from the same code as
on Windows ([src/client](../src/client), [src/manager.rs](../src/manager.rs)). What differs is in
[src/macos](../src/macos):

- **The service** is a launchd daemon, as root, running a copy of the program in
  `/Library/Application Support/Authway`, which only root can change (an administrator could replace
  `/Applications/Authway.app` without a password). It listens on `/var/run/authway.sock`, and the app checks that
  root owns the socket.
- **Adding and removing VPNs** is allowed to root, or to every user with `AllowUserImport` (the package's default).
  Otherwise the app asks macOS for an administrator and runs the same `--import` as root.
- **The tunnels** are `wireguard-go`, the WireGuard of WireGuard LLC in user space, as the WireGuard tools of macOS
  use it: one process per tunnel, on a free `utun` interface, configured through its control socket, never with the
  keys on its command line.
- **The routes** are set as `wg-quick` does: a default route as two halves, the server kept outside the tunnel
  through the gateway of the network. That route is kept in `host-routes.json` while it's there, and taken back at
  the start of the service after a crash. **The DNS servers** are set on every network service, put back when the
  tunnel goes off, and at the start of the service after a crash. The service sets them again when the network
  changes.
- **A tunnel belongs to the user who turned it on.** macOS doesn't tell a service when a user logs out, so the app
  lists the tunnels at least every 10 seconds, and the service turns off the tunnels of a user whose app stopped
  asking for 2 minutes.
- **The files**, readable by root only, in `/Library/Application Support/Authway`: the configurations in
  `tunnels/<name>.conf`, with `<name>.keys` for the WireGuard keys this computer made, and the device keys (made by
  the Security framework, not in the Secure Enclave yet) in `devices/<name>.key`. **The passwords** are in the login
  keychain of the user, under `Authway/http://10.103.1.1:8181`.
- **The logs**: `~/Library/Logs/Authway/client.log` for the app, `/Library/Logs/Authway/service.log` for the service
  and `wireguard-go`.
