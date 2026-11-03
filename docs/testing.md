# What was tested

## The test machines

The tests with a real firewall ran in virtual machines, on one local network:

- a NethSecurity test firewall built from the fork with
  [ns-wgauth](https://github.com/phatdo1819/nethsecurity/tree/ci-wgauth/packages/ns-wgauth): the login, device
  binding, the fallback addresses and the copy detection;
- a Windows 11 and a macOS virtual machine, each with Authway installed from its package, with the real WireGuard
  drivers.

Not tested: physical computers, a firewall in production, clients on other networks across the internet, and many
users at once.

## The test build

`cargo test --features testing` runs the tests ([Building](building.md#tests)). The `testing` feature makes a build
for the tests only: the service runs as the user (`--service-console`) with fake tunnels, and its pipe, its keys
(`HKCU\Software\Authway test`) and its credentials have other names, so it never touches an installed app. On macOS
its socket is `/tmp/authway-test.sock` and its data `~/Library/Application Support/Authway test`.

## The login

The test build ran against the real code of the ns-wgauth daemon: the import, a wrong password then the right one,
the session ended by the server, the saved password, cancel, quit with logout, the removal, and a saved login page
outside the routes, which was dropped.

## The window

Driven through its buttons, against the test build and the same daemon code:

- the empty list, two VPNs added from the command line, the page of one, its switch, the card of the other switched
  on, the speeds;
- a rename once off: the registry key, the page and the card follow;
- a VPN with a login: the saved username and password on its page, **Log in** on the card and the page while the
  login waits, a new username, the password forgotten;
- the banner when the service stops, closing the window (the app stays), and a second start that shows it again.

The unit tests check the cards (state, color, what to do, routing), the speeds made from the counters, and the
renames the service refuses.

## Two steps with a login

Driven the same way with a full tunnel: the routes to the internet wait for the login, come with it, go when the
server ends the session, come back at the next login, and go after 30 seconds without an answer from the server
(seen in the service log: the fake tunnels change no route). The unit tests check which routes wait, for full and
split tunnels, and when the app asks for them.

## The login only through the tunnel

- The unit tests check that discovery never leaves the routes, redirects included, and that nothing goes out through
  another network adapter.
- On the real driver, two WireGuardNT adapters on 127.0.0.1 played the tunnel and a local network that pushes a more
  specific route to the login page. A plain connection went out through the local network, and the login of the app
  through the tunnel, as the driver's counters showed.

## Fallback addresses

- The unit tests replay the counters second by second: an answer, silence, keepalives only, names that can't be
  found.
- In the test build, a fake server answers on any port but 9. The Endpoint and a first fallback on port 9 were each
  left after 21 seconds, and a second fallback, a name, was kept.
- On the real driver, with two WireGuardNT adapters on 127.0.0.1 and the Endpoint on a port where nothing listens:
  the switch came after 21 seconds and the handshake at the driver's next retry, 5 seconds later. The tunnel stayed
  there for 2 minutes of unanswered keepalives, then the rekey.

## Device binding

- The unit tests check SHA-256 and HMAC-SHA256 with the published vectors, the DER of the signatures, the message,
  the SMBIOS UUID (byte order, placeholders), and a real key of the Microsoft Software Key Storage Provider, whose
  signature `openssl dgst -verify` accepts, as the firewall does.
- A proof made by `device::prove` was accepted by the `verify_device` of the firewall, and refused with another user,
  address or server.
- On the test machines, the Windows and the macOS client each enrolled their VPN on the test firewall, and a copy of
  the same `.conf` on the other computer was refused.

## The WireGuard key of this computer

- The unit tests check the key stored and its format, the message signed, which key the service tries after a
  silence and what a handshake decides, and when the app asks.
- A request signed by `device::wireguard_key` was accepted by the `verify_wireguard_key` of the firewall, and refused
  for another address, key or server.
- Without windows, the test build and the real code of the ns-wgauth daemon went through the whole exchange: the
  enrollment, the new key taken and put on the interface of the (fake) firewall, the session going on, the next
  login, a key in use refused, the next connection with the new key, and the keys removed with the VPN.
- Not tested yet: on the test machines, with real tunnels.

## The MSI package

The ARM64 package was tested as administrator on Windows 11: the x64 package refused, the install, the rights and
restarts of the service, two tunnels through the installed `wireguard.dll`, the steps for the apps as SYSTEM, an
update that keeps the VPNs and restarts the app, and a removal that leaves nothing, the driver included.
