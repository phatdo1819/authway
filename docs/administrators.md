# Administrator guide

For the firewall side, follow
[WGAUTH-TESTING.md](https://github.com/phatdo1819/nethsecurity/blob/ci-wgauth/WGAUTH-TESTING.md) on the `ci-wgauth`
branch of the NethSecurity fork: steps 1–7 for the login, 8 for the fallback addresses, 9 for device binding.

- [Windows](#windows)
- [macOS](#macos)
- [Device binding: pros and cons](#device-binding-pros-and-cons)
- [Logs](#logs)

## Windows

### Deploy

The MSI package installs for the whole computer, so Intune, Group Policy or any tool that deploys MSI packages can
install it. As administrator, without windows:

```
msiexec /i authway-0.2.0-x64-unsigned.msi /qn
"C:\Program Files\Authway\authway.exe" --import "C:\path\office.conf" --name "Office"
"C:\Program Files\Authway\authway.exe" --rename "Office" --to "Head office"
"C:\Program Files\Authway\authway.exe" --remove "Office"
msiexec /x authway-0.2.0-x64-unsigned.msi /qn
```

| | |
|---|---|
| **Install** | The app starts for every signed-in user, and at every sign-in. For x64 or ARM64 Windows 10 2004 or later, or Windows 11; the wrong processor is refused. The folder is always `C:\Program Files\Authway`. |
| **Rename** | Only while the VPN is off. Its device key and saved logins stay. |
| **Update** | Install the new package over the old one, even at the same version. The VPNs are kept; the app of each user logs out, quits and starts again. |
| **Remove** | **Settings > Apps**, or `msiexec /x`. It removes the service, the VPNs with their device keys, the logs, the driver, and the settings and passwords of the user who removes it. Other users' saved passwords stay in their Credential Manager. |

### Fill in the login

`--import` can also save the login, as OpenVPN Connect does, so the login window is already filled in (the user still
clicks **Connect**, and types the code when asked):

```
"C:\Program Files\Authway\authway.exe" --import "C:\path\office.conf" --name "Office" --username "alice" --password "Secret,1234"
```

- Run it **as the user**, not as SYSTEM (refused): the login goes to that user's Credential Manager. When the user
  isn't allowed to add VPNs, Windows asks for an administrator for the VPN only. For a tool that runs scripts as the
  user, install with `ALLOWUSERIMPORT=1` (below), so nothing is asked.
- The file needs its `# Login =` line. `--username` alone saves only the username; `--username=alice` works too.
- With the policy `RememberPassword` = 0, `--password` is refused.
- A password on a command line can end up in the shell history, the logs of the deployment tool or the process
  auditing of Windows. Prefer letting users type it once with **Remember my password**, and change the password
  after a deployment that might have logged it.

### Who can add VPNs

By default only administrators can add, rename and remove VPNs, since a VPN can route all the traffic and change the
DNS. Any user can connect and disconnect the VPNs that are there. To let every user add and remove them:

- in the setup, choose **Every user of this computer** on *Who can add VPNs*, or install with `ALLOWUSERIMPORT=1`
  (`=0` takes it back, updates keep it; saved as `AllowUserImport` = 1 in `HKLM\SOFTWARE\Authway`);
- or set the policy below: it applies at once and wins over the setup.

### Policies

DWORD values in `HKLM\SOFTWARE\Policies\Authway`:

| Value | Effect |
|---|---|
| `RememberPassword` = 0 | Never save passwords, only usernames |
| `AllowUserImport` = 1 | Users who aren't administrators can add and remove VPNs |
| `AllowUserImport` = 0 | Only administrators can, whatever the setup chose |

```
reg add "HKLM\SOFTWARE\Policies\Authway" /v AllowUserImport /t REG_DWORD /d 1 /f
```

## macOS

```
sudo installer -pkg authway-0.2.0-macos-unsigned.pkg -target /
sudo /Applications/Authway.app/Contents/MacOS/authway --import ~/Downloads/office.conf --name "Office"
sudo /Applications/Authway.app/Contents/MacOS/authway --remove "Office"
sudo "/Library/Application Support/Authway/uninstall.sh"
```

- **Fill in the login**: as on Windows, but run it **without sudo**, as the user (as root it's refused): the login
  goes to that user's keychain. When the user isn't allowed to add VPNs, macOS asks for an administrator for the VPN
  only. Any user can see the command line with `ps` while it runs.

  ```
  /Applications/Authway.app/Contents/MacOS/authway --import ~/Downloads/office.conf --name "Office" --username "alice" --password "Secret,1234"
  ```

- **Update**: install the new package over the old one. The VPNs are kept; the app of each user logs out and quits,
  then starts again. Version 0.1.0 used another identifier: its launchd jobs are removed, but its policies must be
  written again for `io.authway.client`. macOS may ask again to allow the notices and the background items.
- **Remove**: `uninstall.sh` (also in [installer/macos](../installer/macos)) removes the app, the service, the VPNs,
  the logs, and the settings and passwords of every user. The saved passwords of a user who isn't logged in stay in
  their locked keychain.
- **Policies**: the same values as on Windows, in `/Library/Preferences/io.authway.client.plist` or in a
  configuration profile (MDM) for `io.authway.client`, which wins; they're read again within 15 seconds. Unlike
  Windows, the package sets `AllowUserImport` to true when it isn't set yet, and updates keep the value they find.
  For example, to let only administrators add VPNs and to save no passwords:

  ```
  sudo defaults write /Library/Preferences/io.authway.client AllowUserImport -bool false
  sudo defaults write /Library/Preferences/io.authway.client RememberPassword -bool false
  ```

## Device binding: pros and cons

**Device binding** (and optionally **Machine ID**) is an option of a WireGuard server with the login on the
firewall. The first login of each VPN enrolls the computer, and only it can log in after that. The VPN then gets a
WireGuard key made by the computer, and the `.conf` file stops connecting: a deployed file is a one-time ticket. The
firewall shows the computer name of each enrolled device. Updates keep the keys; removing the VPN or the app deletes
them, and the next login needs **Allow a new device** on the peer.

What each client can do with the `.conf` file of a peer:

| | Before the first login | Enrolled, the firewall still takes the file's key | Enrolled, with the computer's key |
|---|---|---|---|
| **Authway, enrolled computer** | Its first login enrolls it | Connects and logs in | Connects and logs in: the only client that connects |
| **Authway, another computer** | Enrolls if it logs in first | Turned off before the login: *enrolled on another device* | No handshake: *The VPN server doesn't answer...* |
| **Official WireGuard apps** | Connect, but reach only the login page and ping | The same; they can take the enrolled computer's endpoint, and share its session from behind the same public IP | No handshake |
| **A web browser** | Refused: *a web browser can't log in* | Refused | Can't reach the login page |

The middle column lasts only seconds with Authway 0.2.0 and the firewall of the `ci-wgauth` branch, which give the
computer its key right after the first login. With Authway 0.1.0 or an older firewall it lasts as long as the
enrollment. It also comes back for a few seconds each time the firewall restarts the WireGuard interface.

**Pros**

- A copied `.conf` file is useless on another computer, even with the password and the code.
- Once the computer has its key, a copy gets no handshake at all, in any app: it can't reach the login page, take
  the endpoint of the enrolled computer or share its session. The copy alerts and blocks that copies caused stop.
- A deployed file (Intune, Group Policy, a shared folder) is worth nothing once the computer has enrolled, even if
  it leaks.
- The firewall shows the enrolled computer of each peer, when it enrolled and the public IP of its latest login.
- With Machine ID, a device key copied by an administrator of the computer doesn't work on another computer, unless
  the client is modified to send the stolen ID.
- Nothing to do for the user: the app enrolls and gives the key by itself.

**Cons**

- Only Authway can log in, on Windows and macOS: not the official WireGuard apps, not a web browser, and there's no
  Authway for iOS or Android. A user who also needs a phone needs a peer on another server without device binding
  (one peer per user on each server).
- One computer per peer. After a new computer, a reinstall, removing the VPN or the app, or importing the file
  again, the VPN stops working until the administrator clicks **Allow a new device**. Expect help desk requests.
- A configuration downloaded again from the firewall doesn't connect either: only **Allow a new device** makes a file
  connect again.
- The message can't say why. WireGuard never answers a key it doesn't know, so a copy only sees *The VPN server
  doesn't answer...*, as when the server is down, and the firewall logs nothing.
- The enrollment of a new peer stays open for 72 hours by default (`enroll_window` on the firewall). Until then,
  whoever logs in first with Authway, the file, the password and the code becomes the enrolled device. After that,
  the user needs **Allow a new device**.
- With Machine ID, a new motherboard, or a virtual machine moved to another host, can change the ID: that needs a
  new enrollment too.
- The keys are software keys: a normal user can't read them, but an administrator of the computer can copy them,
  and malware on the enrolled computer can use them. Keys in the TPM or the Secure Enclave aren't done.
- The file connects again for a few seconds each time the firewall restarts the WireGuard interface (any change to a
  peer of the server does), and between **Allow a new device** and the next enrollment.
- It needs the firewall of the ns-wgauth fork, with a local users database: the official NethSecurity has no login
  and no device binding.

## Logs

The logs have no passwords, codes or keys:

| | The app | The service |
|---|---|---|
| Windows (**⋯ > Logs**) | `%LOCALAPPDATA%\Authway\client.log` | `C:\Program Files\Authway\log\service.log` |
| macOS (**Logs** opens Console) | `~/Library/Logs/Authway/client.log` | `/Library/Logs/Authway/service.log` |
