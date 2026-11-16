# The RPM package of @PRODUCT@, for RHEL 9 and later and the distributions made from it, and Fedora: tools/dist-linux.sh
# builds it with rpmbuild from the files it made, in %{payload}.
%global debug_package %{nil}

Name:           @LOWER@
Version:        @VERSION@
# no %{?dist}: the same package for RHEL 9, RHEL 10 and Fedora, whichever system builds it
Release:        1
Summary:        WireGuard VPN client that logs in to the servers that require it
License:        MIT
URL:            https://github.com/phatdo1819/authway
Requires:       wireguard-tools, iproute, openssl, systemd, polkit, gtk3
Recommends:     libayatana-appindicator-gtk3, libnotify, libsecret, xdg-utils

%description
@PRODUCT@ connects to WireGuard servers, and logs in with a username, a password and an
authenticator code to the ones that require it (ns-wgauth of NethSecurity), then keeps
watching the session. Device binding, fallback addresses, an icon in the tray and a main
window. It needs Linux 5.7 or later, with WireGuard in the kernel.

%install
cp -a %{payload}/. %{buildroot}/

%post
# the service, at every start of the computer and now; an update restarts it with the new program
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
    systemctl enable @LOWER@.service || :
    systemctl restart @LOWER@.service || :
fi

%preun
# the removal, not an update: the service stops, the tunnels go off with their routes and DNS servers
if [ $1 -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl disable --now @LOWER@.service || :
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
fi
# the removal: the tunnels, the device keys and the logs go with the app, as on Windows
if [ $1 -eq 0 ]; then
    rm -rf /var/lib/@LOWER@ /var/log/@LOWER@
fi

%files
/usr/bin/@EXECUTABLE@
/usr/lib/systemd/system/@LOWER@.service
/usr/share/applications/@LOWER@.desktop
/etc/xdg/autostart/@LOWER@.desktop
%dir /etc/@LOWER@
%config(noreplace) /etc/@LOWER@/policy.conf
/usr/share/polkit-1/actions/@BUNDLE_ID@.policy
/usr/share/polkit-1/rules.d/50-@LOWER@.rules
/usr/share/icons/hicolor/scalable/apps/@LOWER@.svg
/usr/share/icons/hicolor/scalable/status/@LOWER@-*.svg
%dir /usr/share/doc/@LOWER@
%license /usr/share/doc/@LOWER@/copyright
