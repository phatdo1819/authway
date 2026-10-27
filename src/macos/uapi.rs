// The text protocol of the control socket of wireguard-go (the cross-platform interface of WireGuard): what sets
// the configuration of a tunnel or another address for a server, and reads its counters. Plain text, so it's
// tested on every system; macos/wg.rs talks it.

use std::fmt::Write;
use std::net::SocketAddr;

use crate::conf::{Config, Key};
use crate::manager::PeerStats;

pub const GET: &str = "get=1\n\n";

fn hex(key: &Key) -> String {
    key.iter().fold(String::with_capacity(64), |mut text, byte| {
        let _ = write!(text, "{:02x}", byte);
        text
    })
}

fn parse_hex(text: &str) -> Option<Key> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut key = [0u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(key)
}

// The whole configuration: the peers replaced, each with its address, None for a server without Endpoint. The
// text holds the private key: the caller wipes it once sent.
pub fn set_config(config: &Config, endpoints: &[Option<SocketAddr>]) -> String {
    let mut text = String::from("set=1\n");
    let _ = writeln!(text, "private_key={}", hex(&config.private_key));
    if config.listen_port != 0 {
        let _ = writeln!(text, "listen_port={}", config.listen_port);
    }
    text += "replace_peers=true\n";
    for (index, peer) in config.peers.iter().enumerate() {
        let _ = writeln!(text, "public_key={}", hex(&peer.public_key));
        if let Some(key) = &peer.preshared_key {
            let _ = writeln!(text, "preshared_key={}", hex(key));
        }
        if let Some(Some(endpoint)) = endpoints.get(index) {
            let _ = writeln!(text, "endpoint={}", endpoint);
        }
        let _ = writeln!(text, "persistent_keepalive_interval={}", peer.keepalive);
        text += "replace_allowed_ips=true\n";
        for net in &peer.allowed_ips {
            let _ = writeln!(text, "allowed_ip={}", net);
        }
    }
    text + "\n"
}

// Another address for a server: the rest stays as it is, its session included
pub fn set_endpoint(public_key: &Key, endpoint: &SocketAddr) -> String {
    format!("set=1\npublic_key={}\nupdate_only=true\nendpoint={}\n\n", hex(public_key), endpoint)
}

// "errno=0" at the end of every answer; another number is the error of wireguard-go
pub fn check_errno(answer: &str) -> Result<(), String> {
    let errno = answer.lines().rev().find_map(|line| line.strip_prefix("errno="));
    match errno.map(str::trim) {
        Some("0") => Ok(()),
        Some(code) => Err(format!("wireguard-go refused it: error {}", code)),
        None => Err("no answer from wireguard-go".to_string()),
    }
}

// The counters of each server in the answer to GET
pub fn parse_get(answer: &str) -> Result<Vec<PeerStats>, String> {
    check_errno(answer)?;
    let mut peers: Vec<PeerStats> = Vec::new();
    for line in answer.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        if key == "public_key" {
            let Some(public_key) = parse_hex(value) else { continue };
            peers.push(PeerStats { public_key, endpoint: None, tx_bytes: 0, rx_bytes: 0, last_handshake: 0 });
            continue;
        }
        // the lines before the first peer are the ones of the interface, its private key among them
        let Some(peer) = peers.last_mut() else { continue };
        match key {
            "endpoint" => peer.endpoint = value.parse().ok(),
            "tx_bytes" => peer.tx_bytes = value.parse().unwrap_or(0),
            "rx_bytes" => peer.rx_bytes = value.parse().unwrap_or(0),
            "last_handshake_time_sec" => peer.last_handshake = value.parse().unwrap_or(0),
            _ => {}
        }
    }
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conf;

    const CONFIG: &str = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nListenPort = 51000\n\
                          Address = 10.103.1.2\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
                          PresharedKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
                          AllowedIPs = 10.103.1.0/24, fd00::/64\nEndpoint = vpn.example.com:51820\n\
                          PersistentKeepalive = 25\n[Peer]\nPublicKey = 3p7/K1jbsaULU4wqTbxh6yOqUF0X4v6mfS8/0d/Pzxo=\n\
                          AllowedIPs = 192.168.5.0/24\n";

    #[test]
    fn the_configuration() {
        let config = conf::parse(CONFIG).unwrap();
        let endpoint: SocketAddr = "[2001:db8::7]:51820".parse().unwrap();
        let text = set_config(&config, &[Some(endpoint), None]);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "set=1");
        // the keys in hex, as the protocol wants them
        assert_eq!(lines[1], format!("private_key={}", hex(&config.private_key)));
        assert!(lines[1].starts_with("private_key=c8"));
        assert_eq!(parse_hex(&hex(&config.private_key)), Some(config.private_key));
        assert_eq!(lines[2], "listen_port=51000");
        assert_eq!(lines[3], "replace_peers=true");
        assert_eq!(lines[4], format!("public_key={}", hex(&config.peers[0].public_key)));
        assert!(lines[5].starts_with("preshared_key="));
        assert_eq!(lines[6], "endpoint=[2001:db8::7]:51820");
        assert_eq!(lines[7], "persistent_keepalive_interval=25");
        assert_eq!(lines[8..11], ["replace_allowed_ips=true", "allowed_ip=10.103.1.0/24", "allowed_ip=fd00::/64"]);
        // the second server: no Endpoint, no keepalive
        assert_eq!(lines[11], format!("public_key={}", hex(&config.peers[1].public_key)));
        assert_eq!(lines[12..15], ["persistent_keepalive_interval=0", "replace_allowed_ips=true", "allowed_ip=192.168.5.0/24"]);
        assert!(text.ends_with("allowed_ip=192.168.5.0/24\n\n"));
    }

    #[test]
    fn another_address() {
        let key = conf::parse_key("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap();
        let text = set_endpoint(&key, &"203.0.113.2:51821".parse().unwrap());
        assert_eq!(
            text,
            format!("set=1\npublic_key={}\nupdate_only=true\nendpoint=203.0.113.2:51821\n\n", hex(&key))
        );
        assert!(!text.contains("private_key") && !text.contains("replace"));
    }

    #[test]
    fn the_counters() {
        let key = conf::parse_key("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap();
        let answer = format!(
            "private_key={0}\nlisten_port=51000\npublic_key={0}\npreshared_key={1}\nprotocol_version=1\n\
             endpoint=[2001:db8::7]:51820\nlast_handshake_time_sec=1767225600\nlast_handshake_time_nsec=12\n\
             tx_bytes=148\nrx_bytes=92\npersistent_keepalive_interval=25\nallowed_ip=10.103.1.0/24\n\
             public_key={2}\nlast_handshake_time_sec=0\ntx_bytes=0\nrx_bytes=0\nerrno=0\n\n",
            hex(&key),
            "0".repeat(64),
            "11".repeat(32)
        );
        let peers = parse_get(&answer).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].public_key, key);
        assert_eq!(peers[0].endpoint, Some("[2001:db8::7]:51820".parse().unwrap()));
        assert_eq!((peers[0].tx_bytes, peers[0].rx_bytes, peers[0].last_handshake), (148, 92, 1_767_225_600));
        assert_eq!((peers[1].public_key, peers[1].endpoint, peers[1].last_handshake), ([0x11; 32], None, 0));
        assert!(parse_get("errno=22\n\n").is_err());
        assert!(parse_get("").is_err());
        assert!(check_errno("errno=0\n\n").is_ok());
    }
}
