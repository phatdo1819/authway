// The device proof of the login, for the servers that require device binding (ns-wgauth): the service keeps one P-256
// key for each tunnel, that never leaves this computer, and signs the challenge of the login page with it. The server
// enrolls the key at the first login, then accepts only that one. With the machine ID, the service also sends a hash
// of the hardware ID of this computer. The same on every system; the keys and the ID are in devkey.

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::conf::{self, Config};
use crate::{devkey, digest, store, x25519};

pub const MESSAGE: &str = "ns-wgauth-device-v1";
// DER SubjectPublicKeyInfo of a P-256 key, before its 65 bytes uncompressed point
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
// longer than any challenge of the login page
const MAX_CHALLENGE: usize = 128;
const MAX_USERNAME: usize = 256;

// The `device` object of the login request
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct Proof {
    pub challenge: String,
    // DER, base64
    pub signature: String,
    // DER SubjectPublicKeyInfo, base64
    pub public_key: String,
    // where the key is
    pub kind: String,
    // of this computer, for the administrator
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub machine_id: String,
}

// What the device signs: one challenge, one server, one peer, one user name
pub fn message(
    challenge: &str,
    server_key: &str,
    peer_key: &str,
    address: &str,
    username: &str,
    machine_id: &str,
) -> Vec<u8> {
    [MESSAGE, challenge, server_key, peer_key, address, username, machine_id].join("\n").into_bytes()
}

pub fn spki(point: &[u8; 65]) -> Vec<u8> {
    let mut der = SPKI_PREFIX.to_vec();
    der.extend_from_slice(point);
    der
}

// The ID of a device key, as the login page knows it: the SHA-256 of its DER public key, in hex
pub fn id_of(point: &[u8; 65]) -> String {
    digest::hex(&digest::sha256(&spki(point)))
}

// The ID of the key of the tunnel, empty when it has none yet: the login page then knows this computer isn't the
// enrolled one. No key is made for it, a server without device binding never needs one.
pub fn key_id(tunnel: &str, id: &store::Id) -> Result<String, String> {
    Ok(devkey::existing_point(tunnel, id)?.map(|point| id_of(&point)).unwrap_or_default())
}

// The DER form of an ECDSA signature given as r and s, 32 bytes each
pub fn der_signature(raw: &[u8; 64]) -> Vec<u8> {
    fn integer(value: &[u8]) -> Vec<u8> {
        let start = value.iter().position(|&byte| byte != 0).unwrap_or(value.len() - 1);
        let value = &value[start..];
        // a positive integer: a leading zero when the high bit is set
        let pad = value[0] & 0x80 != 0;
        let mut out = vec![0x02, (value.len() + pad as usize) as u8];
        if pad {
            out.push(0);
        }
        out.extend_from_slice(value);
        out
    }
    let mut body = integer(&raw[..32]);
    body.extend(integer(&raw[32..]));
    let mut der = vec![0x30, body.len() as u8];
    der.extend(body);
    der
}

// The machine ID as the server records it: an HMAC keyed with the public key of the server, so the server never sees
// the ID, and two servers get different values for the same computer
pub fn machine_hmac(server_key: &conf::Key, machine: &str) -> String {
    digest::hex(&digest::hmac_sha256(server_key, machine.trim().to_lowercase().as_bytes()))
}

// one line of the message: the service signs nothing else
fn is_field(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

// The server of the configuration that the login page `host` belongs to, the first one when none routes it
fn server_of(config: &Config, host: Ipv4Addr) -> Option<&conf::Peer> {
    let routes = |peer: &&conf::Peer| peer.allowed_ips.iter().any(|net| net.contains(IpAddr::V4(host)));
    config.peers.iter().find(routes).or(config.peers.first())
}

// The proof of a login on the page at `host`, signed by the key of the tunnel, made when it's missing
pub fn prove(
    tunnel: &str,
    id: &store::Id,
    config: &Config,
    host: Ipv4Addr,
    challenge: &str,
    username: &str,
    machine_id: bool,
) -> Result<Proof, String> {
    if !is_field(challenge, MAX_CHALLENGE) || !is_field(username, MAX_USERNAME) {
        return Err("not a challenge of a login page".into());
    }
    let server = server_of(config, host).ok_or("the configuration has no server")?;
    let address = config
        .addresses
        .iter()
        .find_map(|net| match net.addr {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        })
        .ok_or("the configuration has no IPv4 address")?;
    let machine = if machine_id {
        let raw = devkey::machine_id().ok_or("the ID of this computer can't be read")?;
        machine_hmac(&server.public_key, &raw)
    } else {
        String::new()
    };
    let peer_key = conf::encode_key(&x25519::public_key(&config.private_key));
    let server_key = conf::encode_key(&server.public_key);
    let data = message(challenge, &server_key, &peer_key, &address.to_string(), username, &machine);
    let point = devkey::public_point(tunnel, id)?;
    let signature = devkey::sign(tunnel, id, &data)?;
    Ok(Proof {
        challenge: challenge.to_string(),
        signature: conf::base64(&signature),
        public_key: conf::base64(&spki(&point)),
        kind: devkey::KIND.to_string(),
        name: devkey::computer_name(),
        machine_id: machine,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages() {
        let data = message("CHALLENGE", "SERVER", "PEER", "10.103.1.2", "Alice", &"ab".repeat(32));
        let expected = format!("ns-wgauth-device-v1\nCHALLENGE\nSERVER\nPEER\n10.103.1.2\nAlice\n{}", "ab".repeat(32));
        assert_eq!(data, expected.as_bytes());
        assert!(message("C", "S", "P", "10.103.1.2", "alice", "").ends_with(b"\nalice\n"));
        assert!(is_field("alice", 10) && !is_field("", 10) && !is_field("a\nb", 10) && !is_field(&"a".repeat(11), 10));
    }

    #[test]
    fn der() {
        let mut raw = [0u8; 64];
        raw[31] = 1;
        raw[32] = 0x80;
        // r = 1, s with its high bit set: a zero before it
        let der = der_signature(&raw);
        assert_eq!(&der[..5], &[0x30, 3 + 2 + 33, 0x02, 0x01, 0x01]);
        assert_eq!(&der[5..8], &[0x02, 0x21, 0x00]);
        assert_eq!(der.len(), 2 + 3 + 2 + 33);
        // zero
        let der = der_signature(&[0u8; 64]);
        assert_eq!(der, vec![0x30, 6, 0x02, 1, 0, 0x02, 1, 0]);
        // the longest: 72 bytes
        assert_eq!(der_signature(&[0xff; 64]).len(), 72);
    }

    #[test]
    fn keys_and_ids() {
        let point = [4u8; 65];
        let der = spki(&point);
        assert_eq!(der.len(), 91);
        assert_eq!(&der[..2], &[0x30, 0x59]);
        // the same as nethsec.wgauth.device_key_id on the firewall
        assert_eq!(id_of(&point), "4bc1fd1a02bd2365584af4f2ed045fad3e6e83d3ec744395310511277913ee7c");
        assert_eq!(conf::base64(&[1, 2, 3, 4]), "AQIDBA==");
        assert_eq!(conf::base64(b"ab"), "YWI=");
        assert_eq!(conf::base64(b""), "");
        let key = [7u8; 32];
        let id = machine_hmac(&key, "4C4C4544-0042-3510-8051-B4C04F4C4D32\n");
        assert_eq!(id, digest::hex(&digest::hmac_sha256(&key, b"4c4c4544-0042-3510-8051-b4c04f4c4d32")));
        assert_eq!(id.len(), 64);
        assert_ne!(machine_hmac(&[8u8; 32], "4c4c4544-0042-3510-8051-b4c04f4c4d32"), id);
    }

    #[test]
    fn the_server_of_the_page() {
        let text = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.103.1.2/32\n\
                    [Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 192.168.5.0/24\n\
                    Endpoint = 192.0.2.1:51820\n[Peer]\nPublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=\n\
                    AllowedIPs = 10.103.1.0/24\nEndpoint = 192.0.2.2:51820\n";
        let config = conf::parse(text).unwrap();
        let host = "10.103.1.1".parse().unwrap();
        assert_eq!(server_of(&config, host).unwrap().public_key, config.peers[1].public_key);
        assert_eq!(server_of(&config, "172.16.0.1".parse().unwrap()).unwrap().public_key, config.peers[0].public_key);
    }
}
