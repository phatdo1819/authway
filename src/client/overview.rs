// What the main window shows, where the system has one: a card for each VPN, in the order of the service, with its
// switch and its state in words and in a tone; its traffic while it's on; and the state of the service.

use super::details::{routing, sentence, split_endpoint, Routing};
use super::{nets, refusal_text, App, ServiceState, Session, Shell, Tunnel};
use crate::api::Page;
use crate::conf::IpNet;
use crate::strings;

// how the state looks
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    Off,
    Busy,
    Good,
    Warning,
    Bad,
}

#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Traffic {
    // seconds since 1970, 0 for never
    pub since: u64,
    pub handshake: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    // of this computer in the VPN, and of the server in use
    pub address: String,
    pub server: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Card {
    pub name: String,
    // the name of the server, when it says another than the name of the VPN
    pub server: String,
    // of the server in use, without the port
    pub host: String,
    // logged in as
    pub user: String,
    pub state: String,
    pub tone: Tone,
    // what the user can do about the state, or why it can't connect
    pub hint: Option<String>,
    // the switch: on while it's on or turns on, off while it turns off
    pub on: bool,
    pub can_switch: bool,
    pub needs_login: bool,
    pub page: Option<Page>,
    // all the traffic, or which networks
    pub routing: String,
    pub traffic: Option<Traffic>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Overview {
    pub service: ServiceState,
    // the user adds, renames and removes VPNs without asking for an administrator
    pub can_manage: bool,
    pub cards: Vec<Card>,
}

impl Overview {
    pub fn card(&self, name: &str) -> Option<&Card> {
        self.cards.iter().find(|card| card.name == name)
    }
}

fn tone(tunnel: &Tunnel) -> Tone {
    if tunnel.stopping || tunnel.connecting() {
        return Tone::Busy;
    }
    if !tunnel.info.up {
        return if tunnel.error.is_some() { Tone::Bad } else { Tone::Off };
    }
    if tunnel.no_answer() {
        return Tone::Warning;
    }
    if tunnel.page.is_none() {
        return if tunnel.info.handshake > 0 { Tone::Good } else { Tone::Busy };
    }
    match tunnel.session {
        Session::LoggedIn | Session::NotRequired => Tone::Good,
        Session::NeedLogin | Session::Unreachable => Tone::Warning,
        Session::Off | Session::Checking => Tone::Busy,
        Session::Blocked | Session::NoUser | Session::NoOtp | Session::NotEnrolled => Tone::Bad,
    }
}

fn hint(tunnel: &Tunnel) -> Option<String> {
    if tunnel.stopping || tunnel.connecting() {
        return None;
    }
    if !tunnel.info.up {
        return tunnel.error.as_deref().map(strings::error_connect);
    }
    if tunnel.no_answer() {
        return Some(strings::ERROR_NO_ANSWER.to_string());
    }
    refusal_text(tunnel.session).map(str::to_string)
}

// what goes through the tunnel, with the networks
fn routing_text(routes: &[IpNet]) -> String {
    let list = |ipv6: bool| {
        let networks: Vec<String> = routes.iter().filter(|net| net.addr.is_ipv6() == ipv6).map(ToString::to_string).collect();
        (!networks.is_empty()).then(|| networks.join(", "))
    };
    match routing(routes) {
        Routing::Full => strings::HOME_ROUTING_FULL.to_string(),
        Routing::None => strings::HOME_ROUTING_NONE.to_string(),
        Routing::FullIpv4 { .. } => strings::home_routing_full_one("IPv4", "IPv6", list(true).as_deref()),
        Routing::FullIpv6 { .. } => strings::home_routing_full_one("IPv6", "IPv4", list(false).as_deref()),
        Routing::Split => {
            let all: Vec<String> = routes.iter().map(ToString::to_string).collect();
            strings::home_routing_split(&all.join(", "))
        }
    }
}

pub fn card(tunnel: &Tunnel) -> Card {
    let info = &tunnel.info;
    let title = tunnel.title();
    let traffic = info.up.then(|| Traffic {
        since: info.since,
        handshake: info.handshake,
        rx_bytes: info.rx_bytes,
        tx_bytes: info.tx_bytes,
        address: nets(&info.addresses).iter().map(|net| net.addr.to_string()).collect::<Vec<_>>().join(", "),
        server: info.peers.iter().map(|peer| split_endpoint(&peer.address).0).find(|address| !address.is_empty()).unwrap_or_default(),
    });
    Card {
        name: info.name.clone(),
        server: if title == info.name { String::new() } else { title },
        host: tunnel.endpoint_host(),
        user: if tunnel.session == Session::LoggedIn { tunnel.user.clone() } else { String::new() },
        state: sentence(&tunnel.describe()),
        tone: tone(tunnel),
        hint: hint(tunnel),
        on: (info.up || tunnel.connecting()) && !tunnel.stopping,
        can_switch: !tunnel.stopping,
        needs_login: tunnel.needs_login(),
        page: tunnel.page,
        routing: if info.after_login.is_empty() {
            routing_text(&nets(&info.routes))
        } else {
            format!("{} {}", routing_text(&nets(&info.routes)), strings::HOME_ROUTING_BEFORE_LOGIN)
        },
        traffic,
    }
}

impl<S: Shell> App<S> {
    pub fn overview(&self) -> Overview {
        Overview { service: self.service, can_manage: self.can_manage, cards: self.tunnels.iter().map(card).collect() }
    }
}
