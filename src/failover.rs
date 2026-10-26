// The other addresses of a server, the "# Fallback = ..." line that the firewall writes after Endpoint: when the
// server stops answering at one address, the tunnel goes on with the next one, a line that still works. WireGuard has
// no connection to lose: the tunnel stays on, with its addresses, routes and DNS, and its session on the server (the
// public IP of this computer doesn't change); only the address that the driver sends to does.
//
// A server that answers sends something back within seconds of anything but a keepalive: the response to a
// handshake within the round trip, and after data either data or a keepalive of its own, within 10 seconds
// (KEEPALIVE_TIMEOUT of WireGuard). So it's gone when the bytes received stay the same for SILENCE after this
// computer sent anything else. Then the next address, around the list as long as none answers, and the one that
// answers stays: the first one again at the next connection.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::conf::{Endpoint, Peer};

// the counters of the driver are read this often
pub const POLL: Duration = Duration::from_secs(1);
pub const SILENCE: Duration = Duration::from_secs(20);
// for a name, during a change of address: the DNS servers may be the ones of the tunnel that doesn't answer
pub const LOOKUP_TIME: Duration = Duration::from_secs(5);

// A keepalive is the only message of WireGuard that gets no answer: 32 bytes, and two can go in one poll. Any other
// is longer or not a multiple of 32: the initiation of a handshake is 148 bytes, data at least 64.
fn needs_answer(sent: u64) -> bool {
    !sent.is_multiple_of(32) || sent > 64
}

// Whether the server answers, from its counters
#[derive(Default)]
pub struct Watch {
    rx: u64,
    tx: u64,
    // since when the server owes an answer
    waiting: Option<Instant>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    Answered,
    Quiet,
    // no answer for SILENCE
    Silent,
}

impl Watch {
    pub fn update(&mut self, now: Instant, rx: u64, tx: u64) -> Poll {
        let sent = tx.saturating_sub(self.tx);
        let received = rx != self.rx;
        self.rx = rx;
        self.tx = tx;
        if received {
            self.waiting = None;
            return Poll::Answered;
        }
        if self.waiting.is_none() && needs_answer(sent) {
            self.waiting = Some(now);
        }
        match self.waiting {
            Some(since) if now.duration_since(since) >= SILENCE => Poll::Silent,
            _ => Poll::Quiet,
        }
    }

    // a new address gets the whole SILENCE, from what is sent to it
    pub fn restart(&mut self) {
        self.waiting = None;
    }
}

// The address of a server: IPv4 first, the servers of the firewall listen on it
pub fn resolve(endpoint: &Endpoint) -> Result<SocketAddr, String> {
    let addresses: Vec<SocketAddr> = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|error| format!("Can't find the server {}: {}.", endpoint.host, error))?
        .collect();
    addresses
        .iter()
        .find(|address| address.is_ipv4())
        .or(addresses.first())
        .copied()
        .ok_or_else(|| format!("Can't find the server {}.", endpoint.host))
}

// resolve, or None after the time given: the lookup goes on alone
pub fn lookup(endpoint: &Endpoint, time: Duration) -> Option<SocketAddr> {
    if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, endpoint.port));
    }
    let (sender, receiver) = mpsc::channel();
    let endpoint = endpoint.clone();
    thread::spawn(move || {
        let _ = sender.send(resolve(&endpoint));
    });
    receiver.recv_timeout(time).ok().and_then(Result::ok)
}

// The addresses of one server of a tunnel that is on, and the one in use
pub struct Failover {
    // the Endpoint, then the fallbacks
    endpoints: Vec<Endpoint>,
    // the last address found for each
    addresses: Vec<Option<SocketAddr>>,
    // the one the driver sends to
    current: usize,
    // the last one tried, past the ones that couldn't be found
    tried: usize,
    watch: Watch,
    // on another address that hasn't answered yet: for the log
    trying: bool,
}

// What the watch of a server wants: to send to this address, found again
pub struct Next {
    pub index: usize,
    pub endpoint: Endpoint,
    // the address found before, for when the lookup fails
    pub known: Option<SocketAddr>,
}

impl Failover {
    // At the connection: the first address that can be found, the others too when they can, for later. None for a
    // server without an Endpoint, that this computer never sends to first.
    pub fn start(peer: &Peer) -> Result<Option<Failover>, String> {
        let Some(endpoint) = &peer.endpoint else { return Ok(None) };
        let endpoints: Vec<Endpoint> = std::iter::once(endpoint).chain(&peer.fallbacks).cloned().collect();
        let results: Vec<Result<SocketAddr, String>> = endpoints.iter().map(resolve).collect();
        let Some(current) = results.iter().position(Result::is_ok) else {
            return Err(results.into_iter().next().and_then(Result::err).unwrap_or_default());
        };
        Ok(Some(Failover::new(endpoints, results.into_iter().map(Result::ok).collect(), current)))
    }

    fn new(endpoints: Vec<Endpoint>, addresses: Vec<Option<SocketAddr>>, current: usize) -> Failover {
        Failover { endpoints, addresses, current, tried: current, watch: Watch::default(), trying: false }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoints[self.current]
    }

    // 0 for the Endpoint, then 1 for the first fallback...
    pub fn index(&self) -> usize {
        self.current
    }

    pub fn address(&self) -> SocketAddr {
        self.addresses[self.current].expect("the address in use is known")
    }

    // anything to do when it doesn't answer: another address, or a name to look up again
    fn can_move(&self) -> bool {
        self.endpoints.len() > 1 || self.endpoints[0].host.parse::<IpAddr>().is_err()
    }

    // the counters of the server at one poll: Some when it's time to try the next address
    pub fn poll(&mut self, now: Instant, rx: u64, tx: u64) -> (Poll, Option<Next>) {
        let poll = self.watch.update(now, rx, tx);
        if poll == Poll::Answered && !self.trying {
            return (Poll::Quiet, None);
        }
        self.trying &= poll != Poll::Answered;
        if poll != Poll::Silent || !self.can_move() {
            return (poll, None);
        }
        let index = (self.tried + 1) % self.endpoints.len();
        (poll, Some(Next { index, endpoint: self.endpoints[index].clone(), known: self.addresses[index] }))
    }

    // The driver sends to this address of the endpoint now. None when it couldn't be found: the driver keeps the
    // address in use, and the next endpoint comes at the next poll. False when nothing changed, the same name at the
    // same address for example.
    pub fn moved(&mut self, index: usize, address: Option<SocketAddr>) -> bool {
        self.tried = index;
        let Some(address) = address else { return false };
        let changed = index != self.current || Some(address) != self.addresses[index];
        self.current = index;
        self.addresses[index] = Some(address);
        self.watch.restart();
        self.trying = changed;
        changed
    }

    // the driver refused the address: the whole SILENCE again before the next try
    pub fn refused(&mut self) {
        self.watch.restart();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(start: Instant, seconds: u64) -> Instant {
        start + Duration::from_secs(seconds)
    }

    #[test]
    fn what_needs_an_answer() {
        assert!(!needs_answer(0));
        // keepalives
        assert!(!needs_answer(32));
        assert!(!needs_answer(64));
        // the initiation of a handshake, with a keepalive, data
        assert!(needs_answer(148));
        assert!(needs_answer(180));
        assert!(needs_answer(80));
        assert!(needs_answer(96));
        assert!(needs_answer(1420));
    }

    #[test]
    fn a_server_that_answers() {
        let start = Instant::now();
        let mut watch = Watch::default();
        // the handshake, then data both ways, for a minute
        assert_eq!(watch.update(at(start, 1), 0, 148), Poll::Quiet);
        assert_eq!(watch.update(at(start, 2), 92, 180), Poll::Answered);
        for second in 3..60 {
            assert_ne!(watch.update(at(start, second), 92 + second * 100, 180 + second * 100), Poll::Silent);
        }
        // then idle with keepalives only, for minutes: they get no answer, and need none
        let (rx, mut tx) = (92 + 59 * 100, 180 + 59 * 100);
        for second in 60..300 {
            if second % 25 == 0 {
                tx += 32;
            }
            assert_eq!(watch.update(at(start, second), rx, tx), Poll::Quiet, "{}", second);
        }
        // data again: the passive keepalive of the server comes within 10 seconds
        assert_eq!(watch.update(at(start, 300), rx, tx + 500), Poll::Quiet);
        assert_eq!(watch.update(at(start, 310), rx, tx + 500), Poll::Quiet);
        assert_eq!(watch.update(at(start, 311), rx + 32, tx + 500), Poll::Answered);
    }

    #[test]
    fn a_server_that_stops_answering() {
        let start = Instant::now();
        let mut watch = Watch::default();
        assert_eq!(watch.update(at(start, 1), 92, 148), Poll::Answered);
        // data unanswered, then the handshakes of WireGuard every 5 seconds
        assert_eq!(watch.update(at(start, 2), 92, 1148), Poll::Quiet);
        let mut tx = 1148;
        for second in 3..22 {
            if second % 5 == 2 {
                tx += 148;
            }
            assert_eq!(watch.update(at(start, second), 92, tx), Poll::Quiet, "{}", second);
        }
        assert_eq!(watch.update(at(start, 22), 92, tx), Poll::Silent);
        assert_eq!(watch.update(at(start, 23), 92, tx), Poll::Silent);
        // after a change of address: SILENCE from the first handshake sent to it
        watch.restart();
        assert_eq!(watch.update(at(start, 24), 92, tx), Poll::Quiet);
        assert_eq!(watch.update(at(start, 27), 92, tx + 148), Poll::Quiet);
        assert_eq!(watch.update(at(start, 46), 92, tx + 148 * 4), Poll::Quiet);
        assert_eq!(watch.update(at(start, 47), 92, tx + 148 * 5), Poll::Silent);
    }

    #[test]
    fn nothing_sent_nothing_owed() {
        // a tunnel without keepalive and without traffic: no answer is due
        let start = Instant::now();
        let mut watch = Watch::default();
        for second in 0..120 {
            assert_eq!(watch.update(at(start, second), 0, 0), Poll::Quiet);
        }
    }

    fn endpoints(texts: &[&str]) -> Vec<Endpoint> {
        texts.iter().map(|text| Endpoint::parse(text).unwrap()).collect()
    }

    fn address(text: &str) -> Option<SocketAddr> {
        Some(text.parse().unwrap())
    }

    // a server silent from the start: the seconds of the polls when it's time to move, and where
    fn silence(failover: &mut Failover, start: Instant, from: u64, tx: &mut u64) -> (u64, Next) {
        for second in from..from + 60 {
            *tx += 148;
            if let (Poll::Silent, Some(next)) = failover.poll(at(start, second), 0, *tx) {
                return (second, next);
            }
        }
        panic!("never silent");
    }

    #[test]
    fn around_the_addresses() {
        let start = Instant::now();
        let list = endpoints(&["203.0.113.1:51820", "vpn2.example.com:51820", "203.0.113.3:51821"]);
        let mut failover = Failover::new(list, vec![address("203.0.113.1:51820"), None, address("203.0.113.3:51821")], 0);
        assert_eq!(failover.endpoint().to_string(), "203.0.113.1:51820");
        let mut tx = 0;

        let (second, next) = silence(&mut failover, start, 0, &mut tx);
        assert_eq!((second, next.index, next.known), (20, 1, None));
        assert_eq!(next.endpoint.to_string(), "vpn2.example.com:51820");
        assert!(failover.moved(1, address("198.51.100.2:51820")));
        assert_eq!((failover.index(), failover.address()), (1, "198.51.100.2:51820".parse().unwrap()));

        let (second, next) = silence(&mut failover, start, 21, &mut tx);
        assert_eq!((second, next.index), (41, 2));
        assert!(failover.moved(2, next.known));

        // back to the first one, by its last address
        let (_, next) = silence(&mut failover, start, 42, &mut tx);
        assert_eq!((next.index, next.known), (0, address("203.0.113.1:51820")));
        assert!(failover.moved(0, next.known));

        // the next one can't be found: skipped at the next poll, the driver keeps the address in use
        let (second, next) = silence(&mut failover, start, 63, &mut tx);
        assert_eq!((next.index, next.known), (1, address("198.51.100.2:51820")));
        assert!(!failover.moved(1, None));
        assert_eq!((failover.index(), failover.address()), (0, "203.0.113.1:51820".parse().unwrap()));
        tx += 148;
        let (poll, next) = failover.poll(at(start, second + 1), 0, tx);
        assert_eq!((poll, next.as_ref().map(|next| next.index)), (Poll::Silent, Some(2)));
        assert!(!failover.moved(2, None));
        // around to the one in use: the same address, nothing to change, and the whole SILENCE again
        let (poll, next) = failover.poll(at(start, second + 2), 0, tx + 148);
        assert_eq!((poll, next.as_ref().map(|next| next.index)), (Poll::Silent, Some(0)));
        assert!(!failover.moved(0, address("203.0.113.1:51820")));
        assert_eq!(failover.poll(at(start, second + 3), 0, tx + 296).0, Poll::Quiet);
    }

    #[test]
    fn the_address_that_answers_stays() {
        let start = Instant::now();
        let list = endpoints(&["203.0.113.1:51820", "203.0.113.2:51820"]);
        let mut failover = Failover::new(list, vec![address("203.0.113.1:51820"), address("203.0.113.2:51820")], 0);
        let mut tx = 0;
        let (second, next) = silence(&mut failover, start, 0, &mut tx);
        assert!(failover.moved(next.index, next.known));
        // the first answer after a change is told once
        assert_eq!(failover.poll(at(start, second + 3), 92, tx + 148).0, Poll::Answered);
        assert_eq!(failover.poll(at(start, second + 4), 184, tx + 300).0, Poll::Quiet);
        for offset in 5..200 {
            let bytes = offset * 100;
            let (poll, next) = failover.poll(at(start, second + offset), 184 + bytes, tx + 300 + bytes);
            assert!(poll == Poll::Quiet && next.is_none(), "{}", offset);
        }
        assert_eq!(failover.index(), 1);
    }

    #[test]
    fn one_address() {
        let start = Instant::now();
        let mut tx = 0;
        // an IP: nothing else to try
        let mut failover = Failover::new(endpoints(&["203.0.113.1:51820"]), vec![address("203.0.113.1:51820")], 0);
        for second in 0..100 {
            tx += 148;
            assert!(failover.poll(at(start, second), 0, tx).1.is_none());
        }
        // a name: looked up again, and the new address used when it changed
        let mut failover = Failover::new(endpoints(&["vpn.example.com:51820"]), vec![address("203.0.113.1:51820")], 0);
        let (_, next) = silence(&mut failover, start, 0, &mut tx);
        assert_eq!((next.index, next.known), (0, address("203.0.113.1:51820")));
        assert!(!failover.moved(0, address("203.0.113.1:51820")));
        let (_, next) = silence(&mut failover, start, 21, &mut tx);
        assert!(failover.moved(next.index, address("203.0.113.9:51820")));
        assert_eq!(failover.address(), "203.0.113.9:51820".parse().unwrap());
    }

    #[test]
    fn at_the_connection() {
        let peer = |endpoint: &str, fallbacks: &[&str]| Peer {
            public_key: [0; 32],
            preshared_key: None,
            allowed_ips: Vec::new(),
            endpoint: Endpoint::parse(endpoint),
            fallbacks: endpoints(fallbacks),
            keepalive: 25,
            name: None,
        };
        let failover = Failover::start(&peer("192.0.2.1:51820", &["192.0.2.2:51820"])).unwrap().unwrap();
        assert_eq!((failover.index(), failover.address()), (0, "192.0.2.1:51820".parse().unwrap()));
        // the Endpoint can't be found: the first fallback that can
        let failover = Failover::start(&peer("nowhere.invalid:51820", &["nowhere2.invalid:1", "192.0.2.2:51820"])).unwrap();
        assert_eq!(failover.map(|failover| failover.index()), Some(2));
        // none: the error of the Endpoint
        let error = Failover::start(&peer("nowhere.invalid:51820", &["nowhere2.invalid:1"])).err().unwrap();
        assert!(error.starts_with("Can't find the server nowhere.invalid"), "{}", error);
        assert!(Failover::start(&peer("", &[])).unwrap().is_none());
    }
}
