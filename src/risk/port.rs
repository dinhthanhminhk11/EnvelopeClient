//! `frida.port` (heavy flag `frida`): something listening on 127.0.0.1:27042, frida-server's default port. No Android
//! or iOS component uses it. Platform-neutral (std sockets only), so the Android scan and the Apple scan share it.

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// frida-server's default listening port.
const FRIDA_SERVER_PORT: u16 = 27042;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(150);

/// `frida.port`: a TCP connect to 127.0.0.1:27042 that succeeds within 150 ms.
pub fn frida_port_open() -> bool {
    loopback_port_open(FRIDA_SERVER_PORT)
}

fn loopback_port_open(port: u16) -> bool {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&address, CONNECT_TIMEOUT).is_ok()
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn frida_server_default_port_within_150_ms() {
        assert_eq!(FRIDA_SERVER_PORT, 27042);
        assert_eq!(CONNECT_TIMEOUT, Duration::from_millis(150));
    }

    /// An ephemeral port, never 27042: `risk::tests::host_scan_runs` runs the real check in parallel. Only the
    /// positive half: after the listener is dropped, a child process that a test running in parallel forks in the
    /// window between socket() and FD_CLOEXEC on macOS (the Node interop peers) can keep the port open. The negative
    /// half, and 27042 through `frida_port_open` and `risk::scan`, are in tests/frida_port.rs, a process of its own.
    #[test]
    fn sees_a_loopback_listener() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_ne!(port, FRIDA_SERVER_PORT);
        assert!(loopback_port_open(port));
    }
}
