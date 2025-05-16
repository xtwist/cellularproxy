use std::ffi::{CString};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use libc::{c_void, setsockopt, SOL_SOCKET, SO_BINDTODEVICE};
use tokio::net::{TcpSocket, TcpStream};

pub async fn tcp_connect_via_interface(
    remote_addr: SocketAddr,
    ifname: &str,
) -> io::Result<TcpStream> {
    // Approach 1: Using TcpSocket (simplest and most reliable)
    match remote_addr.ip() {
        IpAddr::V4(_) => {
            let socket = TcpSocket::new_v4()?;
            socket.set_nodelay(true)?;
            socket.set_keepalive(true)?;

            // Use SO_BINDTODEVICE to bind the socket to a specific network interface
            let ifname_c = CString::new(ifname)?;
            let res = unsafe {
                setsockopt(
                    socket.as_raw_fd(),
                    SOL_SOCKET,
                    SO_BINDTODEVICE,
                    ifname_c.as_ptr() as *const c_void,
                    ifname_c.as_bytes().len() as u32,
                )
            };
            if res != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // Connect and return the stream
            socket.connect(remote_addr).await
        }
        IpAddr::V6(_) => {
            let socket = TcpSocket::new_v6()?;
            socket.set_nodelay(true)?;
            socket.set_keepalive(true)?;

            // Use SO_BINDTODEVICE to bind the socket to a specific network interface
            let ifname_c = CString::new(ifname)?;
            let res = unsafe {
                setsockopt(
                    socket.as_raw_fd(),
                    SOL_SOCKET,
                    SO_BINDTODEVICE,
                    ifname_c.as_ptr() as *const c_void,
                    ifname_c.as_bytes().len() as u32,
                )
            };
            if res != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // Connect and return the stream
            socket.connect(remote_addr).await
        }
    }
}
