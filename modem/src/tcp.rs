use std::{
    ffi::CString,
    io,
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
};
use libc::{c_void, setsockopt, SOL_SOCKET, SO_BINDTODEVICE, SO_RCVBUF, SO_SNDBUF};
use tokio::net::{TcpSocket, TcpStream};

/// Which OS “fingerprint” to pretend to be
#[derive(Copy, Clone)]
pub enum OsFingerprint {
    Windows,
    Linux,
    Android,
}

pub async fn tcp_connect_with_fingerprint(
    remote_addr: SocketAddr,
    ifname: &str,
    fp: OsFingerprint,
) -> io::Result<TcpStream> {
    // 1) create a v4 or v6 socket:
    let socket = match remote_addr.ip() {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };

    socket.set_nodelay(true)?;
    socket.set_keepalive(true)?;

    // 2) bind to interface (exactly as you had it):
    let ifname_c = CString::new(ifname)?;
    let ret = unsafe {
        setsockopt(
            socket.as_raw_fd(),
            SOL_SOCKET,
            SO_BINDTODEVICE,
            ifname_c.as_ptr() as *const c_void,
            ifname_c.as_bytes().len() as u32,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // 3) apply your “OS fingerprint” tweaks:
    apply_fingerprint_opts(socket.as_raw_fd(), fp)?;

    // 4) actually connect:
    socket.connect(remote_addr).await
}

/// On Linux you can tweak TTL, buffer sizes, etc., to match common defaults.
/// (For real p0f‐style option ordering you’d need a full userspace TCP stack—
/// this just gets you the TTL & bufsize part.)
fn apply_fingerprint_opts(fd: i32, fp: OsFingerprint) -> io::Result<()> {
    // these are the “typical” defaults you’ll see in the wild:
    let (ttl, buf) = match fp {
        OsFingerprint::Windows => (128, 64 * 1024),   // TTL=128, 64 KiB buffers
        OsFingerprint::Linux   => (64,  29_200),      // TTL=64, ~29 KiB buffers
        OsFingerprint::Android => (64,  44_800),      // TTL=64, ~44 KiB buffers
    };

    // 3a) set IP TTL
    let rc = unsafe {
        setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            &ttl as *const _ as *const c_void,
            size_of_val(&ttl) as u32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // 3b) set send buffer
    let rc = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_SNDBUF,
            &buf as *const _ as *const c_void,
            size_of_val(&buf) as u32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // 3c) set recv buffer
    let rc = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVBUF,
            &buf as *const _ as *const c_void,
            size_of_val(&buf) as u32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

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
                return Err(io::Error::last_os_error());
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
                return Err(io::Error::last_os_error());
            }

            // Connect and return the stream
            socket.connect(remote_addr).await
        }
    }
}
