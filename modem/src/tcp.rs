use std::{
    ffi::CString,
    io,
    mem::size_of_val,
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
    MacOS,
    IOS,
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

    // 2) bind to interface
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

/// Tweak TTL & sock buf sizes to match each OS’s usual defaults
fn apply_fingerprint_opts(fd: i32, fp: OsFingerprint) -> io::Result<()> {
    // (ttl, bufsize)
    let (ttl, buf) = match fp {
        OsFingerprint::Windows => (128, 64 * 1024),    // TTL=128, 64 KiB
        OsFingerprint::Linux   => (64,  29_200),       // TTL=64, ~29 KiB
        OsFingerprint::Android => (64,  44_800),       // TTL=64, ~44 KiB
        OsFingerprint::MacOS   => (64,  65_536),       // TTL=64, 64 KiB
        OsFingerprint::IOS     => (64,  32_768),       // TTL=64, 32 KiB
    };

    // set IP TTL
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

    // set send buffer
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

    // set recv buffer
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
