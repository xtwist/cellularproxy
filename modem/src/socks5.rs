use anyhow::{anyhow, Result};
use libc::{c_void, setsockopt, SOL_SOCKET, SO_BINDTODEVICE};
use socks5_protocol::{
    Address, AuthMethod, AuthRequest, AuthResponse, CommandRequest, CommandResponse, Version,
};
use std::{
    collections::HashMap,
    ffi::CString,
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
};

async fn tcp_connect_via_interface(
    remote_addr: SocketAddr,
    ifname: &str,
) -> std::io::Result<TcpStream> {
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

pub async fn handle_socks5(
    mut stream: TcpStream,
    iface_map: HashMap<String, String>,
) -> Result<()> {
    // 1) SOCKS5 greeting
    Version::read(&mut stream).await?; // expect 0x05
    let methods = AuthRequest::read(&mut stream).await?; // read NMETHODS + METHODS
                                                         // choose username/password or fail
    let chosen = if methods.0.contains(&AuthMethod::UsernamePassword) {
        AuthMethod::UsernamePassword
    } else {
        AuthMethod::NoAcceptableMethod
    };
    Version::V5.write(&mut stream).await?; // send 0x05
    AuthResponse::new(chosen).write(&mut stream).await?; // send METHOD
    if chosen != AuthMethod::UsernamePassword {
        return Err(anyhow!("no supported auth methods"));
    }

    // 2) RFC-1929 username/password sub-negotiation
    let v = stream.read_u8().await?; // expect 0x01
    if v != 0x01 {
        return Err(anyhow!("invalid auth version {}", v));
    }
    let ulen = stream.read_u8().await? as usize;
    let mut ubuf = vec![0u8; ulen];
    stream.read_exact(&mut ubuf).await?;
    let plen = stream.read_u8().await? as usize;
    let mut pbuf = vec![0u8; plen];
    stream.read_exact(&mut pbuf).await?;

    let username = String::from_utf8(ubuf)?;
    let password = String::from_utf8(pbuf)?;
    let ok = username == "modem" && iface_map.contains_key(&password);

    // reply sub-negotiation status
    stream.write_u8(0x01).await?; // version
    stream.write_u8(if ok { 0x00 } else { 0x01 }).await?; // status

    let ifname = &iface_map.get(&password).unwrap();

    let cmd = CommandRequest::read(&mut stream).await?;

    let dest = cmd.address;
    let dest_sa = dest
        .to_socket_addr()
        .map_err(|_| anyhow!("only IP addrs supported"))?;

    let mut outbound = match tcp_connect_via_interface(dest_sa, ifname).await {
        Ok(outbound) => outbound,
        Err(e) => {
            return Err(anyhow!("connect: {}", e));
        }
    };

    // 5) reply success + bind address
    let local = outbound.local_addr()?;
    let bind_addr = Address::from(local);
    let resp = CommandResponse::success(bind_addr);
    resp.write(&mut stream).await?;

    // 6) tunnel client ↔ target until EOF
    copy_bidirectional(&mut stream, &mut outbound).await?;

    Ok(())
}
