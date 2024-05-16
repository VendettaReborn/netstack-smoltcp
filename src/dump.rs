// SPDX-License-Identifier: MIT

use std::{
    fs, io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};

use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_sock_diag::{
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
    SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

pub fn resolve(addr: std::net::SocketAddr) {
    let (uid, inode) = match resolve_uid_inode(addr) {
        Some((uid, inode)) => (uid, inode),
        None => {
            eprintln!("Failed to resolve uid and inode");
            return;
        }
    };
    let process_name = match resolve_process_name_by_proc_search(uid, inode) {
        Ok(process_name) => process_name,
        Err(e) => {
            eprintln!("Failed to resolve process name: {}", e);
            return;
        }
    };
    println!("Process name: {}", process_name);
}

fn resolve_uid_inode(addr: std::net::SocketAddr) -> Option<(u32, u32)> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let mut nl_hdr = NetlinkHeader::default();
    nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut socket_id = SocketId::new_v4();
    socket_id.source_address = addr.ip();
    socket_id.source_port = addr.port();
    let mut packet = NetlinkMessage::new(
        nl_hdr,
        SockDiagMessage::InetRequest(InetRequest {
            family: if addr.is_ipv4() { AF_INET } else { AF_INET6 },
            protocol: IPPROTO_TCP,
            extensions: ExtensionFlags::empty(),
            states: StateFlags::all(),
            socket_id,
        })
        .into(),
    );

    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];

    // Before calling serialize, it is important to check that the buffer in
    // which we're emitting is big enough for the packet, other
    // `serialize()` panics.
    assert_eq!(buf.len(), packet.buffer_len());

    packet.serialize(&mut buf[..]);

    if let Err(_) = socket.send(&buf[..], 0) {
        return None;
    }

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();

            match rx_packet.payload {
                NetlinkPayload::Noop => {}
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    if response.header.socket_id.source_address != addr.ip()
                        || response.header.socket_id.source_port != addr.port()
                    {
                        continue;
                    }
                    let uid = response.header.uid;
                    let inode = response.header.inode;
                    println!("response: {:?}, uid: {}, inode: {}", response, uid, inode);
                    return Some((uid, inode));
                }
                NetlinkPayload::Done(_) => {
                    return None;
                }
                _ => return None,
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
    None
}

fn resolve_process_name_by_proc_search(uid: u32, inode: u32) -> Result<String, io::Error> {
    let files = fs::read_dir("/proc")?;

    let mut buffer = [0; libc::PATH_MAX as usize];
    let socket = format!("socket:[{}]", inode).into_bytes();

    for file in files {
        let file = file?;
        let file_name = file.file_name();
        let file_name = file_name
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid file name"))?;

        if !file.metadata()?.is_dir() || !file_name.chars().all(char::is_numeric) {
            continue;
        }

        let uid_match = file.metadata()?.uid() == uid;
        if !uid_match {
            // println!("file of {} uid not match", file_name);
            continue;
        }

        let process_path = format!("/proc/{}", file_name);
        let fd_path = format!("{}/fd", process_path);

        let fds = fs::read_dir(fd_path)?;
        for fd in fds {
            let fd = fd?;
            let fd_path = fd.path();

            let n = unsafe {
                libc::readlink(
                    fd_path.as_os_str().as_bytes().as_ptr() as *const libc::c_char,
                    buffer.as_mut_ptr() as *mut libc::c_char,
                    buffer.len(),
                )
            };
            if n == -1 {
                continue;
            }

            let n = n as usize;
            let read_link = &buffer[..n];
            if read_link == &socket[..] {
                let cmdline = fs::read_to_string(Path::new(&process_path).join("cmdline"))?;
                println!(
                    "process: {}, socket:{}, read_link:{}",
                    process_path,
                    String::from_utf8_lossy(&socket[..]),
                    String::from_utf8_lossy(read_link)
                );
                return Ok(split_cmdline(&cmdline));
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("Process of uid({}), inode({}) not found", uid, inode),
    ))
}

fn split_cmdline(cmdline: &str) -> String {
    cmdline.split('\0').next().unwrap_or("").to_string()
}

#[test]
fn test_read() {
    let mut buffer = [0u8; libc::PATH_MAX as usize];
    let fd_path = "/proc/46008/fd";
    let fds = fs::read_dir(fd_path).unwrap();
    for fd in fds {
        let fd = fd.unwrap();
        let fd_path = fd.path();

        let n = unsafe {
            libc::readlink(
                fd_path.as_os_str().as_bytes().as_ptr() as *const libc::c_char,
                buffer.as_mut_ptr() as *mut libc::c_char,
                buffer.len(),
            )
        };
        if n == -1 {
            continue;
        }

        let n = n as usize;
        let read_link = &buffer[..n];
        println!("{:?}", String::from_utf8_lossy(read_link));
    }
}

#[test]
fn test_search() {
    let res = resolve_process_name_by_proc_search(0, 216397);
    println!("{:?}", res);
}
