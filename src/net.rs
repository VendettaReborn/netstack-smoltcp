use std::time::Duration;

use socket2::TcpKeepalive;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::utils::DEFAULT_IF_INDEX;

#[cfg(target_os = "windows")]
mod win_net {
    use std::{
        cell::RefCell,
        collections::HashMap,
        ffi::CString,
        io::{self, ErrorKind},
        mem,
        os::windows::io::AsRawSocket,
        time::{Duration, Instant},
    };

    use tracing::error;
    use windows_sys::{
        core::PCSTR,
        Win32::{
            NetworkManagement::IpHelper::if_nametoindex,
            Networking::WinSock::{
                htonl, setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF,
                IP_UNICAST_IF, SOCKET, SOCKET_ERROR,
            },
        },
    };

    pub fn find_adapter_interface_index(is_ipv6: bool, iface: &str) -> io::Result<Option<u32>> {
        let adapaters =
            ipconfig::get_adapters().map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;
        let if_index = adapaters
            .iter()
            .filter(|a| {
                if is_ipv6 {
                    a.ipv6_if_index() != 0
                } else {
                    a.ipv4_if_index() != 0
                }
            })
            .find(|a| a.friendly_name() == iface || a.adapter_name() == iface)
            .map(|adapter| adapter.ipv4_if_index());
        Ok(if_index)
    }

    fn find_interface_index_cached(is_ipv6: bool, iface: &str) -> io::Result<u32> {
        const INDEX_EXPIRE_DURATION: Duration = Duration::from_secs(5);

        thread_local! {
            static INTERFACE_INDEX_CACHE: RefCell<HashMap<String, (u32, Instant)>> =
                RefCell::new(HashMap::new());
        }

        let cache_index = INTERFACE_INDEX_CACHE.with(|cache| cache.borrow().get(iface).cloned());
        if let Some((idx, insert_time)) = cache_index {
            // short-path, cache hit for most cases
            let now = Instant::now();
            if now - insert_time < INDEX_EXPIRE_DURATION {
                return Ok(idx);
            }
        }

        // Get from API GetAdaptersAddresses
        let idx = match find_adapter_interface_index(is_ipv6, iface)? {
            Some(idx) => idx,
            None => unsafe {
                // Windows if_nametoindex requires a C-string for interface name
                let ifname = CString::new(iface).expect("iface");

                // https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff553788(v=vs.85)
                let if_index = if_nametoindex(ifname.as_ptr() as PCSTR);
                if if_index == 0 {
                    // If the if_nametoindex function fails and returns zero, it is not possible to determine an error code.
                    error!("if_nametoindex {} fails", iface);
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "invalid interface name",
                    ));
                }

                if_index
            },
        };

        INTERFACE_INDEX_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert(iface.to_owned(), (idx, Instant::now()));
        });

        Ok(idx)
    }

    // the addr doesn't matter, it's just a mark of ip version
    #[allow(unused)]
    pub fn set_ip_unicast_if<S: AsRawSocket>(
        socket: &S,
        is_ipv6: bool,
        iface: &str,
    ) -> io::Result<()> {
        let handle = socket.as_raw_socket() as SOCKET;

        let if_index = find_interface_index_cached(is_ipv6, iface)?;

        unsafe {
            // https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
            let ret = if !is_ipv6 {
                // Interface index is in network byte order for IPPROTO_IP.
                let if_index = htonl(if_index);
                setsockopt(
                    handle,
                    IPPROTO_IP as i32,
                    IP_UNICAST_IF as i32,
                    &if_index as *const _ as PCSTR,
                    mem::size_of_val(&if_index) as i32,
                )
            } else {
                // Interface index is in host byte order for IPPROTO_IPV6.
                setsockopt(
                    handle,
                    IPPROTO_IPV6 as i32,
                    IPV6_UNICAST_IF as i32,
                    &if_index as *const _ as PCSTR,
                    mem::size_of_val(&if_index) as i32,
                )
            };

            if ret == SOCKET_ERROR {
                let err = io::Error::from_raw_os_error(WSAGetLastError());
                error!(
                    "set IP_UNICAST_IF / IPV6_UNICAST_IF interface: {}, index: {}, error: {}",
                    iface, if_index, err
                );
                return Err(err);
            }
        }

        Ok(())
    }
}

pub fn apply_tcp_options(s: TcpStream) -> std::io::Result<TcpStream> {
    #[cfg(not(target_os = "windows"))]
    {
        let s = socket2::Socket::from(s.into_std()?);
        s.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1))
                .with_retries(3),
        )?;
        TcpStream::from_std(s.into())
    }
    #[cfg(target_os = "windows")]
    {
        let s = socket2::Socket::from(s.into_std()?);
        s.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1)),
        )?;
        TcpStream::from_std(s.into())
    }
}

#[allow(unreachable_code)]
pub fn if_nametoindex(name: &str) -> u32 {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    {
        let c_str = std::ffi::CString::new(name).unwrap();
        // Safety: This function is unsafe because it deals with raw pointers and can cause undefined behavior if used incorrectly.
        return unsafe {
            if libc::if_nametoindex(c_str.as_ptr()) == 0 {
                warn!("No interface found for name {}", name);
                0
            } else {
                libc::if_nametoindex(c_str.as_ptr())
            }
        };
    }

    #[cfg(target_os = "windows")]
    {
        return win_net::find_adapter_interface_index(false, name)
            .unwrap_or_default()
            .unwrap_or(0);
    }
    return 0;
}

#[allow(unreachable_code)]
pub fn if_indextoname(ifindex: u32) -> Option<String> {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    {
        let mut buf = [0u8; libc::IFNAMSIZ]; // IFNAMSIZ is typically used to define the buffer size

        // Safety: This function is unsafe because it deals with raw pointers and can cause undefined behavior if used incorrectly.
        return unsafe {
            if libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char).is_null() {
                warn!("No interface found for index {}", ifindex);
                None
            } else {
                let c_str = std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char);
                let str_slice = c_str.to_str().unwrap();
                debug!("default Interface name: {}", str_slice);
                Some(str_slice.to_owned())
            }
        };
    }
    #[cfg(target_os = "windows")]
    {
        let adapters = ipconfig::get_adapters().unwrap();
        let adapter = adapters.iter().find(|a| a.ipv4_if_index() == ifindex);
        return adapter.map(|a| a.friendly_name().to_string());
    }
    None
}

#[allow(unreachable_code)]
pub fn get_default_if_name() -> Option<String> {
    let ifindex = dbg!(DEFAULT_IF_INDEX.load(std::sync::atomic::Ordering::SeqCst));
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    {
        let mut buf = [0u8; libc::IFNAMSIZ]; // IFNAMSIZ is typically used to define the buffer size

        // Safety: This function is unsafe because it deals with raw pointers and can cause undefined behavior if used incorrectly.
        return unsafe {
            if libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char).is_null() {
                warn!("No interface found for index {}", ifindex);
                None
            } else {
                let c_str = std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char);
                let str_slice = c_str.to_str().unwrap();
                debug!("default Interface name: {}", str_slice);
                Some(str_slice.to_owned())
            }
        };
    }
    #[cfg(target_os = "windows")]
    {
        let adapters = ipconfig::get_adapters().unwrap();
        let adapter = adapters.iter().find(|a| a.ipv4_if_index() == ifindex);
        return adapter.map(|a| a.friendly_name().to_string());
    }
    None
}

#[allow(warnings)]
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[tokio::test]
    #[ignore = "not a real test"]
    async fn test_connect_tcp() {
        let if_index = win_net::find_adapter_interface_index(false, "wlo1").unwrap();
        assert!(if_index.is_some());
    }

    /**
    *
    *  Adapter { adapter_name: "{00000000-0000-01ED-48AF-665DBC8B1241}", ipv4_if_index: 25, ip_addresses: [fe80::8489:f5c9:237b:912b, 10.10.2.1], prefixes: [(fe80::, 64), (fe80::8489:f5c9:237b:912b, 128), (ff00::, 8), (0.0.0.0, 0), (10.10.2.0, 24), (10.10.2.1, 32), (10.10.2.255, 32), (224.0.0.0, 4), (255.255.255.255, 32)], gateways: [0.0.0.0], dns_servers: [fec0:0:0:ffff::1, fec0:0:0:ffff::2, fec0:0:0:ffff::3], description: "utun64 Tunnel", friendly_name: "utun64", physical_address: None, receive_link_speed: 100000000000, transmit_link_speed: 100000000000, oper_status: IfOperStatusUp, if_type: Unsupported, ipv6_if_index: 25, ipv4_metric: 5, ipv6_metric: 5 }
       Adapter { adapter_name: "{8D217AD1-0CDB-4DDF-9801-A68AA5371984}", ipv4_if_index: 9, ip_addresses: [192.168.213.132], prefixes: [(192.168.213.0, 24), (192.168.213.132, 32), (192.168.213.255, 32), (224.0.0.0, 4), (255.255.255.255, 32)], gateways: [192.168.213.2], dns_servers: [192.168.213.2], description: "Intel(R) 82574L Gigabit Network Connection", friendly_name: "wlo1", physical_address: Some([0, 12, 41, 28, 52, 201]), receive_link_speed: 1000000000, transmit_link_speed: 1000000000, oper_status: IfOperStatusUp, if_type: EthernetCsmacd, ipv6_if_index: 0, ipv4_metric: 25, ipv6_metric: 0 }
       Adapter { adapter_name: "{6F07BA5E-F95F-11EE-8736-806E6F6E6963}", ipv4_if_index: 1, ip_addresses: [::1, 127.0.0.1], prefixes: [(::1, 128), (ff00::, 8), (127.0.0.0, 8), (127.0.0.1, 32), (127.255.255.255, 32), (224.0.0.0, 4), (255.255.255.255, 32)], gateways: [], dns_servers: [fec0:0:0:ffff::1, fec0:0:0:ffff::2, fec0:0:0:ffff::3], description: "Software Loopback Interface 1", friendly_name: "Loopback Pseudo-Interface 1", physical_address: None, receive_link_speed: 1073741824, transmit_link_speed: 1073741824, oper_status: IfOperStatusUp, if_type: SoftwareLoopback, ipv6_if_index: 1, ipv4_metric: 75, ipv6_metric: 75 }
    *
    *
    *  Adapter { adapter_name: "{8596E604-240E-49D9-354C-49E37C906AE8}", ipv4_if_index: 12, ip_addresses: [fe80::df3e:1aa8:b0c8:e819, 198.18.0.1], prefixes: [(fe80::, 64), (fe80::df3e:1aa8:b0c8:e819, 128), (ff00::, 8), (198.18.0.0, 30), (198.18.0.1, 32), (198.18.0.3, 32), (224.0.0.0, 4), (255.255.255.255, 32)], gateways: [], dns_servers: [198.18.0.2], description: "Meta Tunnel", friendly_name: "verge", physical_address: None, receive_link_speed: 100000000000, transmit_link_speed: 100000000000, oper_status: IfOperStatusUp, if_type: Unsupported, ipv6_if_index: 12, ipv4_metric: 5, ipv6_metric: 5 }
    */

    #[cfg(target_os = "windows")]
    #[tokio::test]
    #[ignore = "not a real test"]
    async fn test_list() {
        let adapters = ipconfig::get_adapters().unwrap();
        for adapter in adapters {
            println!("{:?}", adapter);
        }
    }
}
