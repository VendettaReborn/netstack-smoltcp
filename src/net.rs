use std::time::Duration;

use socket2::TcpKeepalive;
use tokio::net::TcpStream;
#[allow(unused)]
use tracing::{debug, warn};

use crate::utils::DEFAULT_IF_INDEX;

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
        return ipconfig2::if_nametoindex(false, name)
            .unwrap_or_default()
            .unwrap_or_default();
    }
    0
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
        let adapters = ipconfig2::get_adapters().unwrap();
        let adapter = adapters.iter().find(|a| a.ipv4_if_index == ifindex);
        return adapter.map(|a| a.friendly_name.clone());
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
        let adapters = ipconfig2::get_adapters().unwrap();
        let adapter = adapters.iter().find(|a| a.ipv4_if_index == ifindex);
        return adapter.map(|a| a.friendly_name.clone());
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
        let if_index = ipconfig2::if_nametoindex(false, "wlo1").unwrap();
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
        let adapters = ipconfig2::get_adapters().unwrap();
        for adapter in adapters {
            println!("{:?}", adapter);
        }
    }
}
