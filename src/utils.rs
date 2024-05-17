use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::AtomicU32,
};

use futures::StreamExt;
use net_route::{Handle, Route};

pub static DEFAULT_IF_INDEX: AtomicU32 = AtomicU32::new(0);

// #[cfg(not(target_os = "linux"))]
async fn get_default_interface_exclude_self(
    handle: &Handle,
    this: Option<u32>,
) -> io::Result<Option<Route>> {
    for route in handle.list().await? {
        if (route.destination == Ipv4Addr::UNSPECIFIED
            || route.destination == std::net::Ipv6Addr::UNSPECIFIED)
            && route.prefix == 0
            && route.gateway != Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            && route.gateway != Some(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))
            && (this.is_none() || route.ifindex != this)
        {
            return Ok(Some(route));
        }
    }
    Ok(None)
}

// this_if: the interface index of the current tun interface, which should be excluded
pub async fn init_default_interface(handle: Handle, this_if: Option<u32>) -> io::Result<()> {
    let default_if = get_default_interface_exclude_self(&handle, this_if).await?;
    if let Some(default_if) = default_if {
        DEFAULT_IF_INDEX.store(
            default_if.ifindex.unwrap_or_default(),
            std::sync::atomic::Ordering::SeqCst,
        );
        Ok(())
    } else {
        Err(std::io::Error::other("no default interface"))
    }
}

pub async fn monitor_default_interface(handle: Handle, this_if: Option<u32>) -> io::Result<()> {
    let stream = handle.route_listen_stream();
    futures::pin_mut!(stream);

    println!("Listening for route events, press Ctrl+C to cancel...");
    while let Some(event) = stream.next().await {
        println!("event:{:?}", event);
        if let Some(route) = get_default_interface_exclude_self(&handle, this_if).await? {
            println!("Default route:\n{:?}", route);
            DEFAULT_IF_INDEX.store(
                route.ifindex.unwrap_or_default(),
                std::sync::atomic::Ordering::SeqCst,
            );
        } else {
            println!("No default route found!");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub async fn add_ipv6_addr(index: u32, ip: Ipv6Addr, prefix: u8) {
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    handle
        .address()
        .add(index, IpAddr::V6(ip), prefix)
        .execute()
        .await
        .unwrap()
}

#[cfg(target_os = "macos")]
pub async fn add_ipv6_addr(name: &str, ip: Ipv6Addr, prefix: u8) {
    ipv6_addr::add_ipv6_addr(name, ip, prefix).unwrap();
}

#[cfg(target_os = "macos")]
mod ipv6_addr {
    use std::{mem, net::Ipv6Addr};

    use libc::{c_char, c_int, in6_addr, sockaddr_in6, time_t, AF_INET6, IFNAMSIZ, SOCK_DGRAM};

    #[allow(non_camel_case_types)]
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct in6_aliasreq {
        pub name: [c_char; IFNAMSIZ],
        pub addr: sockaddr_in6,
        pub dstaddr: sockaddr_in6,
        pub prefixmask: sockaddr_in6,
        pub flags: c_int,
        pub lifetime: in6_addrlifetime,
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct in6_addrlifetime {
        pub ia6t_expire: time_t,
        pub ia6t_preferred: time_t,
        pub ia6t_vltime: u32,
        pub ia6t_pltime: u32,
    }

    /// A wrapper for `sockaddr_in6`.
    #[derive(Copy, Clone)]
    pub struct SockAddrV6(sockaddr_in6);

    impl SockAddrV6 {
        /// Create a new `SockAddrV6` from a generic `sockaddr`.
        pub fn new(value: &sockaddr_in6) -> std::io::Result<Self> {
            if value.sin6_family != libc::AF_INET6 as libc::sa_family_t {
                return std::io::Result::Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid address family",
                ));
            }

            unsafe { Self::unchecked(value) }
        }

        /// # Safety
        ///  Create a new `SockAddrV6` and not check the source.
        pub unsafe fn unchecked(value: &sockaddr_in6) -> std::io::Result<Self> {
            Ok(SockAddrV6(std::ptr::read(value as *const _ as *const _)))
        }
    }

    impl From<Ipv6Addr> for SockAddrV6 {
        fn from(ip: Ipv6Addr) -> SockAddrV6 {
            let mut addr = unsafe { mem::zeroed::<sockaddr_in6>() };
            let addr_family = if ip.is_unspecified() {
                libc::AF_UNSPEC
            } else {
                libc::AF_INET6
            };

            // macos: ioctl does not accept sockaddr_in6 without sin6_len set.
            addr.sin6_len = mem::size_of::<sockaddr_in6>() as u8;
            addr.sin6_family = addr_family as libc::sa_family_t;
            addr.sin6_port = 0;
            addr.sin6_addr = in6_addr {
                s6_addr: ip.octets(),
            };

            SockAddrV6(addr)
        }
    }

    impl From<SockAddrV6> for Ipv6Addr {
        fn from(addr: SockAddrV6) -> Ipv6Addr {
            Ipv6Addr::from(addr.0.sin6_addr.s6_addr)
        }
    }

    impl From<SockAddrV6> for sockaddr_in6 {
        fn from(addr: SockAddrV6) -> sockaddr_in6 {
            addr.0
        }
    }

    ioctl::ioctl!(write siocaifaddr_in6 with 'i', 26; in6_aliasreq);

    pub fn add_ipv6_addr(name: &str, addr: Ipv6Addr, prefix_len: u8) -> std::io::Result<()> {
        let addr = ipnet::Ipv6Net::new(addr, prefix_len).unwrap();
        let mask = addr.netmask();
        let addr = addr.addr();

        let ctl_inet6 = unsafe { libc::socket(AF_INET6, SOCK_DGRAM, 0) };
        unsafe {
            let mut req: in6_aliasreq = mem::zeroed();
            std::ptr::copy_nonoverlapping(
                name.as_ptr() as *const c_char,
                req.name.as_mut_ptr(),
                name.len(),
            );
            req.addr = SockAddrV6::from(addr).into();
            req.prefixmask = SockAddrV6::from(mask).into();
            req.lifetime.ia6t_pltime = u32::MAX;
            req.lifetime.ia6t_vltime = u32::MAX;

            if siocaifaddr_in6(ctl_inet6, &req) < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            Ok(())
        }
    }
}

#[tokio::test]
async fn test_default_if() -> io::Result<()> {
    let handle = Handle::new()?;

    init_default_interface(handle, None).await?;
    let if_name = crate::net::get_default_if_name();
    println!("default if name: {:?}", if_name);
    let if_index = crate::net::get_if_index(if_name.as_ref().map(|x| x.as_str()).unwrap_or(""));
    // let if_index = crate::net::get_if_index("ethernet_32769");
    println!("default if index: {:?}", if_index);
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_rules() -> io::Result<()> {
    let mut rule1 = net_route::Rule::default();
    rule1.suppress_prefixlength = Some(0);
    rule1.table_id = Some(254);
    rule1.priority = Some(7000);

    // will lookup the route table, which has only one route to the tun device
    let mut rule2 = net_route::Rule::default();
    rule2.table_id = Some(1989);
    // rule2.dst = Some((
    //     "1.0.0.1"
    //         .parse::<Ipv4Addr>()
    //         .unwrap()
    //         .into(),
    //     32,
    // ));
    rule2.priority = Some(7000);

    let mut rule3 = net_route::Rule::default();
    rule3.suppress_prefixlength = Some(0);
    rule3.table_id = Some(254);
    rule3.priority = Some(7000);
    rule3.v6 = true;

    // will lookup the route table, which has only one route to the tun device
    let mut rule4 = net_route::Rule::default();
    rule4.table_id = Some(1989);
    rule4.priority = Some(7000);
    // rule4.dst = Some((
    //     "2603:c024:f:17e:ab4e:5672:fe71:2dd7"
    //         .parse::<Ipv6Addr>()
    //         .unwrap()
    //         .into(),
    //     128,
    // ));
    rule4.v6 = true;

    let handle = Handle::new()?;
    handle
        .delete_rules(vec![rule1, rule2, rule3, rule4])
        .await?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_list_routes() -> io::Result<()> {
    let handle = Handle::new()?;
    let routes = handle.list_rules().await?;
    for route in routes {
        println!("{:?}", route);
    }
    Ok(())
}

#[tokio::test]
async fn test_clear() -> io::Result<()> {
    let handle = Handle::new().unwrap();

    let opt = watfaq_tun::Opt {
        #[cfg(target_os = "linux")]
        table: 1989,
        preset: vec![],
        if_index: 1,
        gateway_ipv4: Some("10.10.2.1".parse().unwrap()),
        gateway_ipv6: Some("2:2:1:1443::400".parse().unwrap()),
    };
    let routes = watfaq_tun::platform::build_routes(&opt);
    assert_eq!(routes.len(), 16);

    for route in routes {
        let _ = handle.delete(&route).await;
    }
    Ok(())
}
