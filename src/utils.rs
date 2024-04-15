use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    sync::atomic::AtomicU32,
};

use futures::StreamExt;
use net_route::{Handle, Route};
use tracing::{debug, warn};

#[derive(Clone, Debug, Default)]
pub struct Opt {
    addrs: Vec<(IpAddr, u8)>,
    #[cfg(target_os = "linux")]
    pub table: u32,
}

// eq: from all lookup `opt.table`
#[cfg(target_os = "linux")]
pub async fn add_rules(opt: &Opt) -> io::Result<()> {
    let handle = Handle::new()?;

    // will lookup the table main fristly, and ignore the default route(with prefix of 0) in it
    let mut rule1 = net_route::Rule::default();
    rule1.suppress_prefixlength = Some(0);
    rule1.table_id = Some(254);
    rule1.priority = Some(7000);

    // will lookup the route table, which has only one route to the tun device
    let mut rule2 = net_route::Rule::default();
    rule2.table_id = Some(opt.table);
    rule2.priority = Some(7001);

    handle.add_rules(vec![rule1, rule2]).await
}

#[allow(unreachable_code, unused_variables)]
pub fn build_routes(gateway: IpAddr, opt: &Opt) -> Vec<Route> {
    if !opt.addrs.is_empty() {
        return opt
            .addrs
            .iter()
            .cloned()
            .map(|(dst, prefix)| Route::new(dst, prefix))
            .collect::<Vec<_>>();
    }

    #[cfg(target_os = "macos")]
    {
        return [
            Route::new("1.0.0.0".parse().unwrap(), 8).with_gateway(gateway),
            Route::new("2.0.0.0".parse().unwrap(), 7).with_gateway(gateway),
            Route::new("4.0.0.0".parse().unwrap(), 6).with_gateway(gateway),
            Route::new("8.0.0.0".parse().unwrap(), 5).with_gateway(gateway),
            Route::new("16.0.0.0".parse().unwrap(), 4).with_gateway(gateway),
            Route::new("32.0.0.0".parse().unwrap(), 3).with_gateway(gateway),
            Route::new("64.0.0.0".parse().unwrap(), 2).with_gateway(gateway),
            Route::new("128.0.0.0".parse().unwrap(), 1).with_gateway(gateway),
        ]
        .into();
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let if_index = get_if_index("utun20");
        println!("if index of utun20: {}", if_index);
        return [
            Route::new(Ipv4Addr::UNSPECIFIED.into(), 0)
                .with_ifindex(if_index)
                .with_table(opt.table),
            // Route::new("128.0.0.0".parse().unwrap(), 1)
            //     .with_ifindex(if_index)
            //     .with_table(opt.table),
        ]
        .into();
    }

    return [
        Route::new(Ipv4Addr::UNSPECIFIED.into(), 1).with_gateway(gateway),
        Route::new("128.0.0.0".parse().unwrap(), 1).with_gateway(gateway),
    ]
    .into();
}

pub async fn add_route(gateway: IpAddr, opt: &Opt) -> io::Result<()> {
    let handle = Handle::new()?;
    let routes = build_routes(gateway, opt);

    for route in routes {
        const MAX_RETRY: usize = 3;
        for _ in 0..MAX_RETRY {
            if let Err(e) = handle.add(&route).await {
                warn!("Failed to add route: {:?}, err: {:?}", route, e);
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    // ignore the error in delete
                    let _ = handle.delete(&route).await;
                }
            } else {
                debug!("add route success: {:?},", route);
                break;
            }
        }
    }

    Ok(())
}

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

pub fn get_if_index(name: &str) -> u32 {
    let c_str = std::ffi::CString::new(name).unwrap();
    // Safety: This function is unsafe because it deals with raw pointers and can cause undefined behavior if used incorrectly.
    unsafe {
        if libc::if_nametoindex(c_str.as_ptr()) == 0 {
            warn!("No interface found for name {}", name);
            0
        } else {
            libc::if_nametoindex(c_str.as_ptr())
        }
    }
}

pub fn get_default_if_name() -> Option<String> {
    let ifindex = DEFAULT_IF_INDEX.load(std::sync::atomic::Ordering::SeqCst);
    let mut buf = [0u8; libc::IFNAMSIZ]; // IFNAMSIZ is typically used to define the buffer size

    // Safety: This function is unsafe because it deals with raw pointers and can cause undefined behavior if used incorrectly.
    unsafe {
        if libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char).is_null() {
            warn!("No interface found for index {}", ifindex);
            None
        } else {
            let c_str = std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char);
            let str_slice = c_str.to_str().unwrap();
            debug!("default Interface name: {}", str_slice);
            Some(str_slice.to_owned())
        }
    }
}

#[tokio::test]
async fn t1() -> io::Result<()> {
    let handle = Handle::new()?;

    init_default_interface(handle, None).await?;
    let if_name = get_default_if_name();
    println!("default if name: {:?}", if_name);
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn t2() -> io::Result<()> {
    add_rules(&Opt {
        table: 1989,
        ..Default::default()
    })
    .await?;

    // println!("default if name: {:?}",);
    Ok(())
}
