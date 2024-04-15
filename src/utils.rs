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
    pub table: u8,
}

#[cfg(target_os = "linux")]
pub fn build_rules(opt: &Opt) {}

#[allow(unreachable_code)]
pub fn build_routes(gateway: IpAddr, opt: Opt) -> Vec<Route> {
    if !opt.addrs.is_empty() {
        return opt
            .addrs
            .into_iter()
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
        return [
            Route::new(Ipv4Addr::UNSPECIFIED.into(), 1)
                .with_gateway(gateway)
                .with_table(opt.table),
            Route::new("128.0.0.0".parse().unwrap(), 1)
                .with_gateway(gateway)
                .with_table(opt.table),
        ]
        .into();
    }

    return [
        Route::new(Ipv4Addr::UNSPECIFIED.into(), 1).with_gateway(gateway),
        Route::new("128.0.0.0".parse().unwrap(), 1).with_gateway(gateway),
    ]
    .into();
}

pub async fn add_route(gateway: IpAddr) -> io::Result<()> {
    let handle = Handle::new()?;
    let routes = build_routes(gateway, Opt { addrs: vec![] });

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

pub async fn init_default_interface(handle: Handle) -> io::Result<()> {
    let default_idx = handle.default_route().await?.unwrap().ifindex;
    DEFAULT_IF_INDEX.store(
        default_idx.unwrap_or_default(),
        std::sync::atomic::Ordering::SeqCst,
    );
    Ok(())
}

pub async fn monitor_default_interface(handle: Handle) -> io::Result<()> {
    let stream = handle.route_listen_stream();
    futures::pin_mut!(stream);

    println!("Listening for route events, press Ctrl+C to cancel...");
    while let Some(event) = stream.next().await {
        println!("event:{:?}", event);
        if let Some(route) = handle.default_route().await? {
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

    init_default_interface(handle).await?;
    let if_name = get_default_if_name();
    println!("default if name: {:?}", if_name);
    Ok(())
}
