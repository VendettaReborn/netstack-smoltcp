use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::AtomicU32,
};

use futures::StreamExt;
use net_route::{Handle, Route};
use tracing::{debug, warn};

#[derive(Clone, Debug)]
pub struct Opt {
    addrs: Vec<(IpAddr, u8)>,
    #[cfg(target_os = "linux")]
    pub table: u32,
    #[cfg(target_os = "windows")]
    pub luid: Option<u64>,
    pub if_index: u32,
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
    rule2.dst = Some(("1.0.0.1".parse::<Ipv4Addr>().unwrap().into(), 32));
    rule2.priority = Some(7001);

    let mut rule3 = net_route::Rule::default();
    rule3.suppress_prefixlength = Some(0);
    rule3.table_id = Some(254);
    rule3.priority = Some(7000);
    rule3.v6 = true;

    // will lookup the route table, which has only one route to the tun device
    let mut rule4 = net_route::Rule::default();
    rule4.table_id = Some(opt.table);
    rule4.priority = Some(7001);
    rule4.dst = Some((
        "2603:c024:f:17e:ab4e:5672:fe71:2dd7"
            .parse::<Ipv6Addr>()
            .unwrap()
            .into(),
        128,
    ));
    rule4.v6 = true;

    let rules = vec![rule1, rule2, rule3, rule4];

    // rule2.dst = Some(("1.0.0.1".parse().unwrap(), 53));

    // clear before add
    let _ = handle.delete_rules(rules.clone()).await;
    handle.add_rules(rules).await
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
        return [
            Route::new(Ipv4Addr::UNSPECIFIED.into(), 0)
                .with_ifindex(opt.if_index)
                .with_table(opt.table),
            Route::new(Ipv6Addr::UNSPECIFIED.into(), 0)
                .with_ifindex(opt.if_index)
                .with_table(opt.table),
            // Route::new("128.0.0.0".parse().unwrap(), 1)
            //     .with_ifindex(if_index)
            //     .with_table(opt.table),
        ]
        .into();
    }

    #[cfg(target_os = "windows")]
    {
        let mut r1 = Route::new(Ipv4Addr::UNSPECIFIED.into(), 1)
            .with_gateway(gateway)
            .with_metric(0);
        if let Some(luid) = opt.luid {
            r1 = r1.with_luid(luid);
        }
        if let Some(if_index) = opt.if_index {
            r1 = r1.with_ifindex(if_index);
        }

        return vec![r1];
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
        println!("adding route:{:?},", route);
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

#[tokio::test]
async fn test_list_routes() -> io::Result<()> {
    let handle = Handle::new()?;
    let routes = handle.list_rules().await?;
    for route in routes {
        println!("{:?}", route);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Session {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}
