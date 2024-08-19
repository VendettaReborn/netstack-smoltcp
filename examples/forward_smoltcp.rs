use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{
    net::{get_default_if_name, if_nametoindex},
    utils::init_default_interface,
    StackBuilder, TcpListener, UdpSocket,
};
use structopt::StructOpt;
use tokio::{
    net::{TcpSocket, TcpStream},
    sync::RwLock,
};
use tracing::{error, info, warn};

// to run this example, you should set the policy routing **after the start of the main program**
//
// linux:
// with bind device:
// `curl 1.1.1.1 --interface utun8`
// with default route:
// `bash scripts/route-linux.sh add`
// `curl 1.1.1.1`
// with single route:
// `ip rule add to 1.1.1.1 table 200`
// `ip route add default dev utun8 table 200`
// `curl 1.1.1.1`
//
// macos:
// with default route:
// `bash scripts/route-macos.sh add`
// `curl 1.1.1.1`
//
// windows:
// with default route:
// tun2 set default route automatically, won't set agian
// # `powershell.exe scripts/route-windows.ps1 add`
// `curl 1.1.1.1`
//
// currently, the example only supports the TCP stream, and the UDP packet will be dropped.
// and the changes of default interface will be detected and updated automatically.

static DEFAULT_IF_INDEX: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

lazy_static::lazy_static! {
    static ref DEFAULT_IF_NAME: Arc<RwLock<String>> = Arc::new(RwLock::new("".into()));
}

#[derive(Debug, StructOpt)]
#[structopt(name = "forward", about = "Simply forward tun tcp/udp traffic.")]
struct Opt {
    /// Default binding interface, default by guessed.
    /// Specify but doesn't exist, no device is bound.
    #[structopt(short = "i", long = "interface")]
    interface: Option<String>,

    /// Tracing subscriber log level.
    #[structopt(long = "log-level", default_value = "debug")]
    log_level: tracing::Level,

    /// Tokio current-thread runtime, default to multi-thread.
    #[structopt(long = "current-thread")]
    current_thread: bool,

    /// Tokio task spawn_local, default to spwan.
    #[structopt(long = "local-task")]
    local_task: bool,
}

fn main() {
    let opt = Opt::from_args();

    let rt = if opt.current_thread {
        tokio::runtime::Builder::new_current_thread()
    } else {
        tokio::runtime::Builder::new_multi_thread()
    }
    .enable_all()
    .build()
    .unwrap();

    rt.block_on(main_exec(opt));
}

async fn main_exec(opt: Opt) {
    macro_rules! tokio_spawn {
        ($fut: expr) => {
            if opt.local_task {
                tokio::task::spawn_local($fut)
            } else {
                tokio::task::spawn($fut)
            }
        };
    }

    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(opt.log_level)
            .finish(),
    )
    .unwrap();

    let mut cfg = tun::Configuration::default();
    #[cfg(target_os = "windows")]
    cfg.platform_config(|config| {
        config.device_guid(Some(9099482345783245345345_u128));
    });
    cfg.layer(tun::Layer::L3);
    let fd = -1;
    let dst = "10.10.2.1";
    let addr = "10.10.2.1";
    let addr_v6: Ipv6Addr = "2:2:1:1443:0:0:0:400".parse().unwrap();
    let netmask = "255.255.255.0";
    let tun_name = "utun64";
    if fd >= 0 {
        cfg.raw_fd(fd);
    } else {
        cfg.tun_name(tun_name)
            .address(addr)
            .destination(dst)
            .mtu(tun::DEFAULT_MTU);
        #[cfg(not(any(
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "mipsel",
            target_arch = "mipsel64",
        )))]
        {
            cfg.netmask(netmask);
        }
        cfg.up();
    }

    let device = tun::create_as_async(&cfg).unwrap();
    let mut builder = StackBuilder::default();
    if let Some(device_broadcast) = get_device_broadcast(&device) {
        builder = builder
            // .add_ip_filter(Box::new(move |src, dst| *src != device_broadcast && *dst != device_broadcast));
            .add_ip_filter_fn(move |src, dst| *src != device_broadcast && *dst != device_broadcast);
    }

    let default_if_index_opt = opt.interface.as_ref().map(|i| if_nametoindex(i));

    let interface;
    let if_index;

    #[cfg(debug_assertions)]
    {
        if_index = if_nametoindex(tun_name);
        // the tun device is not handled yet
        init_default_interface(net_route::Handle::new().unwrap(), Some(if_index))
            .await
            .unwrap();
        interface = opt.interface.unwrap_or(get_default_if_name().unwrap());
        info!(
            "re detect interface: {}, default if: {:?}",
            &interface,
            get_default_if_name()
        );
    }

    async fn update_default_if(if_index: u32) {
        tracing::info!("updating default if...");
        DEFAULT_IF_INDEX.store(if_index, std::sync::atomic::Ordering::SeqCst);
        let new_if_name = netstack_smoltcp::net::if_indextoname(if_index).unwrap();
        tracing::info!("new default if: {}", new_if_name);
        *DEFAULT_IF_NAME.write().await = new_if_name;
    }

    // ignore the close notifier
    let (default_if_index, close_sender) =
        netstack_smoltcp::utils::use_monitor_async(Some(if_index), |route| async move {
            match route.ifindex {
                Some(if_index) => update_default_if(if_index).await,
                None => {
                    tracing::warn!("no default interface index found");
                }
            }
        })
        .await
        .unwrap();

    // if there is any default interface specified or detected, use it
    // or just return, we should have a default interface to work with
    match (default_if_index_opt, default_if_index) {
        (Some(if_index), _) | (None, Some(if_index)) => {
            DEFAULT_IF_INDEX.store(if_index, std::sync::atomic::Ordering::SeqCst);
            *DEFAULT_IF_NAME.write().await =
                netstack_smoltcp::net::if_indextoname(if_index).unwrap();
        }
        (None, None) => {
            tracing::error!("failed to get default interface index");
            return;
        }
    }

    #[cfg(target_os = "linux")]
    netstack_smoltcp::utils::add_ipv6_addr(if_index, addr_v6, 64).await;

    #[cfg(target_os = "macos")]
    netstack_smoltcp::utils::add_ipv6_addr(tun_name, addr_v6, 64).await;
    let opt: Opt;
    let table = 1989;

    #[cfg(target_os = "linux")]
    {
        opt = watfaq_tun::Opt {
            table,
            if_index: if_nametoindex(tun_name),
            preset: vec![],
            gateway_ipv4: Some(addr.parse().unwrap()),
            gateway_ipv6: Some(addr_v6),
        };
    }

    #[cfg(target_os = "macos")]
    {
        opt = watfaq_tun::Opt {
            if_index: if_nametoindex(tun_name),
            preset: vec![],
            gateway_ipv4: Some(addr.parse().unwrap()),
            gateway_ipv6: Some(addr_v6),
        };
    }

    #[cfg(target_os = "linux")]
    watfaq_tun::platform::add_rules(table, true, true, true)
        .await
        .unwrap();
    // watfaq_tun::add_route(&opt).await.unwrap();

    let (runner, udp_socket, tcp_listener, stack) = builder.build();
    tokio_spawn!(runner);

    let framed = device.into_framed();
    let (mut tun_sink, mut tun_stream) = framed.split();
    let (mut stack_sink, mut stack_stream) = stack.split();

    let mut futs = vec![];

    // Reads packet from stack and sends to TUN.
    futs.push(tokio_spawn!(async move {
        while let Some(pkt) = stack_stream.next().await {
            if let Ok(pkt) = pkt {
                match tun_sink.send(pkt).await {
                    Ok(_) => {}
                    Err(e) => warn!("failed to send packet to TUN, err: {:?}", e),
                }
            }
        }
    }));

    // Reads packet from TUN and sends to stack.
    futs.push(tokio_spawn!(async move {
        while let Some(pkt) = tun_stream.next().await {
            if let Ok(pkt) = pkt {
                match stack_sink.send(pkt).await {
                    Ok(_) => {}
                    Err(e) => warn!("failed to send packet to stack, err: {:?}", e),
                };
            }
        }
    }));

    // Extracts TCP connections from stack and sends them to the dispatcher.
    futs.push(tokio_spawn!({
        async move {
            handle_inbound_stream(tcp_listener).await;
        }
    }));

    // Receive and send UDP packets between netstack and NAT manager. The NAT
    // manager would maintain UDP sessions and send them to the dispatcher.
    futs.push(tokio_spawn!(async move {
        handle_inbound_datagram(udp_socket).await;
    }));

    futures::future::join_all(futs)
        .await
        .iter()
        .for_each(|res| {
            if let Err(e) = res {
                error!("error: {:?}", e);
            }
        });
    drop(close_sender);
}

/// simply forward tcp stream
async fn handle_inbound_stream(mut tcp_listener: TcpListener) {
    while let Some((mut stream, local, remote)) = tcp_listener.next().await {
        let interface = DEFAULT_IF_NAME.read().await.clone();
        tokio::spawn(async move {
            info!("new tcp connection: {:?} => {:?}", local, remote);
            #[cfg(target_os = "linux")]
            netstack_smoltcp::dump::resolve(local);
            match new_tcp_stream(remote, &interface).await {
                // match new_tcp_stream(remote, &interface).await {
                Ok(mut remote_stream) => {
                    info!("tcp connection start copying: {:?} => {:?}", local, remote);
                    // pipe between two tcp stream
                    match tokio::io::copy_bidirectional(&mut stream, &mut remote_stream).await {
                        Ok(_) => {}
                        Err(e) => warn!(
                            "failed to copy tcp stream {:?}=>{:?}, err: {:?}",
                            local, remote, e
                        ),
                    }
                }
                Err(e) => warn!(
                    "failed to new tcp stream {:?}=>{:?}, err: {:?}",
                    local, remote, e
                ),
            }
        });
    }
}

/// simply forward udp datagram
async fn handle_inbound_datagram(udp_socket: UdpSocket) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let (mut read_half, mut write_half) = udp_socket.split();
    tokio::spawn(async move {
        while let Some((data, local, remote)) = rx.recv().await {
            let _ = write_half.send((data, remote, local)).await;
        }
    });

    while let Some((data, local, remote)) = read_half.next().await {
        let tx = tx.clone();
        let interface = DEFAULT_IF_NAME.read().await.clone();
        tokio::spawn(async move {
            info!("new udp datagram: {:?} => {:?}", local, remote);
            match new_udp_packet(remote, &interface).await {
                Ok(remote_socket) => {
                    // pipe between two udp sockets
                    let _ = remote_socket.send(&data).await;
                    loop {
                        let mut buf = vec![0; 1024];
                        match remote_socket.recv_from(&mut buf).await {
                            Ok((len, _)) => {
                                let _ = tx.send((buf[..len].to_vec(), local, remote));
                            }
                            Err(e) => {
                                warn!(
                                    "failed to recv udp datagram {:?}<->{:?}: {:?}",
                                    local, remote, e
                                );
                                break;
                            }
                        }
                    }
                }
                Err(e) => warn!(
                    "failed to new udp socket {:?}=>{:?}, err: {:?}",
                    local, remote, e
                ),
            }
        });
    }
}

#[allow(unused)]
async fn new_tcp_stream_without_bind(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    socket.set_keepalive(true)?;
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;

    let stream = TcpSocket::from_std_stream(socket.into())
        .connect(addr)
        .await?;

    Ok(stream)
}

async fn new_tcp_stream<'a>(addr: SocketAddr, iface: &str) -> std::io::Result<TcpStream> {
    use socket2_ext::{AddressBinding, BindDeviceOption};

    let socket = if addr.is_ipv4() {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        socket.bind_to_device(BindDeviceOption::v4(iface))?;
        socket
    } else {
        let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?;
        socket.bind_to_device(BindDeviceOption::v6(iface))?;
        socket
    };
    socket.set_keepalive(true)?;
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;

    let stream = TcpSocket::from_std_stream(socket.into())
        .connect(addr)
        .await?;

    Ok(stream)
}

async fn new_udp_packet(addr: SocketAddr, iface: &str) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2_ext::{AddressBinding, BindDeviceOption};

    let socket = if addr.is_ipv4() {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
        socket.bind_to_device(BindDeviceOption::v4(iface))?;
        socket
    } else {
        let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
        socket.bind_to_device(BindDeviceOption::v6(iface))?;
        socket
    };
    socket.set_nonblocking(true)?;

    let socket = tokio::net::UdpSocket::from_std(socket.into());
    if let Ok(ref socket) = socket {
        socket.connect(addr).await?;
    }
    socket
}

fn get_device_broadcast(device: &tun::AsyncDevice) -> Option<std::net::Ipv4Addr> {
    use tun::AbstractDevice;

    let mtu = device.as_ref().mtu().unwrap_or(tun::DEFAULT_MTU);

    let address = match device.as_ref().address() {
        Ok(a) => match a {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return None,
        },
        Err(_) => return None,
    };

    let netmask = match device.as_ref().netmask() {
        Ok(n) => match n {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return None,
        },
        Err(_) => return None,
    };

    match smoltcp::wire::Ipv4Cidr::from_netmask(address.into(), netmask.into()) {
        Ok(address_net) => match address_net.broadcast() {
            Some(broadcast) => {
                info!(
                    "tun device network: {} (address: {}, netmask: {}, broadcast: {}, mtu: {})",
                    address_net, address, netmask, broadcast, mtu,
                );

                Some(broadcast.into())
            }
            None => {
                error!("invalid tun address {}, netmask {}", address, netmask);
                None
            }
        },
        Err(err) => {
            error!(
                "invalid tun address {}, netmask {}, error: {}",
                address, netmask, err
            );
            None
        }
    }
}
