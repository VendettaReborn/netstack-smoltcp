use std::net::{IpAddr, SocketAddr};

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{
    utils::{add_route, add_rules, get_default_if_name, get_if_index, init_default_interface},
    StackBuilder, TcpListener, UdpSocket,
};
use structopt::StructOpt;
use tokio::net::{TcpSocket, TcpStream};
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
    cfg.layer(tun::Layer::L3);
    let fd = -1;
    let dst = "10.10.10.1";
    let addr = "10.10.10.1";
    let netmask = "255.255.255.0";
    let name = "utun20";
    if fd >= 0 {
        cfg.raw_fd(fd);
    } else {
        cfg.tun_name(name)
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

    // the tun device is not handled yet
    init_default_interface(net_route::Handle::new().unwrap(), None)
        .await
        .unwrap();
    let interface = opt.interface.unwrap_or(get_default_if_name().unwrap());
    info!(
        "using interface: {}, default if: {:?}",
        &interface,
        get_default_if_name()
    );

    let device = tun::create_as_async(&cfg).unwrap();
    let mut builder = StackBuilder::default();
    if let Some(device_broadcast) = get_device_broadcast(&device) {
        builder = builder
            // .add_ip_filter(Box::new(move |src, dst| *src != device_broadcast && *dst != device_broadcast));
            .add_ip_filter_fn(move |src, dst| *src != device_broadcast && *dst != device_broadcast);
    }

    #[cfg(debug_assertions)]
    {
        let if_index = get_if_index(name);
        // the tun device is not handled yet
        init_default_interface(net_route::Handle::new().unwrap(), Some(if_index))
            .await
            .unwrap();
        info!(
            "re detect interface: {}, default if: {:?}",
            &interface,
            get_default_if_name()
        );
    }

    let mut util_opt = netstack_smoltcp::utils::Opt::default();
    #[cfg(target_os = "linux")]
    {
        util_opt.table = 1989;
    }

    add_rules(&util_opt).await.unwrap();
    add_route(addr.parse().unwrap(), &util_opt).await.unwrap();

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
        let interface = interface.clone();
        async move {
            handle_inbound_stream(tcp_listener, interface).await;
        }
    }));

    // Receive and send UDP packets between netstack and NAT manager. The NAT
    // manager would maintain UDP sessions and send them to the dispatcher.
    futs.push(tokio_spawn!(async move {
        handle_inbound_datagram(udp_socket, interface).await;
    }));

    futures::future::join_all(futs)
        .await
        .iter()
        .for_each(|res| {
            if let Err(e) = res {
                error!("error: {:?}", e);
            }
        });
}

/// simply forward tcp stream
async fn handle_inbound_stream(mut tcp_listener: TcpListener, interface: String) {
    while let Some((mut stream, local, remote)) = tcp_listener.next().await {
        let interface = interface.clone();
        tokio::spawn(async move {
            info!("new tcp connection: {:?} => {:?}", local, remote);
            match new_tcp_stream(remote, &interface).await {
                Ok(mut remote_stream) => {
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
async fn handle_inbound_datagram(udp_socket: UdpSocket, interface: String) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let (mut read_half, mut write_half) = udp_socket.split();
    tokio::spawn(async move {
        while let Some((data, local, remote)) = rx.recv().await {
            let _ = write_half.send((data, remote, local)).await;
        }
    });

    while let Some((data, local, remote)) = read_half.next().await {
        let tx = tx.clone();
        let interface = interface.clone();
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

async fn new_tcp_stream<'a>(addr: SocketAddr, iface: &str) -> std::io::Result<TcpStream> {
    use socket2_ext::{AddressBinding, BindDeviceOption};
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    socket.bind_to_device(BindDeviceOption::v4(iface))?;
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
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    socket.bind_to_device(BindDeviceOption::v4(iface))?;
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
