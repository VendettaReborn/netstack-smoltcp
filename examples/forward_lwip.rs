use std::net::{Ipv6Addr, SocketAddr};

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{
    net::{get_default_if_name, if_nametoindex},
    utils::init_default_interface,
};

use netstack_lwip::*;

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
    let name = "utun64";
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

    let device = tun::create_as_async(&cfg).unwrap();
    let if_index = if_nametoindex(name);

    #[cfg(target_os = "linux")]
    netstack_smoltcp::utils::add_ipv6_addr(if_index, addr_v6, 64).await;

    #[cfg(target_os = "macos")]
    netstack_smoltcp::utils::add_ipv6_addr(name, addr_v6, 64).await;

    let interface;

    #[cfg(debug_assertions)]
    {
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

    let opt: Opt;
    let table = 1989;

    #[cfg(target_os = "linux")]
    {
        opt = watfaq_tun::Opt {
            table,
            if_index: if_nametoindex(name),
            preset: vec![],
            gateway_ipv4: Some(addr.parse().unwrap()),
            gateway_ipv6: Some(addr_v6),
        };
    }

    #[cfg(target_os = "macos")]
    {
        opt = watfaq_tun::Opt {
            if_index: if_nametoindex(name),
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

    let (stack, tcp_listener, udp_socket) =
        netstack_lwip::NetStack::with_buffer_size(512, 256).unwrap();

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
        let default_if = interface.clone();
        async move {
            handle_inbound_stream(tcp_listener, default_if).await;
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
            #[cfg(target_os = "linux")]
            netstack_smoltcp::dump::resolve(local);
            match new_tcp_stream(remote, &interface).await {
                // match new_tcp_stream(remote, &interface).await {
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
async fn handle_inbound_datagram(_udp_socket: Box<UdpSocket>, _interface: String) {}

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
