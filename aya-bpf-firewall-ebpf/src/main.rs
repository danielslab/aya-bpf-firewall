#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::{xdp, map}, programs::XdpContext, maps::HashMap};
use aya_log_ebpf::info;

use core::mem;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};


#[map]
static BLOCKLIST_V4: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static BLOCKLIST_V6: HashMap<u128,u32> = HashMap::with_max_entries(1024, 0);
#[map]
static PORT_MONITOR_LIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn aya_bpf_firewall(ctx: XdpContext) -> u32 {
    match try_aya_bpf_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] // (1)
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_aya_bpf_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // (2)
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
            let destination_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr});
        
            let source_port = match unsafe { (*ipv4hdr).proto } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr =
                        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*udphdr).source })
                }
                _ => return Err(()),
            };

            let destination_port = match unsafe { (*ipv4hdr).proto } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr =
                        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*tcphdr).dest })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*udphdr).dest })
                }
                _ => return Err(()),
            };
        
            // (3)
            info!(&ctx, "SRC IP: {:i}, DST IP: {:i}, SRC PORT: {}, DST PORT: {}", source_addr, destination_addr, source_port, destination_port);



        }

        EtherType::Ipv6 => {
            let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let source_addr = unsafe { (*ipv6hdr).src_addr.in6_u.u6_addr16 };
            let destination_addr = unsafe { (*ipv6hdr).dst_addr.in6_u.u6_addr16 };

            let source_port = match unsafe { (*ipv6hdr).next_hdr } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr =
                        ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                    u16::from_be(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                    u16::from_be(unsafe { (*udphdr).source })
                }
                _ => return Err(()),
            };

            let destination_port = match unsafe { (*ipv6hdr).next_hdr } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr =
                        ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                    u16::from_be(unsafe { (*tcphdr).dest })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                    u16::from_be(unsafe { (*udphdr).dest })
                }
                _ => return Err(()),
            };

            info!(&ctx, "SRC IPv6: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}, DST IPv6: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}, SRC PORT: {}, DST PORT: {}", 
                u16::from_be(source_addr[0]), 
                u16::from_be(source_addr[1]), 
                u16::from_be(source_addr[2]), 
                u16::from_be(source_addr[3]), 
                u16::from_be(source_addr[4]), 
                u16::from_be(source_addr[5]), 
                u16::from_be(source_addr[6]), 
                u16::from_be(source_addr[7]),
                u16::from_be(destination_addr[0]),
                u16::from_be(destination_addr[1]),
                u16::from_be(destination_addr[2]),
                u16::from_be(destination_addr[3]),
                u16::from_be(destination_addr[4]),
                u16::from_be(destination_addr[5]),
                u16::from_be(destination_addr[6]),
                u16::from_be(destination_addr[7]),
                source_port,
                destination_port);
        }

        _ => return Ok(xdp_action::XDP_PASS),
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
