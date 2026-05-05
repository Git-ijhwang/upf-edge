#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    // maps::xdp,
    programs::XdpContext
};
use aya_log_ebpf::info;

mod gtpu;
use gtpu::*;


#[inline(always)]
unsafe fn ptr_at<T> (ctx: &XdpContext, offset: usize)
    -> Option<*const T>
{
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}


#[xdp]
pub fn upf_edge(ctx: XdpContext) -> u32 {
    match try_upf_edge(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_upf_edge(ctx: &XdpContext) -> Result<u32, ()> {
    // 1. Ethernet Header Check (EtherType = IPv4)
    let eth_type = unsafe {
        match ptr_at::<u16>(ctx, 12) { //Ethernet Type Offset
            Some(p) => u16::from_be(*p),
            None => {
                info!(ctx, "ethernet");
                return Ok(xdp_action::XDP_PASS);
            },
        }
    };
    if eth_type != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip_proto = unsafe {
        match ptr_at::<u8>(ctx, ETH_HDR_LEN + 9) {
            Some(p) => *p,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };
    if ip_proto != 17 {
        info!(ctx, "Not IP Proto: {}", ip_proto);
        return Ok(xdp_action::XDP_PASS);
    }
    // 3. UDP Destination Port Check (2152 = GTP-U)
    let udp_dst = unsafe {
        match ptr_at::<u16>(ctx, ETH_HDR_LEN + IP_HDR_LEN + 2) {
            Some(p) => u16::from_be(*p),
            None => {
                info!(ctx, "Udp Proto");
                return Ok(xdp_action::XDP_PASS);
            }
        }
    };
    if udp_dst != 2152 {
        info!(ctx, "Not 2152 port {}", udp_dst);
        return Ok(xdp_action::XDP_PASS);
    }

    // 4. GTP-U Header Parsing
    let gtpu = unsafe {
        match ptr_at::<GtpuHdr>(ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN) {
            Some(p) => *p,
            None => {
                info!(ctx, "GTP U Proto");
                return Ok(xdp_action::XDP_PASS);
            }
        }
    };
    // 5. G-PDU Procesing
    if gtpu.msg_type != GTPU_GPDU {
        info!(ctx, "Not GPDU");
        return Ok(xdp_action::XDP_PASS);
    }

    let teid = u32::from_be(gtpu.teid);

    info!(ctx, "GTP-U packet: TEID={}", teid);

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
