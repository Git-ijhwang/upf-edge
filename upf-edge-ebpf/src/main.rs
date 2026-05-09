#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{
        xdp,
        map,
    },
    maps::HashMap,
    programs::XdpContext,
    helpers::bpf_xdp_adjust_head,
};
use aya_log_ebpf::info;
use upf_edge_common::{SessionInfo, SessionKey};

mod gtpu;
use gtpu::*;

#[map]
static SESSION_MAP: HashMap<SessionKey, SessionInfo> = HashMap::with_max_entries(1024, 0);

#[map]
static IF_INDEX: aya_ebpf::maps::Array<u32> = aya_ebpf::maps::Array::with_max_entries(2, 0);

#[map]
static GW_MAC: aya_ebpf::maps::Array<upf_edge_common::MacAddr> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);


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

#[inline(always)]
unsafe fn ptr_at_mut<T> (ctx: &XdpContext, offset: usize)
    -> Option<*mut T>
{
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *mut T)
}

#[xdp]
pub fn upf_edge_n3(ctx: XdpContext) -> u32
{
    match try_upf_edge(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[xdp]
pub fn upf_edge_n6(ctx: XdpContext) -> u32
{
    match try_encap(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
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

    // 2. IP Proto == UDP
    let ip_proto = unsafe {
        match ptr_at::<u8>(ctx, ETH_HDR_LEN + 9) {
            Some(p) => *p,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };
    if ip_proto != 17 {
        if ip_proto != 6 {
            info!(ctx, "Not IP Proto: {}", ip_proto);
        }
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
    if gtpu.msg_type != GTPU_GPDU {
        info!(ctx, "Not GPDU");
        return Ok(xdp_action::XDP_PASS);
    }

    // GTP-U 확인 후, src IP 필터 추가
    // Uplink만 처리: src = gNB IP (172.22.0.23)
    let src_ip = unsafe {
        match ptr_at::<u32>(ctx, ETH_HDR_LEN + 12) {
            Some(p) => u32::from_be(*p),
            None => return Ok(xdp_action::XDP_PASS),
        }
    };


    let teid = u32::from_be(gtpu.teid);
    info!(ctx, "GTP-U packet: TEID={}", teid);

    // 172.22.0.23 = 0xac160017
    if src_ip != 0xac160017 {
        return Ok(xdp_action::XDP_PASS);  // Downlink는 건드리지 않음
    }

    // 5. Optional Field Calc
    let opt_len = if gtpu.flags & (GTPU_FLAG_S | GTPU_FLAG_E | GTPU_FLAG_PN) != 0 {
        GTPU_OPT_LEN
    }
    else {
        0
    };

    let dst_mac = unsafe {
        match GW_MAC.get(0) {
            Some(m) => m.addr,
            None => [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        }
    };

    // 6. external ETH mac address save
    let eth_dst = unsafe {
        match ptr_at::<[u8; 6]>(ctx, 0) {
            Some(p) => core::ptr::read_unaligned(p),
            None => return Ok(xdp_action::XDP_PASS),
        }
    };
    let eth_src = unsafe {
        match ptr_at::<[u8; 6]>(ctx, 6) {
            Some(p) => core::ptr::read_unaligned(p),
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 7. Decapsulation
    let full_outer = (ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + GTPU_HDR_LEN + opt_len) as i32;

    if unsafe { bpf_xdp_adjust_head (ctx.ctx, full_outer) } != 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    if unsafe { bpf_xdp_adjust_head (ctx.ctx, -(ETH_HDR_LEN as i32)) } != 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Pointer re-verify
    let new_start = ctx.data();
    let new_end = ctx.data_end();
    if new_start + ETH_HDR_LEN > new_end {
        return Ok(xdp_action::XDP_PASS);
    }

    unsafe {
        // core::ptr::write_unaligned((new_start) as *mut [u8; 6], eth_src);
        core::ptr::write_unaligned((new_start) as *mut [u8; 6], dst_mac);
        core::ptr::write_unaligned((new_start + 6) as *mut [u8; 6], eth_dst);
        core::ptr::write_unaligned((new_start + 12) as *mut u16, 0x0008u16);
    }

    info!(ctx, "Decapsulated.");
    return Ok(xdp_action::XDP_PASS);

    // 이하 코드는 무효???
    /*
    let ifindex = unsafe {
        match IF_INDEX.get(0) {
            Some(v) => *v,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };
    info!(ctx, "Redirecting to ifindex={}", ifindex);  // 추가


    if ifindex == 0 {
        info!(ctx, "ifindex is 0, passing");  // 추가
        return Ok(xdp_action::XDP_PASS);
    }

    let ret = unsafe { aya_ebpf::helpers::bpf_redirect(ifindex, 0) } as u32;
    info!(ctx, "bpf_redirect returned={}", ret);  // 추가
    Ok(ret)
*/
}

fn try_encap(ctx: &XdpContext) -> Result<u32, ()> 
{
    // 1. Check the EtherType is IPv4
    let eth_type = unsafe {
        match ptr_at::<u16>(ctx, 12) {
            Some(p) => u16::from_be(*p),
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    if eth_type != 0x0800 {
            return Ok(xdp_action::XDP_PASS);
    }

    // 2. Read Destination address of IP header
    let dst_ip = unsafe {
        match ptr_at::<u32>(ctx, ETH_HDR_LEN + 16) {
            Some(p) => *p, //Big-Endian type
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 3. Find the Session with key
    let key = SessionKey{ue_ip: dst_ip};
    let session = unsafe {
        match SESSION_MAP.get(&key) {
            Some(s) => *s,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 4. Get Eth src and dst address from eth header
    let eth_src = unsafe {
        match ptr_at::<[u8; 6]>(ctx, 6) {
            Some(p) => core::ptr::read_unaligned(p),
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    let eth_dst = unsafe {
        match ptr_at::<[u8; 6]>(ctx, 0) {
            Some(p) => core::ptr::read_unaligned(p),
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 5. Get IP Total length
    let inner_ip_tot_len = unsafe {
        match ptr_at::<u16>(ctx, ETH_HDR_LEN + 2) {
            Some(p) => u16::from_be(*p),
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 6. Make Outer Header space
    // Eth(14) + IP(20) + UDP(8) + GTP(8) = 50
    // [                      ][Originial IP packet]
    // ^ <----------------------^
    let add_len = (ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + GTPU_HDR_LEN) as i32;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -add_len)} != 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // 7. Re-verify Pointer
    let data = ctx.data();
    let data_end = ctx.data_end();
    let total_hdr = add_len as usize;
    if data + total_hdr > data_end {
        return Ok(xdp_action::XDP_PASS);
    }




    let eth = EthHdr {
        dst: eth_src,
        src: eth_dst,
        eth_type: 0x0008u16,
    };

    // 8. Make Ethernet Header
    // [                     ][GTP][Originial IP packet]
    //  ^
    //  |
    // data
    unsafe {
    /*
        core::ptr::write_unaligned((data) as *mut [u8; 6], eth_src);
        core::ptr::write_unaligned((data + 6) as *mut [u8; 6], eth_dst);
        core::ptr::write_unaligned((data + 12) as *mut u16, 0x0008u16);
    */
        core::ptr::write_unaligned(
            (data) as *mut EthHdr,
            eth);
    }

    // 9. Outer IP Header
    // [Ethernet][          ][GTP][Originial IP packet]
    //  ^         |
    //  ----------+
    //            data
    let outer_ip_len = (IP_HDR_LEN + UDP_HDR_LEN + GTPU_HDR_LEN) as u16 + inner_ip_tot_len;
    let ip = IpHdr {
        version_ihl: 0x45,
        tos: 0,
        tot_len: outer_ip_len.to_be(),
        id: 0,
        frag_off: 0,
        ttl: 64,
        protocol: 17, // UDP
        check: 0,     // 나중에 계산
        saddr: session.upf_ip,
        daddr: session.gnb_ip,
    };
    let check = ip_checksum(&ip);
    let mut ip = ip;
    ip.check = check;

    unsafe {
        core::ptr::write_unaligned(
            (data + ETH_HDR_LEN) as *mut IpHdr,
            ip,
        );
    }
    // 10. UDP Header
    // [Ethernet][IP][UDP][GTP]
    //            ^-->^
    //                |
    //                data
    let udp_len = (UDP_HDR_LEN + GTPU_HDR_LEN) as u16 + inner_ip_tot_len;
    let udp = UdpHdr {
        source: 2152u16.to_be(),
        dest: 2152u16.to_be(),
        len: udp_len.to_be(),
        check: 0, //<- UDP checksum 
    };
    unsafe {
        core::ptr::write_unaligned(
            (data + ETH_HDR_LEN + IP_HDR_LEN) as *mut UdpHdr, 
            udp);
    }

    // 11. GTP-U Header
    // [Ethernet][IP][UDP][GTP]
    //                    ^
    let gtp_len  = inner_ip_tot_len;
    let gtpu = GtpuHdr {
        flags: 0x30, //version 1, PT=1, E=0, S=0, PN=0
        msg_type: GTPU_GPDU,
        length: gtp_len.to_be(),
        teid: session.teid,
    };
    unsafe {
        core::ptr::write_unaligned(
            (data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN) as *mut GtpuHdr, 
            gtpu);
    }

    // Done.
    info!(ctx, "Encapsulated: TEID={}", u32::from_be(session.teid));

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
