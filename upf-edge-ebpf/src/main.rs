#![no_std]
#![no_main]

// use core::intrinsics::offload;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{
        xdp,
        map,
    },
    maps::HashMap,
    programs::XdpContext,
    helpers::{
        bpf_xdp_adjust_head,
        bpf_redirect,
    }
};
use aya_log_ebpf::info;
use upf_edge_common::{
    SessionInfo,
    SessionKey,
    PdrKey, PdrValue,
    FarKey, FarValue,
    MacAddr,
    IFACE_ACCESS, IFACE_CORE,
    ACTION_BUFF, ACTION_DROP, ACTION_FORW,
    MAX_PDR_PER_SESSION, GTP_UDP_PORT,
};

mod gtpu;
use gtpu::*;

// ═══════════════════════════════════════════════════════════════
// eBPF Maps - userspace(pfcp server) write and XDP will read
// ═══════════════════════════════════════════════════════════════


/// UE IP -> Session Information
/// Key: SessionKey { ue_ip: u32 } 
#[map]
static SESSION_MAP: HashMap<SessionKey, SessionInfo> = HashMap::with_max_entries(1024, 0);

/// PDR ID -> Packet Detection Rule
/// Key: PdrKey { pdr_id: u32 }
#[map]
static PDR_MAP: HashMap<PdrKey, PdrValue> = HashMap::with_max_entries(4096, 0);

/// FAR ID -> Forwarding Action Rule
/// Key: FarKey { far_id: u32 }
#[map]
static FAR_MAP: HashMap<FarKey, FarValue> = HashMap::with_max_entries(4096, 0);

/// Interface Index: [0]-N3(gNB direction) [1]=N6(Internet direction)
#[map]
static IF_INDEX: aya_ebpf::maps::Array<u32> = aya_ebpf::maps::Array::with_max_entries(2, 0);

/// Gateway MAC: [0]-N6 Bridge [1]-gNB MAC
#[map]
static GW_MAC: aya_ebpf::maps::Array<upf_edge_common::MacAddr> =
    aya_ebpf::maps::Array::with_max_entries(2, 0); // 0: upfedge0, 1: bNB


//==============================================================
// Utilities
//==============================================================

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


//==============================================================
// for XDP
//==============================================================

/// Uplink (gNB -> Internet)
#[xdp]
pub fn upf_edge_n3(ctx: XdpContext) -> u32
{
    match try_n3_uplink(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Downlink (Internet -> UPF)
#[xdp]
pub fn upf_edge_n6(ctx: XdpContext) -> u32
{
    match try_n6_downlink(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn uplink_check_far(session: &SessionInfo) -> bool 
{
    let mut i = 0usize;
    while i < MAX_PDR_PER_SESSION {
        if i >= session.pdr_count as usize {
            break;
        }

        let pdr_id = session.pdr_ids[i];
        i += 1;

        let pdr = unsafe {
            match PDR_MAP.get(&PdrKey { pdr_id }) {
                Some(p) => *p,
                None => continue,
            }
        };

        if pdr.source_interface != IFACE_ACCESS {
            continue;
        }

        let far = unsafe {
            match FAR_MAP.get(&FarKey { far_id: pdr.far_id }) {
                Some(f) => *f,
                None => continue,
            }
        };

        if far.apply_action & ACTION_DROP != 0 {
            return true;
        }
        if far.apply_action & ACTION_FORW != 0 {
            return false;
        }
        return true;
    }

    false
}

fn try_n3_uplink(ctx: &XdpContext) -> Result<u32, ()> {
    // 1. Ethernet Header Check (EtherType = IPv4)
    let eth_type = unsafe {
        match ptr_at::<u16>(ctx, 12) { //Ethernet Type Offset
            Some(p) => u16::from_be(*p),
            None => {
                // info!(ctx, "ethernet");
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
            // info!(ctx, "Not IP Proto: {}", ip_proto);
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // 3. UDP Destination Port Check (2152 = GTP-U)
    let udp_dst = unsafe {
        match ptr_at::<u16>(ctx, ETH_HDR_LEN + IP_HDR_LEN + 2) { //2 means destination port offset in UDP Header.
            Some(p) => u16::from_be(*p),
            None => {
                // info!(ctx, "Udp Proto");
                return Ok(xdp_action::XDP_PASS);
            }
        }
    };
    if udp_dst != GTP_UDP_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    // 4. GTP-U Header Parsing
    let gtpu = unsafe {
        match ptr_at::<GtpuHdr>(ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN) {
            Some(p) => *p,
            None => {
                // info!(ctx, "GTP U Proto");
                return Ok(xdp_action::XDP_PASS);
            }
        }
    };
    if gtpu.msg_type != GTPU_GPDU {
        // info!(ctx, "Not GPDU");
        return Ok(xdp_action::XDP_PASS);
    }

    // GTP-U 확인 후, src IP 필터 추가
    // Uplink만 처리: src = gNB IP (172.22.0.23)
    // let src_ip = unsafe {
    //     match ptr_at::<u32>(ctx, ETH_HDR_LEN + 12) {
    //         Some(p) => u32::from_be(*p),
    //         None => return Ok(xdp_action::XDP_PASS),
    //     }
    // };


    // let teid = u32::from_be(gtpu.teid);
    // info!(ctx, "GTP-U packet: TEID={}", teid);

    // 172.22.0.23 = 0xac160017
    // if src_ip != 0xac160017 {
    //     return Ok(xdp_action::XDP_PASS);  // Downlink는 건드리지 않음
    // }

    // 5. Optional Field Calc
    let opt_len = if gtpu.flags & GTPU_FLAG_E != 0 {
        GTPU_EXT_HDR_LEN
    } else if gtpu.flags & (GTPU_FLAG_S | GTPU_FLAG_PN) != 0 {
        GTPU_OPT_LEN
    }
    else {
        0
    };
    // info!(ctx, "gtpu.flags=0x{:x}, opt_len={}", gtpu.flags, opt_len);

    // 6. Get UE IP address from Inner IP
    let outer_total = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + GTPU_HDR_LEN + opt_len;// as i32;
    let ue_ip_be = unsafe {
        match ptr_at::<u32>(ctx, outer_total + 12) {
            Some(p) => *p,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 7. Search SESSION MAP
    let key = SessionKey { ue_ip: ue_ip_be };
    let session = unsafe {
        match SESSION_MAP.get(&key) {
            Some(s) => *s,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 8. PDR/FAR lookup
    let should_drop = if session.pdr_count > 0 {
        uplink_check_far(&session)
    }
    else {
        false
    };

    if should_drop {
        return Ok(xdp_action::XDP_DROP);
    }

    // 9. get ethernet address
    let eth_src = unsafe {
        match ptr_at::<[u8; 6]>(ctx, 6)  {
            Some(p) => core::ptr::read_unaligned(p),
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    let strip = outer_total as i32;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, strip) } != 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(ETH_HDR_LEN as i32)) } != 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let new_start = ctx.data();
    let new_end = ctx.data_end();
    if new_start + ETH_HDR_LEN > new_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let br_mac = unsafe {
        match GW_MAC.get(0) {
            Some(m) => m.addr,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    unsafe {
        core::ptr::write_unaligned((new_start) as *mut [u8; 6], br_mac);
        core::ptr::write_unaligned((new_start + 6) as *mut [u8; 6], eth_src);
        core::ptr::write_unaligned((new_start + 12) as *mut u16, 0x0008u16);
    }

    info!(ctx, "[UL] decap ok, UE={:x}, redirect N6.", ue_ip_be);

    let n6_ifindex = unsafe {
        match IF_INDEX.get(1) {
            Some(&idx) => idx,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    Ok( unsafe{
        bpf_redirect(n6_ifindex, 0) as u32
    })
}


#[inline(always)]
fn downlink_get_far(session: &SessionInfo) -> Option<(u32, u32)>
{
    let mut i = 0usize;
    while i < MAX_PDR_PER_SESSION {
        if i >= session.pdr_count as usize {
            break;
        }

        let pdr_id = session.pdr_ids[i];
        i += 1;

        let pdr: PdrValue = unsafe {
            match PDR_MAP.get(&PdrKey { pdr_id }) {
                Some(p) => *p,
                None => continue,
            }
        };

        if pdr.source_interface != IFACE_CORE {
            continue;
        }

        let far: FarValue = unsafe {
            match FAR_MAP.get(&FarKey { far_id: pdr.far_id }) {
                Some(f) => *f,
                None => continue,
            }
        };

        if far.apply_action & ACTION_DROP != 0 {
            return None;
        }

        if far.apply_action & ACTION_FORW != 0 {
            return Some((far.gnb_ip, far.teid));
        }

    }
    None
}


fn try_n6_downlink(ctx: &XdpContext) -> Result<u32, ()> 
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
    let dst_ip_be = unsafe {
        match ptr_at::<u32>(ctx, ETH_HDR_LEN + 16) {
            Some(p) => *p, //Big-Endian type
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 3. Find the Session with key
    let key = SessionKey{ue_ip: dst_ip_be};
    let session = unsafe {
        match SESSION_MAP.get(&key) {
            Some(s) => *s,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 4. PDR/FAR lookup
    let (gnb_ip_be, teid_be) =  if session.pdr_count > 0 {
        match downlink_get_far(&session) {
            Some((ip, teid)) => (ip, teid),
            None => (session.gnb_ip, session.teid),
        }
    }
    else {
        (session.gnb_ip, session.teid)
    };

    // 5. 
    let inner_ip_tot_len = unsafe {
        match ptr_at::<u16>(ctx, ETH_HDR_LEN + 2) {
            Some(p) => u16::from_be(*p),
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 6. Get Eth Dst Address from ethernet header
    let eth_src = unsafe {
        match ptr_at::<[u8; 6]>(ctx, 0) {
            Some(p) => core::ptr::read_unaligned(p),
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 7. Get IP Total length
    // let inner_ip_tot_len = unsafe {
    //     match ptr_at::<u16>(ctx, ETH_HDR_LEN + 2) {
    //         Some(p) => u16::from_be(*p),
    //         None => return Ok(xdp_action::XDP_PASS),
    //     }
    // };

    // 6. Make Outer Header space
    // Eth(14) + IP(20) + UDP(8) + GTP(8) = 50
    // [                      ][Originial IP packet]
    // ^ <----------------------^
    let add_len = (IP_HDR_LEN + UDP_HDR_LEN + GTPU_HDR_LEN + GTPU_EXT_HDR_LEN) as i32;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -add_len)} != 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // 7. Re-verify Pointer
    let data = ctx.data();
    let data_end = ctx.data_end();
    let total_hdr = (ETH_HDR_LEN as i32 + add_len) as usize;
    if data + total_hdr > data_end {
        return Ok(xdp_action::XDP_PASS);
    }


    let gnb_mac = unsafe {
        match GW_MAC.get(1) {
            Some(m) => m.addr,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    // 8. Make Ethernet Header
    let eth = EthHdr {
        dst: gnb_mac,
        src: eth_src,
        eth_type: 0x0008u16,
    };

    // [                     ][GTP][Originial IP packet]
    //  ^
    //  |
    // data
    unsafe {
        core::ptr::write_unaligned(
            (data) as *mut EthHdr,
            eth);
    }

    // 9. Outer IP Header
    // [Ethernet][          ][GTP][Originial IP packet]
    //  ^-------->|
    //            data
    let outer_ip_len = (IP_HDR_LEN + UDP_HDR_LEN + GTPU_HDR_LEN + GTPU_EXT_HDR_LEN) as u16 + inner_ip_tot_len;
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
        daddr: gnb_ip_be,
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
    let udp_len = (UDP_HDR_LEN + GTPU_HDR_LEN + GTPU_EXT_HDR_LEN) as u16 + inner_ip_tot_len;
    let udp = UdpHdr {
        source: GTP_UDP_PORT.to_be(),
        dest: GTP_UDP_PORT.to_be(),
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
    let gtp_len  = inner_ip_tot_len + GTPU_EXT_HDR_LEN as u16;
    let gtpu = GtpuHdr {
        flags: 0x34, //version 1, PT=1, E=0, S=0, PN=0
        msg_type: GTPU_GPDU,
        length: gtp_len.to_be(),
        teid: teid_be,
    };
    unsafe {
        core::ptr::write_unaligned(
            (data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN) as *mut GtpuHdr, 
            gtpu);
    }

     // PDU Session Container Extension Header (Downlink, QFI=1)
    let ext_bytes: [u8; GTPU_EXT_HDR_LEN] = [
        0x00, 0x00,  // sequence number
        0x00,        // N-PDU number
        0x85,        // next ext type = PDU Session Container
        0x01,        // ext header length = 1 (× 4 bytes)
        0x00,        // PDU Type=0 (Downlink), spare
        0x01,        // spare=0, QFI=1
        0x00,        // next ext type = 0 (no more)
    ];
    unsafe {
        core::ptr::copy_nonoverlapping(
            ext_bytes.as_ptr(),
            (data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + GTPU_HDR_LEN) as *mut u8,
            GTPU_EXT_HDR_LEN,
        );
    }

    info!(ctx, "[DL] encap ok, UE={:x}, TEID={}", dst_ip_be, u32::from_be(teid_be));

    // Done.
    // info!(ctx, "Encapsulated: TEID={}", u32::from_be(session.teid));

    let n3_ifindex = unsafe {
        match IF_INDEX.get(0) {
            Some(&idx) => idx,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    Ok(unsafe { bpf_redirect(n3_ifindex, 0) as u32 })
}





#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
