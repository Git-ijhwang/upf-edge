use std::net::Ipv4Addr;
use pfcp_common::dict_ext;
use pfcp_common::header::PfcpHeader;
use pfcp_common::ie;
use pfcp_common::types::*;

pub fn validate_response ( req_type: u8,
                            req_seq: u32,
                            rsp:     &[u8])
    -> anyhow::Result<()>
{
    let (rsp_hdr, body) = PfcpHeader::decode(rsp)?;
    let expected_type = req_type + 1;

    anyhow::ensure!( rsp_hdr.msg_type == expected_type,
        "msg_type 불일치: expected={}, got={}",
        expected_type, rsp_hdr.msg_type);

    anyhow::ensure!( rsp_hdr.seq_num == req_seq,
        "seq 불일치: expected={}, got={}",
        req_seq, rsp_hdr.seq_num);

    let result = dict_ext::validate(rsp_hdr.msg_type, body);
    if !result.is_ok() {
        anyhow::bail!( "Mandaytory IE 누락 in {}: {:?}",
            dict_ext::lookup(rsp_hdr.msg_type)
                .map(|s| s.name)
                .unwrap_or("unknown"),
            result.missing);
    }

    let ies = ie::iter_ies(body);
    if let Some(cause) = ies.iter().find(|i| i.ie_type == PFCP_IE_CAUSE) {
        anyhow::ensure!(
            !cause.value.is_empty() && cause.value[0] == CAUSE_REQUEST_ACCEPTED,
            "Cause={} (not accepted)", cause.value.first().unwrap_or(&0)
        );
    }

    Ok(())
}


pub fn extract_session_info(rsp: &[u8]) -> anyhow::Result<(u64, u32, Ipv4Addr)>
{
    let (_hdr, body) = PfcpHeader::decode(rsp)?;
    let ies = ie::iter_ies(body);

    // F-SEID -> UPF SEID
    let fseid = ies.iter()
        .find(|i| i.ie_type == PFCP_IE_FSEID)
        .ok_or_else(|| anyhow::anyhow!("No F-SEID"))?;

    let (upf_seid, _) = ie::parse_fseid(fseid.value)?;
    anyhow::ensure!(upf_seid != 0, "UPF SEID = 0 (Abnormal)");

    // Created PDR -> F-TEID
    let created_pdr = ies.iter()
        .find(|i| i.ie_type == PFCP_IE_CREATED_PDR)
        .ok_or_else(|| anyhow::anyhow!("No Created PDR"))?;
    let inner = ie::iter_ies(created_pdr.value);
    let fteid = inner.iter()
        .find(|i| i.ie_type == PFCP_IE_FTEID)
        .ok_or_else(|| anyhow::anyhow!("No F-TEID"))?;
    let (upf_teid, upf_n3_addr) = ie::parse_fteid(fteid.value)?;
    anyhow::ensure!(upf_teid != 0, "UPF TEID = 0 (Abnormal)");

    Ok((upf_seid, upf_teid, upf_n3_addr))
}


pub fn extract_recovery_ts(rsp: &[u8]) -> Option<u32> {
    let (_hdr, body) = pfcp_common::header::PfcpHeader::decode(rsp).ok()?;
    let ies = pfcp_common::ie::iter_ies(body);
    ies.iter()
        .find(|i| i.ie_type == pfcp_common::types::PFCP_IE_RECOVERY_TIME_STAMP)
        .and_then(|i| pfcp_common::ie::parse_recovery_timestamp(i.value).ok())
}