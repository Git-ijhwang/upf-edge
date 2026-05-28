use std::net::Ipv4Addr;
use crate::ie::{self, iter_ies};
use crate::types::*;
use crate::header::PfcpError;

///Association Setup Request
pub struct AssociationSetupReq {
    pub node_id: Ipv4Addr,
    pub recovery_ts: u32,
}

impl AssociationSetupReq {
    pub fn decode(body: &[u8]) -> anyhow::Result<Self> 
    {
        let ies = iter_ies(body);

        let node_id = ies.iter()
            .find(|ie| ie.ie_type == PFCP_IE_NODE_ID)
            .ok_or_else(|| anyhow::anyhow!("Node ID Missing"))
            .and_then(|raw| ie::parse_node_id(raw.value)
                .map_err(|e| anyhow::anyhow!("{}", e))
            )?;
        
        let recovery_ts = ies.iter()
            .find(|ie| ie.ie_type == PFCP_IE_RECOVERY_TIME_STAMP)
            .ok_or_else(|| anyhow::anyhow!("Recovery TS missing"))
            .and_then(|raw| ie::parse_recovery_timestamp(raw.value)
                .map_err(|e| anyhow::anyhow!("{}", e))
            )?;

        Ok(Self {node_id, recovery_ts})
    }
}

pub struct SessionEstablishmentReq {
    pub node_id: Option<Ipv4Addr>,
    pub cp_seid: u64,
    pub smf_addr: Ipv4Addr,
    pub create_pdrs: Vec<crate::ie::ParsedPDR>,
    pub create_fars: Vec<crate::ie::ParsedFAR>,
}

impl SessionEstablishmentReq {
    pub fn decode(body: &[u8]) -> anyhow::Result<Self>
    {
        let ies = iter_ies(body);

        let (cp_seid, smf_addr) = ies.iter()
            .find(|ie| ie.ie_type == PFCP_IE_FSEID)
            .ok_or_else(|| anyhow::anyhow!("F-SEID missing"))
            .and_then(|raw| ie::parse_fseid(raw.value)
                .map_err(|e| anyhow::anyhow!("{}", e))
            )?;

        let node_id = ies.iter()
            .find(|ie| ie.ie_type == PFCP_IE_NODE_ID)
            .and_then(|raw| ie::parse_node_id(raw.value).ok());

        let create_pdrs = ies.iter()
            .filter(|ie| ie.ie_type == PFCP_IE_CREATE_PDR)
            .map(|raw| ie::parse_create_pdr(raw.value)
                .map_err(|e| anyhow::anyhow!("{}", e)))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let create_fars = ies.iter()
            .filter(|ie| ie.ie_type == PFCP_IE_CREATE_FAR)
            .map(|raw| ie::parse_create_far(raw.value)
                .map_err(|e| anyhow::anyhow!("{}", e)))
            .collect::<anyhow::Result<Vec<_>>>()?;


        Ok(Self {
            node_id,
            cp_seid,
            smf_addr,
            create_pdrs,
            create_fars,
        })
    }
}

///Heartbeat Request
pub struct HeartbeatReq {
    pub recovery_ts: Option<u32>
}

impl HeartbeatReq {
    pub fn decode(body: &[u8]) -> Self
    {
        let ies = iter_ies(body);

        let recovery_ts = ies.iter()
            .find(|ie| ie.ie_type == PFCP_IE_RECOVERY_TIME_STAMP)
            .and_then(|raw| ie::parse_recovery_timestamp(raw.value).ok());

        Self { recovery_ts }
    }
}