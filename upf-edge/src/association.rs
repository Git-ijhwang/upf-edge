use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use crate::pfcp_server::SessionData; 

#[derive(Clone, Debug, PartialEq)]
enum AssociationState {
    Active,
    HeartbeatTimeOut,
}

pub struct SmfAssociation {
    pub node_id: Ipv4Addr,
    pub peer_addr: SocketAddr,
    pub recovery_ts: u32,
    pub state: AssociationState,
    pub sessions: HashMap<u64, SessionData>,
    pub last_activity: Instant,
    pub heartbeat: HeartbeatTracker,
}

impl SmfAssociation {
    pub fn new(node_id: Ipv4Addr, peer_addr: SocketAddr, recovery_ts: u32) -> Self {
        Self {
            node_id,
            peer_addr,
            recovery_ts,
            state: AssociationState::Active,
            sessions: HashMap::new(),
            last_activity: Instant::now(),
            heartbeat: HeartbeatTracker::new(),
        }
    }
}

pub struct HeartbeatTracker {
    pub next_seq: u32,
    pub last_sent: Option<Instant>,
    pub last_response: Option<Instant>,
    pub consecutive_failures: u32,
}
impl HeartbeatTracker {
    pub fn new() -> Self {
        Self {
            next_seq: 200,
            last_sent: None,
            last_response: None,
            consecutive_failures: 0,
        }
    }
}