use std::collections::VecDeque;
use chrono::Local;

pub enum AppEvent {
    /// Log message
    Log(String),

    /// UPF association changed
    AssociationChanged(bool),

    /// UPF sessions updated
    SessionsUpdated(Vec<SessionEntry>),

    /// UPF heartbeat updated
    HeartbeatUpdated,
}

#[derive(Clone)]
pub struct SessionEntry {
    pub seid: u64,
    pub ue_ip: std::net::Ipv4Addr,
    pub teid: u32,

    pub gnb_ip: std::net::Ipv4Addr,
    pub duration: std::time::Instant
}

pub struct LogEntry {
    pub time: String,
    pub message: String,
}

impl LogEntry {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            time: Local::now().format("%H:%M:%s").to_string(),
            message: msg.into(),
        }
    }
}

pub struct App {
    pub logs: VecDeque<LogEntry>,
    pub sessions: Vec<SessionEntry>,
    pub associated: bool,
    pub last_hb_secs: u64,
    pub cpu_pct: f32,
    pub mem_pct: f32,
    pub should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            logs: VecDeque::new(),
            sessions: Vec::new(),
            associated: false,
            last_hb_secs: 0,
            cpu_pct: 0.0,
            mem_pct: 0.0,
            should_quit: false,
        }
    }

    pub fn log (&mut self, msg: impl Into<String>) {
        self.logs.push_back(LogEntry::new(msg));
        if self.logs.len() > 200 {
            self.logs.pop_front();
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}