use std::collections::VecDeque;
use chrono::Local;

use crate::state::SimSession;

pub struct LogEntry {
    pub time: String,
    pub message: String,
}

impl LogEntry {
    fn new(msg: impl Into<String>) -> Self {
        Self {
            time: Local::now().format("%H:%M:S").to_string(),
            message: msg.into(),
        }
    }
}

pub struct App {
    /// Log buffer (Max 200)
    pub logs: VecDeque<LogEntry>,
    /// Session List
    pub sessions: Vec<SimSession>,
    /// Association Status
    pub associated: bool,
    /// elapse time after last Heartbeat message
    pub last_hb_secs: u64,
    /// Program exit flag
    pub should_quit: bool,
    /// Message for last command result
    pub last_result: Option<String>,
}

impl App {
    pub fn new() -> Self {
        Self {
            logs:         VecDeque::new(),
            sessions:     Vec::new(),
            associated:   false,
            last_hb_secs: 0,
            should_quit:  false,
            last_result:  None,
        }
    }

    pub fn log(&mut self, msg: impl Into<String>)
    {
        self.logs.push_back(LogEntry::new(msg));
        if self.logs.len() > 200 { //Max Line 200
            self.logs.pop_front();
        }
    }

    pub fn clear_logs(&mut self)
    {
        self.logs.clear();
    }

    pub fn session_count(&self) -> usize
    {
        self.sessions.len()
    }
}