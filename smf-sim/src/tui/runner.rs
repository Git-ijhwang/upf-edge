
use std::time::{Duration, Instant};

// use clap::Command;
use std::sync::Arc;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{Terminal, backend::CrosstermBackend, text};
use tui_textarea::TextArea;

// use Parking_lot::parking_lot;
use crate::config::SimConfig;
use crate::state::SimState;
use crate::transport::PfcpTransport;

use super::tui;
use super::app::{App, AppEvent};
// use super::command::Command;
use super::command::Command as TuiCommand;
use crossterm::event::EventStream;

use futures::StreamExt;

use pfcp_common::builder::MsgBuilder;
use pfcp_common::header::PfcpHeader;
use pfcp_common::types::*;

async fn do_association(transport: &PfcpTransport,
                        smf_addr: std::net::Ipv4Addr)
    -> anyhow::Result<()>
{
    let seq = 1u32;
    let ntp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_secs() as u32;

    let hdr = PfcpHeader::new_node_msg(PFCP_ASSOCIATION_SETUP_REQ,seq);
    let mut msg = MsgBuilder::new(hdr);

    msg.add_node_id_v4(smf_addr);
    msg.add_recovery_timestamp(ntp.wrapping_add(2_208_988_800));

    let req = msg.finish();

    let rsp = transport.send_and_recv(&req).await?;

    crate::validator::validate_response(PFCP_ASSOCIATION_SETUP_REQ, seq, &rsp)?;

    Ok(())
}


async fn handle_async_command( cmd: TuiCommand,
                               transport: Arc<PfcpTransport>,
                               tx: tokio::sync::mpsc::Sender<AppEvent>,
                               smf_addr: std::net::Ipv4Addr,
                               gnb_addr: std::net::Ipv4Addr,
                            //    config: &SimConfig,
                            //    state: Arc<std::sync::Mutex<SimState>>)
                               state: Arc<parking_lot::Mutex<SimState>>)
{
    match cmd {
        TuiCommand::AddSession { count } => {
            for i in 0..count {
                let (seq, ue_ip, gnb_teid, cp_seid) = {
                    let mut s = state.lock();
                    let seq = s.next_seq_num();

                    let ue_ip = match s.alloc_ue_ip() {
                        Ok(ip) => ip,
                        Err(e) => {
                            tx.send(AppEvent::Log(format!("UE IP 할당 실패: {}", e))).await.ok();
                            return;
                        }
                    };
                    (seq, ue_ip, s.alloc_gnb_teid(), s.alloc_cp_seid())
                };


                tx.send(AppEvent::Log(format!("UE IP  {}", ue_ip))).await.ok();
                let req = pfcp_common::builder::build_session_establishment_request(
                    seq, smf_addr, cp_seid, ue_ip, gnb_addr, gnb_teid,
                );

                match transport.as_ref().send_and_recv(&req).await {
                    Ok(rsp) => {

                        match crate::validator::extract_session_info(&rsp) {
                            Ok((upf_seid, upf_teid, upf_n3_addr)) => {
                                let session = crate::state::SimSession {
                                    cp_seid, upf_seid, upf_teid,
                                    upf_n3_addr, ue_ip, gnb_teid,
                                    created_at: std::time::Instant::now(),
                                };

                                state.lock().sessions.insert(cp_seid, session);
                                tx.send(
                                    AppEvent::Log(
                                        format!(
                                            "Session Added: UE={}, SEID={:#x}", ue_ip, upf_seid
                                        )
                                    )
                                ).await.ok();
                            }
                            Err(e) => {
                                tx.send(
                                    AppEvent::Log(
                                        format!("세션 정보 추출 실패: {}", e)
                                    )
                                ).await.ok();
                            }
                        }
                    }
                    Err(e) => {
                        tx.send(
                            AppEvent::Log(
                                format!("세션 생성 실패: {}", e)
                            )
                        ).await.ok();
                    }
                }

                let sessions: Vec<_> = {
                    let s = state.lock();
                    s.sessions.values().cloned().collect()
                };
                tx.send(AppEvent::SessionsUpdated(sessions)).await.ok();
            }
        }

        TuiCommand::DelSession { seid } => {
            let upf_seid = {
                state.lock().sessions.get(&seid).map(|s| s.upf_seid)
            };

            if let Some(upf_seid) = upf_seid {
                let seq = state.lock().next_seq_num();
                let hdr = PfcpHeader::new_session_msg(PFCP_SESSION_DELETION_REQ, upf_seid, seq);
                let msg = MsgBuilder::new(hdr).finish();

                match transport.as_ref().send_and_recv(&msg).await {
                    Ok(rsp) => {
                        let _ = crate::validator::validate_response(
                            PFCP_SESSION_DELETION_REQ, seq, &rsp
                        );
                        state.lock().sessions.remove(&seid);

                        let sessions: Vec<_> = state.lock()
                            .sessions.values().cloned().collect();

                        tx.send(AppEvent::SessionsUpdated(sessions)).await.ok();
                        tx.send(AppEvent::Log(
                            format!("Session Deleted: SEID={:#x}", seid)
                        )).await.ok();
                    }
                    Err(e) => {
                        tx.send(AppEvent::Log(format!("Failed to delete session: {}", e))).await.ok();
                    }
                }
            }
            else {
                tx.send(AppEvent::Log(format!("No Exist Session {:#x}", seid))).await.ok();
            }
        }

        TuiCommand::Heartbeat => {
            let seq = { state.lock().next_seq_num() };
            let hdr = PfcpHeader::new_node_msg(PFCP_HEARTBEAT_REQ, seq);
            let mut msg = MsgBuilder::new(hdr);
            let ntp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap().as_secs() as u32;

            msg.add_recovery_timestamp(ntp.wrapping_add(2_208_988_800));

            let req = msg.finish();
            match transport.as_ref().send_and_recv(&req).await {
                Ok(_) => {
                    tx.send(AppEvent::Log("← Heartbeat Response OK".into())).await.ok();
                    tx.send(AppEvent::HeartbeatUpdated).await.ok();
                }
                Err(e) => {
                    tx.send(AppEvent::Log(format!("HB 실패: {}", e))).await.ok();
                }
            }
        }

        _ => {}
    }
}


async fn run_loop( terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
                    config: &SimConfig,
                    transport: std::sync::Arc<PfcpTransport>,
                    state: SimState)
    -> anyhow::Result<()>
{
    let mut event_stream = EventStream::new();

    let state_arc = Arc::new(parking_lot::Mutex::new(state));
    // let state_arc = Arc::new(std::sync::Mutex::new(state));

    let mut app = App::new();
    let mut textarea = TextArea::default();
    textarea.set_placeholder_text("Input Command..");

    app.log(" smf-sim TUI Start! Check the'help' command.");

    let (tx, mut rx) = tokio::sync::mpsc::channel::<AppEvent>(100);

    {
        let t = transport.clone();
        let cfg_smf_addr = config.network.smf_n4_addr;
        let tx2 = tx.clone();

        tokio::spawn(async move {
            tx2.send(AppEvent::Log("upf-edge Connecting....".to_string())).await.ok();

            match do_association(&t, cfg_smf_addr).await {
                Ok(_) => {
                    tx2.send(AppEvent::AssociationChanged(true)).await.ok();
                    tx2.send(AppEvent::Log("Connected to upf-edge".to_string())).await.ok();
                }

                Err(e) => {
                    // tx2.send(AppEvent::AssociationChanged(false)).await.ok();
                    tx2.send(AppEvent::Log(format!("Failed to connect to upf-edge: {}", e))).await.ok();
                }
            }
        });
    }

    let tick = Duration::from_millis(250);
    let mut last_tick = Instant::now();

    loop {
        // Handle Background Events
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::Log(msg) => app.log(msg),
                AppEvent::AssociationChanged(v) => app.associated = v,
                AppEvent::HeartbeatUpdated => app.last_hb_secs = 0,
                AppEvent::SessionsUpdated(sessions) => app.sessions = sessions,
            }
        }


        // Draw UI
        terminal.draw(|frame| {
            tui::render(frame, &app, &textarea);
        })?;

        // Handle Key Events
        // if crossterm::event::poll(tick.saturating_sub(last_tick.elapsed()))? {
        tokio::select! {
            _ = tokio::time::sleep(tick) => {
                if last_tick.elapsed() >= tick {
                    last_tick = Instant::now();
                }
            }

            Some(Ok(event)) = event_stream.next() => {
            // match event::read()? {
                // Event::Key(key) => {
                if let Event::Key(key) = event {

                    match (key.code, key.modifiers) {
                        // 'q' 또는 Ctrl+C로 종료
                        (KeyCode::Char('q'), KeyModifiers::NONE) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                            app.should_quit = true;
                        }

                        // Enter 키로 명령 실행
                        (KeyCode::Enter, KeyModifiers::NONE) => {
                            // let input = textarea.lines()[0].trim().to_string();

                            // if !input.trim().is_empty() {
                            //     execute_command(&mut app, &input);

                            //     // 명령 실행 후 입력 초기화
                            //     textarea = TextArea::default();
                            //     textarea.set_placeholder_text("Input Command..");
                            // }

                            let input = textarea.lines()[0].trim().to_string();

                            if !input.is_empty() {
                                if let Some(async_cmd) = execute_command(&mut app, &input) {
                                    let t = transport.clone();
                                    let tx2 = tx.clone();
                                    let state2 = state_arc.clone();
                                    let smf_addr = config.network.smf_n4_addr;
                                    let gnb_addr = config.network.gnb_addr;

                                    tokio::task::spawn_local(async move {
                                        handle_async_command(
                                            async_cmd, t,
                                            tx2, smf_addr,
                                            gnb_addr, state2).await;
                                    });
                                }

                                textarea = TextArea::default();
                                textarea.set_placeholder_text("Input Command..");
                            }
                        }

                        //Esc 키로 입력 초기화
                        (KeyCode::Esc, KeyModifiers::NONE) => {
                            textarea = TextArea::default();
                            textarea.set_placeholder_text("Input Command..");
                        }

                        // 그 외의 키는 TextArea에 전달
                        _ => {
                            textarea.input(key);
                        }
                    }
                }
                // _ => { /* Ignore other events */ }
            }
        }

        // Periodically update the status
        if last_tick.elapsed() >= tick {
            last_tick = Instant::now();
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}


fn execute_command(app: &mut App, input: &str)
    -> Option<TuiCommand>
{
    app.log(format!("> {}", input));

    match TuiCommand::from_input(input) {
        Ok(cmd) => match cmd {
            TuiCommand::ShowSessions => {
                if app.sessions.is_empty() {
                    app.log("no session");
                }
                else {
                    app.log(format!(" Total {} sessions(s)", app.sessions.len()));

                    // for s in &app.sessions {
                    // let seid = s.upf_seid;
                    // let ue_ip = s.ue_ip;
                    // let teid = s.cp_seid;
                    // let gnb_ip = s.upf_n3_addr;

                        let lines: Vec<String> = app.sessions.iter().map(|s| {
                            format!("  SEID={:#x}  UE={}  TEID={:#x}  gNB={}",
                                s.upf_seid, s.ue_ip, s.upf_teid, s.upf_n3_addr)
                        }).collect();

                        for line in lines {
                            app.log(line);
                        }
                    // }
                }

                None
            }

            TuiCommand::ShowSession { seid } => {
                if let Some(s) = app.sessions.iter().find(|s| s.upf_seid == seid) {
                    let seid = s.upf_seid;
                    let ue_ip = s.ue_ip;
                    let teid = s.cp_seid;
                    let gnb_ip = s.upf_n3_addr;
                    app.log(format!("  SEID    : {:#x}", seid));
                    app.log(format!("  UE IP   : {}", ue_ip));
                    app.log(format!("  TEID    : {:#x}", teid));
                    app.log(format!("  gNB IP  : {}", gnb_ip));
                } else {
                    app.log(format!("  SEID    : {:#x} 없음", seid));
                }

                None
            }

            cmd @ TuiCommand::AddSession { .. } => Some(cmd),
            // { app.log(format!("  세션 {}개 추가", count)); }
            cmd @ TuiCommand::DelSession { .. } => Some(cmd),
            // { app.log(format!("  SEID {:#x} 세션 삭제 [not develped yet]", seid)); }
            cmd @ TuiCommand::Heartbeat => Some(cmd),
            // { app.log("  Heartbeat 수동 전송 [not develped yet]"); }
            TuiCommand::Clear => {
                app.logs.clear();
                None
            }
            TuiCommand::Help => {
                for line in TuiCommand::help_text().lines() {
                    app.log(line);
                }
                None
            }
            TuiCommand::Quit => {
                app.should_quit = true;
                None
            }
        },
        Err(e) => {
            app.log(format!("  명령어 파싱 실패: {}", e));
            None
        }
    }
}

pub async fn run ( config: &SimConfig,
                    transport: std::sync::Arc<PfcpTransport>,
                    state: SimState)
    -> anyhow::Result<()>
{
    enable_raw_mode();
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture);
    let backend =CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // let result = run_loop(&mut terminal, config, transport, state).await;
    let local = tokio::task::LocalSet::new();
    let result = local.run_until(
        run_loop(&mut terminal, config, transport, state)
    ).await;


    disable_raw_mode();
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    result
}
