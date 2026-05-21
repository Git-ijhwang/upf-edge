
use std::time::{Duration, Instant};

use clap::Command;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{Terminal, backend::CrosstermBackend, text};
use tui_textarea::TextArea;

use crate::config::SimConfig;
use crate::state::SimState;
use crate::transport::PfcpTransport;

use super::tui;
use super::app::App;
// use super::command::Command;
use super::command::Command as TuiCommand;



async fn run_loop(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
                    _config: &SimConfig,
                    _transport: std::sync::Arc<PfcpTransport>,
                    _state: SimState)
    -> anyhow::Result<()>
{
    let mut app = App::new();
    let mut textarea = TextArea::default();
    textarea.set_placeholder_text("Input Command..");

    app.log("smf-sim TUI 시작. 'help' 명령어로 사용법 확인.");

    let tick = Duration::from_millis(250);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|frame| {
            tui::render(frame, &app, &textarea);
        })?;

        if crossterm::event::poll(tick.saturating_sub(last_tick.elapsed()))? {
            match event::read()? {
                Event::Key(key) => {
                    match (key.code, key.modifiers) {
                        // 'q' 또는 Ctrl+C로 종료
                        (KeyCode::Char('q'), KeyModifiers::NONE) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                            app.should_quit = true;
                        }

                        // Enter 키로 명령 실행
                        (KeyCode::Enter, KeyModifiers::NONE) => {
                            let input = textarea.lines()[0].trim().to_string();

                            if !input.trim().is_empty() {
                                execute_command(&mut app, &input);

                                // 명령 실행 후 입력 초기화
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
                _ => { /* Ignore other events */ }
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
            }

            TuiCommand::AddSession { count } => {
                app.log(format!("  세션 {}개 추가", count));
            }
            TuiCommand::DelSession { seid } => {
                app.log(format!("  SEID {:#x} 세션 삭제 [not develped yet]", seid));
            }
            TuiCommand::Heartbeat => {
                app.log("  Heartbeat 수동 전송 [not develped yet]");
            }
            TuiCommand::Clear => {
                app.logs.clear();
            }
            TuiCommand::Help => {
                for line in TuiCommand::help_text().lines() {
                    app.log(line);
                }
            }
            TuiCommand::Quit => {
                app.should_quit = true;
            }
        },
        Err(e) => {
            app.log(format!("  명령어 파싱 실패: {}", e));
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

    let result = run_loop(&mut terminal, config, transport, state).await;

    disable_raw_mode();
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    result
}
