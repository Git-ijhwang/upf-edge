use std::sync::Arc;
use std::time::{Duration, Instant};
use crossterm::event::EventStream;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt;
use ratatui::{Terminal, backend::CrosstermBackend, text};
use tui_textarea::TextArea;

use super::app::{App, AppEvent};
use super::command::UpfCommand;
use super::ui;


async fn run_loop( terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
                rx: &mut tokio::sync::mpsc::Receiver<AppEvent>)
    -> anyhow::Result<()>
{
    let mut app = App::new();
    let mut textarea = TextArea::default();
    textarea.set_placeholder_text("Input Command..");

    let mut sys = sysinfo::System::new_all();

    let mut event_stream = EventStream::new();
    let tick = Duration::from_millis(500);
    let mut last_sys_update = Instant::now();

    app.log(" smf-sim TUI Start! Check the'help' command.");

    loop {
        // Draw UI
        terminal.draw(|frame| {
            ui::render(frame, &app, &textarea);
        })?;

        tokio::select! {
            _ = tokio::time::sleep(tick) => {
                app.last_hb_secs = app.last_hb_secs.saturating_add(1);

                if last_sys_update.elapsed() >= Duration::from_secs(1) {
                    sys.refresh_cpu_all();
                    sys.refresh_memory();

                    app.cpu_pct = sys.global_cpu_usage();
                    app.mem_pct = sys.used_memory() as f32 / sys.total_memory() as f32 * 100.0;
                    last_sys_update = Instant::now();
                }
            }

            event = rx.recv() => {
                match event {
                    Some(AppEvent::Log(msg)) => app.log(msg),
                    Some(AppEvent::AssociationChanged(v)) => {
                        app.associated = v;
                        app.log(if v { "✅ UPF Associated" } else { "❌ UPF Disassociated" });
                    }
                    Some(AppEvent::SessionsUpdated(s)) => app.sessions = s,
                    Some(AppEvent::HeartbeatUpdated) => app.last_hb_secs = 0,
                    None => break,
                }
            }

            Some(Ok(event)) = event_stream.next() => {
                if let Event::Key(key) = event {
                    match (key.code, key.modifiers) {
                        (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                            app.should_quit = true;
                        }

                        (KeyCode::Enter, KeyModifiers::NONE) => {
                            let input = textarea.lines()[0].trim().to_string();
                            if !input.is_empty() {
                                execute_command(&mut app, &input);
                                textarea = TextArea::default();
                                textarea.set_placeholder_text("Input Command..");
                            }
                        }

                        (KeyCode::Esc, KeyModifiers::NONE) => {
                            textarea = TextArea::default();
                            textarea.set_placeholder_text("Input Command..");
                        }

                        _ => {
                            textarea.input(key);
                        }
                    }
                }
            }
        }

        if app.should_quit { break; }
    }
    Ok(())
}


fn execute_command(app: &mut App, input: &str)
{
    app.log(format!("> {}", input));
    match UpfCommand::from_input(input) {
        Ok(cmd) => match cmd {
            UpfCommand::ShowSessions => {
                if app.sessions.is_empty() {
                    app.log("no session");
                }
                else {
                    app.log(format!(" Total {} sessions(s)", app.sessions.len()));

                    let lines: Vec<String> = app.sessions.iter().map(|s| {
                        format!("  SEID={:#x}  UE={}  TEID={:#x}  gNB={}",
                            s.seid, s.ue_ip, s.teid, s.gnb_ip)
                    }).collect();

                    for line in lines {
                        app.log(line);
                    }

                }
            }

            UpfCommand::ShowSession { seid } => {
                if let Some(s) = app.sessions.iter().find(|s| s.seid == seid) {

                    let seid = s.seid;
                    let ue_ip = s.ue_ip;
                    let teid = s.teid;
                    let gnb_ip = s.gnb_ip;

                    app.log(format!("  SEID    : {:#x}", seid));
                    app.log(format!("  UE IP   : {}", ue_ip));
                    app.log(format!("  TEID    : {:#x}", teid));
                    app.log(format!("  gNB IP  : {}", gnb_ip));
                } else {
                    app.log(format!("  SEID    : {:#x} 없음", seid));
                }
            }
            UpfCommand::Clear => {
                app.logs.clear();
            }
            UpfCommand::Help => {
                for line in UpfCommand::help_text().lines() {
                    app.log(line);
                }
            }
            UpfCommand::Quit => app.should_quit = true,
        },
        Err(e) => {
            app.log(format!("  명령어 파싱 실패: {}", e));
        }
    }
}


pub async fn run (mut rx: tokio::sync::mpsc::Receiver<AppEvent>)
    -> anyhow::Result<()>
{

    enable_raw_mode();
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture);
    let backend =CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let local = tokio::task::LocalSet::new();
    let result = local.run_until(
        run_loop(&mut terminal, &mut rx)
    ).await;

    disable_raw_mode();
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    result
}
                  
                 