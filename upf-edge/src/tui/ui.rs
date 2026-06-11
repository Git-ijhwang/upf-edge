use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Wrap},
};

use tui_textarea::TextArea;
use super::app::App;


/// 사용률에 따라 색상 결정
fn gauge_color(pct: f32) -> Color {
    if pct >= 80.0 { Color::Red }
    else if pct >= 60.0 { Color::Yellow }
    else { Color::Green }
}

pub fn render(frame: &mut Frame, app: &App, textarea: &TextArea)
{
    let area = frame.area();

    let chunk = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(7),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(area);

    render_status(frame, app, chunk[0]);
    render_server_status(frame, app, chunk[1]);
    render_logs(frame, app, chunk[2]);
    render_input(frame, textarea, chunk[3]);
    render_help(frame, chunk[4]);
}


fn render_status(frame: &mut Frame, app: &App, area: Rect)
{
    let assoc = if app.associated {
        Span::styled("✅ Associated", Style::default().fg(Color::Green))
    } else {
        Span::styled("❌ Not Associated", Style::default().fg(Color::Red))
    };

    let sessions = Span::raw(format!("  │  {} Session", app.session_count()));
    let hb = Span::raw(format!("  │  HB: {} Sec.", app.last_hb_secs));
    let line = Line::from(vec![
        assoc, sessions, hb
        ]);
    
    let block = Block::default()
        .title(" UPF-EDGE ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let para = Paragraph::new(line).block(block);

    frame.render_widget( para, area);
}

fn render_server_status(frame: &mut Frame, app: &App, area: Rect)
{
    let block = Block::default()
        .title(" Server Status ")
        .borders(Borders::ALL);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), //Space
            Constraint::Length(1), //CPU
            Constraint::Length(1), //Memory
            Constraint::Length(1), //Session
            Constraint::Length(1), //Space
        ])
        .split(inner);

    let cpu_color = gauge_color(app.cpu_pct);
    frame.render_widget(
        Gauge::default()
            .label(format!("CPU     {:5.1}%", app.cpu_pct))
            .ratio((app.cpu_pct / 100.0).clamp(0.0, 1.0) as f64)
            .gauge_style(Style::default().fg(cpu_color)),
        rows[1],
    );

    let mem_color = gauge_color(app.mem_pct);
    frame.render_widget(
        Gauge::default()
            .label(format!("Memory     {:5.1}%", app.mem_pct))
            .ratio((app.mem_pct / 100.0).clamp(0.0, 1.0) as f64)
            .gauge_style(Style::default().fg(mem_color)),
        rows[2],
    );

    let max_sessions = 100.0_f32;
    let sess_pct = (app.session_count() as f32 / max_sessions * 100.0).min(100.0);
    frame.render_widget(
        Gauge::default()
            .label(format!("Session {:5.1}% ({})", sess_pct, app.session_count()))
            .ratio((sess_pct / 100.0).clamp(0.0, 1.0) as f64)
            .gauge_style(Style::default().fg(Color::Blue)),
        rows[3],
    );

}


fn render_logs(frame: &mut Frame, app: &App, area: Rect)
{
    let items: Vec<ListItem> = app.logs.iter().map(|entry| {
        ListItem::new(
            Line::from(vec![
                Span::styled(
                    format!("[{}] ", entry.time),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(&entry.message),
            ])
        )
    }).collect();

    // 로그는 항상 최신 항목이 아래에 오도록
    let list = List::new(items)
        .block(Block::default().title(" Shell ").borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    frame.render_widget(list, area);
}


fn render_input(frame: &mut Frame, textarea: &TextArea, area: Rect)
{
    let mut textarea = textarea.clone();

    let block = Block::default()
        .title(" Input Command (Enter: Runs | Esc: Reset) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    textarea.set_block(block);
    frame.render_widget(&textarea, area);
}


fn render_help(frame: &mut Frame, area: Rect)
{
    let text = vec![
        Line::from("  show sessions   │  show session <seid>   │  quit / q"),
    ];

    let para = Paragraph::new(text)
        .block(Block::default().title(" Commands ").borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    frame.render_widget(para, area);
}