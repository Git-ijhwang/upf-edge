use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};
use tui_textarea::TextArea;

use super::app::App;

pub fn render(frame: &mut Frame, app: &App, textarea: &TextArea)
{
    let area = frame.area();

    // 레이아웃 분할:
    // ┌─ 상태바 (3줄) ─┐
    // ├─ 로그 영역 ────┤
    // ├─ 명령어 입력 ──┤
    // └─ 도움말 (3줄) ┘

    let chunk = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(3),
            Constraint::Length(6),
        ])
        .split(area);

    render_status(frame, app, chunk[0]);
    render_logs(frame, app, chunk[1]);
    render_input(frame, textarea, chunk[2]);
    render_help(frame, chunk[3]);
}

fn render_status(frame: &mut Frame, app: &App, area: Rect)
{
    let assoc = if app.associated {
        Span::styled("✅ Associated", Style::default().fg(Color::Green))
    } else {
        Span::styled("❌ Not Associated", Style::default().fg(Color::Red))
    };

    let sessions = Span::raw(format!("  │  세션: {}개", app.session_count()));
    let hb = Span::raw(format!("  │  HB: {}초 전", app.last_hb_secs));
    let line = Line::from(vec![assoc, sessions, hb]);

    let block = Block::default()
        .title(" smf-sim ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let para = Paragraph::new(line).block(block);
    frame.render_widget(para, area);
}

fn render_logs(frame: &mut Frame, app: &App, area: Rect)
{
    let items: Vec<ListItem> = app.logs.iter().map(|entry| {
        let line = Line::from(vec![
            Span::styled(
                format!("[{}] ", entry.time),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(&entry.message),
        ]);
        ListItem::new(line)
    }).collect();

    // 로그는 항상 최신 항목이 아래에 오도록
    let list = List::new(items)
        .block(Block::default().title(" Shell ").borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    frame.render_widget(list, area);
}

fn render_input(frame: &mut Frame, textarea: &TextArea, area: Rect)
{
    let block = Block::default()
        .title(" Input Command (Enter: Runs | Esc: Reset) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let mut textarea = textarea.clone();
    textarea.set_block(block);
    frame.render_widget(&textarea, area);
}

fn render_help(frame: &mut Frame, area: Rect)
{
    let text = vec![
        Line::from("  show sessions   │  add session [N]   │  del session <seid>"),
        Line::from("  heartbeat / hb  │  clear             │  quit / q"),
    ];

    let para = Paragraph::new(text)
        .block(Block::default().title(" Commands ").borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    frame.render_widget(para, area);
}
