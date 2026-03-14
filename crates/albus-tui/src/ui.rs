use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::{
    AppSnapshot, EntryDetail, LockedView, NoVaultView, UnlockedView,
    runtime::{ModalFieldView, ModalView},
};

/// Renders the current application snapshot and optional modal dialog.
pub(crate) fn render(frame: &mut Frame<'_>, snapshot: &AppSnapshot, modal: Option<&ModalView>) {
    match snapshot {
        AppSnapshot::NoVault(view) => render_no_vault(frame, view),
        AppSnapshot::Locked(view) => render_locked(frame, view),
        AppSnapshot::Unlocked(view) => render_unlocked(frame, view),
    }

    if let Some(modal) = modal {
        render_modal(frame, modal);
    }

    if let Some(message) = status_message(snapshot) {
        render_status(frame, frame.area(), message);
    }
}

fn render_no_vault(frame: &mut Frame<'_>, view: &NoVaultView) {
    let area = frame.area();
    let lines = vec![
        Line::from("No encrypted vault is configured on this device."),
        Line::from(String::new()),
        Line::from(format!(
            "Suggested path: {}",
            view.suggested_vault_path.display()
        )),
        Line::from(String::new()),
        Line::from("Press c to create a new local vault."),
        Line::from("Press r to restore an encrypted backup."),
    ];

    let widget = Paragraph::new(lines)
        .block(Block::default().title("Albus").borders(Borders::ALL))
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    frame.render_widget(widget, area);
}

fn render_locked(frame: &mut Frame<'_>, view: &LockedView) {
    let area = frame.area();
    let entry_count = view
        .known_entry_count
        .map_or_else(|| "unavailable".to_owned(), |count| count.to_string());
    let lines = vec![
        Line::from("Vault is locked."),
        Line::from(String::new()),
        Line::from(format!("Path: {}", view.vault_path.display())),
        Line::from(format!("Known entry count: {entry_count}")),
        Line::from(String::new()),
        Line::from("Press u to unlock the vault."),
        Line::from("Press r to restore an encrypted backup."),
    ];

    let widget = Paragraph::new(lines)
        .block(Block::default().title("Albus").borders(Borders::ALL))
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    frame.render_widget(widget, area);
}

fn render_unlocked(frame: &mut Frame<'_>, view: &UnlockedView) {
    let area = frame.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(3)])
        .split(area);

    let content = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(outer[0]);

    render_entry_list(frame, content[0], view);
    let vault_path = view.vault_path.display().to_string();
    render_detail(
        frame,
        content[1],
        view.selected_detail.as_ref(),
        &vault_path,
    );

    let help = if view.dirty {
        "Up/Down move  / filter  a add  i import  e edit  d delete  b backup  p passphrase  s save and lock  l lock without saving  q quit"
    } else {
        "Up/Down move  / filter  a add  i import  e edit  d delete  b backup  p passphrase  s lock  l lock without saving  q quit"
    };
    let footer = Paragraph::new(help)
        .block(Block::default().title("Keys").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(footer, outer[1]);
}

fn render_entry_list(frame: &mut Frame<'_>, area: Rect, view: &UnlockedView) {
    let items = if view.entries.is_empty() {
        if view.filter_query.is_some() && view.total_entry_count > 0 {
            vec![ListItem::new("No entries match the current filter")]
        } else {
            vec![ListItem::new("No entries yet")]
        }
    } else {
        view.entries
            .iter()
            .map(|entry| ListItem::new(format!("{} | {}", entry.issuer, entry.account_label)))
            .collect()
    };
    let title = match view.filter_query.as_deref() {
        Some(filter) => format!(
            "Entries ({}/{}) [{filter}]",
            view.visible_entry_count, view.total_entry_count
        ),
        None => format!("Entries ({})", view.total_entry_count),
    };

    let list = List::new(items)
        .block(Block::default().title(title).borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">");
    let mut state = ListState::default();
    state.select(view.selected_index);
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    detail: Option<&EntryDetail>,
    vault_path: &str,
) {
    let lines = match detail {
        Some(detail) => vec![
            Line::from(format!("Vault: {vault_path}")),
            Line::from(String::new()),
            Line::from(format!("Issuer: {}", detail.issuer)),
            Line::from(format!("Account: {}", detail.account_label)),
            Line::from(format!("Algorithm: {}", detail.algorithm.as_otpauth_str())),
            Line::from(format!("Digits: {}", detail.digits)),
            Line::from(format!("Period: {}s", detail.period_secs)),
            Line::from(String::new()),
            Line::from(Span::styled(
                group_code(&detail.code),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(format!("Valid for: {}s", detail.valid_for_secs)),
        ],
        None => vec![
            Line::from(format!("Vault: {vault_path}")),
            Line::from(String::new()),
            Line::from("No entry selected."),
            Line::from(String::new()),
            Line::from("Add an entry with a."),
        ],
    };

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Current Code").borders(Borders::ALL))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_status(frame: &mut Frame<'_>, area: Rect, message: &str) {
    let status_area = Rect {
        x: area.x.saturating_add(2),
        y: area.y.saturating_add(area.height.saturating_sub(5)),
        width: area.width.saturating_sub(4),
        height: 3,
    };
    let paragraph = Paragraph::new(message.to_owned())
        .block(Block::default().title("Status").borders(Borders::ALL))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
    frame.render_widget(Clear, status_area);
    frame.render_widget(paragraph, status_area);
}

fn render_modal(frame: &mut Frame<'_>, modal: &ModalView) {
    let area = centered_rect(70, modal_height(modal), frame.area());
    let lines: Vec<Line<'_>> = modal
        .fields
        .iter()
        .map(field_line)
        .chain([Line::from(String::new()), Line::from(modal.hint.as_str())])
        .collect();

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(modal.title.as_str())
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(Clear, area);
    frame.render_widget(paragraph, area);
}

fn field_line(field: &ModalFieldView) -> Line<'_> {
    let prefix = if field.is_active { "> " } else { "  " };
    let value = if let Some(secret_len) = field.secret_len {
        "*".repeat(secret_len)
    } else {
        field.value.clone()
    };

    Line::from(vec![
        Span::raw(prefix),
        Span::raw(field.label.as_str()),
        Span::raw(": "),
        Span::raw(value),
    ])
}

fn group_code(code: &str) -> String {
    match code.len() {
        6 => format!("{} {}", &code[..3], &code[3..]),
        8 => format!("{} {}", &code[..4], &code[4..]),
        _ => code.to_owned(),
    }
}

fn modal_height(modal: &ModalView) -> u16 {
    let field_count = u16::try_from(modal.fields.len()).unwrap_or(u16::MAX);
    field_count.saturating_add(4)
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Length(height),
            Constraint::Percentage(50),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1]);
    horizontal[1]
}

fn status_message(snapshot: &AppSnapshot) -> Option<&str> {
    match snapshot {
        AppSnapshot::NoVault(view) => view.status_message.as_deref(),
        AppSnapshot::Locked(view) => view.status_message.as_deref(),
        AppSnapshot::Unlocked(view) => view.status_message.as_deref(),
    }
}
