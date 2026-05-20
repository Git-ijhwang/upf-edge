#[derive(Debug, Clone)]
pub enum Command {
    ShowSessions,
    ShowSession {seid: u64},
    AddSession {count: u32},
    DelSession {seid: u64},
    Heartbeat,
    Clear,
    Help,
    Quit,
}

#[derive(Debug)]
pub struct ParseError(pub String);

impl Command {
    pub fn from_input(input: &str) -> Result<Command, ParseError> {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();

        match parts.as_slice() {
            ["show", "sessions"] | ["session", "list"] => {
                Ok(Command::ShowSessions)
            }

            ["show", "session", seid] => {
                let seid = parse_seid(seid)?;
                Ok(Command::ShowSession{seid})
            }

            ["add", "session"] => {
                Ok(Command::AddSession { count: 1})
            }

            ["add", "session", n] => {
                let count = n.parse::<u32>().map_err(|_| {
                    ParseError(format!("input integer number"))
                })?;
                Ok(Command::AddSession {count})
            }

            ["del", "session", seid] => {
                let seid = parse_seid(seid)?;
                Ok(Command::DelSession {seid})
            }

            ["heartbeat"] | ["hb"] => Ok(Command::Heartbeat),
            ["clear"]              => Ok(Command::Clear),
            ["help"] | ["?"]       => Ok(Command::Help),
            ["quit"] | ["exit"] | ["q"] => Ok(Command::Quit),
            [] => Err(ParseError("빈 명령어".into())),
            _ => Err(ParseError(format!("알 수 없는 명령어: '{}'", input.trim()))),
        }
    }

    /// 도움말 텍스트
    pub fn help_text() -> &'static str {
        "Commands:
            show sessions          — 전체 세션 목록
            show session <seid>    — 특정 세션 상세 (seid: 0x01 or 1)
            add session [N]        — N개 세션 추가 (기본 1)
            del session <seid>     — 세션 삭제
            heartbeat / hb         — Heartbeat 수동 전송
            clear                  — 로그 초기화
            help / ?               — 도움말
            quit / q               — 종료
        "
    }
}

fn parse_seid(s: &str) -> Result<u64, ParseError>
{
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| {
            ParseError(format!("Wrong SEID: {}", s))
        })
    }
    else {
        s.parse::<u64>().map_err(|_|{
            ParseError(format!("Wrong SEID: {}", s))
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_show_sessions() {
        assert!(matches!(
            Command::from_input("show sessions").unwrap(),
            Command::ShowSessions
        ));
        assert!(matches!(
            Command::from_input("session list").unwrap(),
            Command::ShowSessions
        ));
    }

    #[test]
    fn parse_add_session() {
        let cmd = Command::from_input("add session 3").unwrap();
        assert!(matches!(cmd, Command::AddSession { count: 3 }));
    }

    #[test]
    fn parse_seid_hex() {
        let cmd = Command::from_input("del session 0x01").unwrap();
        assert!(matches!(cmd, Command::DelSession { seid: 1 }));
    }

    #[test]
    fn parse_unknown() {
        assert!(Command::from_input("foo bar").is_err());
    }
}