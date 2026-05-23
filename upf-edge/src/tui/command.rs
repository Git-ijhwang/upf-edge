
#[derive(Debug, Clone)]
pub enum UpfCommand {
    ShowSessions,
    ShowSession {seid: u64},
    Clear,
    Help,
    Quit,
}

impl UpfCommand {
    pub fn from_input(input: &str) -> Result<Self, ParseError> {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();

        match parts.as_slice() {
            ["show", "sessions"] | ["session", "list"] => {
                Ok(UpfCommand::ShowSessions)
            }
            ["show", "session", seid] => {
                // let seid = parse_seid(seid)?;
                Ok(UpfCommand::ShowSession{seid: parse_seid(seid)?})
                // Ok(UpeCommand::ShowSession{seid: parse_seid(seid)? })
            }

            ["clear"]              => Ok(UpfCommand::Clear),
            ["help"] | ["?"]       => Ok(UpfCommand::Help),
            ["quit"] | ["exit"] | ["q"] => Ok(UpfCommand::Quit),
            [] => Err(ParseError("빈 명령어".into())),
            _ => Err(ParseError(format!("알 수 없는 명령어: '{}'", input.trim()))),
        }
    }
    pub fn help_text() -> &'static str {
        "
            show sessions          — 전체 세션 목록
            show session <seid>    — 특정 세션 상세 (seid: 0x01 or 1)
            clear                  — 로그 초기화
            help / ?               — 도움말
            quit / q               — 종료
        "
    }
}


fn parse_seid(s: &str) -> Result<u64, ParseError>
{
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| 
            ParseError(format!("Wrong SEID format: {}", s)))
    }
    else {
        s.parse::<u64>()
            .map_err(|_| ParseError(format!("Wrong SEID format: {}", s)))
    }
}


#[derive(Debug)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_show_sessions() {
        assert!(matches!(
            UpfCommand::from_input("show sessions").unwrap(),
            UpfCommand::ShowSessions
        ));
    }

    #[test]
    fn parse_seid_hex() {
        let cmd = UpfCommand::from_input("show session 0x02").unwrap();
        assert!(matches!(cmd, UpfCommand::ShowSession { seid: 2 }));
    }

    #[test]
    fn parse_quit() {
        assert!(matches!(
            UpfCommand::from_input("q")
                .unwrap(),
            UpfCommand::Quit
        ));
    }
}