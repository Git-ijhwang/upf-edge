pub const PFCP_S_FLAG: u8  = 0b00000001;
pub const PFCP_MP_FLAG: u8 = 0b00000010;
pub const PFCP_FO_FLAG: u8 = 0b00000100;
const PFCP_VERSION: u8     = 1;


#[derive(Clone, Debug)]
pub struct PfcpHeader {
    pub version:    u8,     // Version (3 bits) + Spare (2 bits) + FO flag (1 bit) + MP flag (1 bit) + S flag (1 bit)
    pub s_flag:     bool,
    pub mp_flag:    bool,
    pub fo_flag:    bool,
    pub msg_type:   u8,     // Message type (8 bits)
    pub length:     u16,    // Message length (16 bits)
    pub seid:       Option<u64>, // SEID (64 bits)
    pub seq_num:    u32,    // Sequence number (24 bits)
    pub priority:   u8,     // Message Priority (4 bits)
}


impl PfcpHeader {
    pub fn new(&self) -> Self {
        PfcpHeader {
            version:    PFCP_VERSION,
            s_flag:     false,
            mp_flag:    false,
            fo_flag:    false,
            msg_type:   0,
            length:     0,
            seid:       None,
            seq_num:    0,
            priority:   0,
        }
    }

    pub fn new_node_msg(msg_type: u8, seq_num: u32) -> Self {
        PfcpHeader {
            version:    PFCP_VERSION,
            s_flag:     false,
            mp_flag:    false,
            fo_flag:    false,
            msg_type,
            length:     0,
            seid:       None,
            seq_num,
            priority:   0,
        }
    }

    pub fn new_session_msg(msg_type: u8, seid: u64, seq_num: u32) -> Self {
        PfcpHeader {
            version:    PFCP_VERSION,
            s_flag:     true,
            mp_flag:    false,
            fo_flag:    false,
            msg_type,
            length:     0,
            seid:       Some(seid),
            seq_num,
            priority:   0,
        }
    }

    pub fn header_len(&self) -> usize {
        if self.s_flag { 16 } else { 8 }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);

        let mut flags: u8 = (self.version & 0x07) << 5;

        if self.fo_flag { flags |= PFCP_FO_FLAG; }
        if self.mp_flag { flags |= PFCP_MP_FLAG; }
        if self.s_flag { flags |= PFCP_S_FLAG; }

        buf.push(flags);

        buf.push(self.msg_type);

        buf.extend_from_slice(&self.length.to_be_bytes());

        if self.s_flag {
            buf.extend_from_slice(&self.seid.unwrap_or(0).to_be_bytes());
        }

        buf.push((self.seq_num >> 16) as u8);
        buf.push((self.seq_num >> 8) as u8);
        buf.push(self.seq_num as u8);
        buf.push(
            if self.mp_flag { self.priority << 4 } else { 0 }
        );

        buf
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), PfcpError> {
        if buf.len() < 8 {
            return Err(PfcpError::BufferTooShort {need: 8, have: buf.len() });
        }

        let mut pos: usize = 0;

        let flags = buf[pos];
        let version = flags >> 5;
        if version != PFCP_VERSION {
            return Err(PfcpError::UnsupportedVersion(version));
        }

        let s_flag: bool = (flags & PFCP_S_FLAG) != 0;
        let mp_flag: bool = (flags & PFCP_MP_FLAG) != 0;
        let fo_flag: bool = (flags & PFCP_FO_FLAG) != 0;
        pos += 1;

        let msg_type = buf[pos];
        pos += 1;

        let length = u16::from_be_bytes([buf[pos], buf[pos+1]]);
        pos += 2;

        let seid = if s_flag {
            if buf.len() < 16 {
                return Err(PfcpError::BufferTooShort { need: 16, have: buf.len() });
            }

            let seid = u64::from_be_bytes([
                buf[pos],   buf[pos+1], buf[pos+2], buf[pos+3],
                buf[pos+4], buf[pos+5], buf[pos+6], buf[pos+7]
            ]);
            pos += 8;

            Some(seid)
        } else {
            None
        };

        let seq_num = u32::from_be_bytes([0, buf[pos], buf[pos+1], buf[pos+2]]);
        pos += 3; //Length of Sequence Number field

        let priority = if mp_flag  { buf[pos] >> 4 } else { 0 };
        pos += 1;

        let header = PfcpHeader {
            version, s_flag, mp_flag, fo_flag, msg_type,
            length, seid, seq_num, priority,
        };

        Ok((header, &buf[pos..]))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PfcpError {
    #[error("Buffer too short: need {need}, have {have}")]
    BufferTooShort {need: usize, have: usize},

    #[error("Unsupported PFCP version: {0}")]
    UnsupportedVersion(u8),

    #[error("IE {ie_type} parse error: {reason}")]
    IeParseError { ie_type: u16, reason: String },

    #[error("session {0} not found")]
    SessionNotFound(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_header_roundtrip() {
        let hdr = PfcpHeader::new_node_msg(1, 42);
        let bytes = hdr.encode();
        assert_eq!(bytes.len(), 8);

        let (decoded, body) = PfcpHeader::decode(&bytes).unwrap();
        assert_eq!(decoded.version, 1);
        assert!(!decoded.s_flag);
        assert_eq!(decoded.msg_type, 1);
        assert_eq!(decoded.seq_num, 42);
        assert!(decoded.seid.is_none());
        assert_eq!(body.len(), 0);
    }

    #[test]
    fn session_header_roundtrip() {
        let hdr = PfcpHeader::new_session_msg(50, 0xDEADBEEF, 99);
        let bytes = hdr.encode();
        assert_eq!(bytes.len(), 16);

        let (decoded, body) = PfcpHeader::decode(&bytes).unwrap();
        assert!(decoded.s_flag);
        assert_eq!(decoded.msg_type, 50);
        assert_eq!(decoded.seid, Some(0xDEADBEEF));
        assert_eq!(decoded.seq_num, 99);
    }

    #[test]
    fn too_short_buffer() {
        let buf = [0x20, 0x01, 0x00];
        assert!(PfcpHeader::decode(&buf).is_err());
    }
}