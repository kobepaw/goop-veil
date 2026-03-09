//! 802.11 frame classification — parses frame control, addresses, and management fields.

use pyo3::prelude::*;

/// Frame type constants (from frame control field bits 2-3).
const FRAME_TYPE_MANAGEMENT: u8 = 0;
const FRAME_TYPE_CONTROL: u8 = 1;
const FRAME_TYPE_DATA: u8 = 2;

/// Management frame subtypes (bits 4-7).
const SUBTYPE_BEACON: u8 = 8;
const SUBTYPE_PROBE_REQ: u8 = 4;
const SUBTYPE_PROBE_RESP: u8 = 5;
const SUBTYPE_AUTH: u8 = 11;
const SUBTYPE_DEAUTH: u8 = 12;
const SUBTYPE_ACTION: u8 = 13;

/// Data frame subtypes.
const SUBTYPE_NULL: u8 = 4;
const SUBTYPE_QOS_DATA: u8 = 8;

/// Minimum 802.11 frame: FC(2) + Duration(2) + Addr1(6) = 10 bytes.
const MIN_FRAME_LEN: usize = 10;

/// Parsed 802.11 frame information exposed to Python.
#[pyclass]
#[derive(Debug, Clone)]
pub struct FrameInfo {
    #[pyo3(get)]
    pub frame_type: String,
    #[pyo3(get)]
    pub subtype: String,
    #[pyo3(get)]
    pub type_num: u8,
    #[pyo3(get)]
    pub subtype_num: u8,
    #[pyo3(get)]
    pub addr1: String,
    #[pyo3(get)]
    pub addr2: Option<String>,
    #[pyo3(get)]
    pub addr3: Option<String>,
    #[pyo3(get)]
    pub is_beacon: bool,
    #[pyo3(get)]
    pub is_probe_request: bool,
    #[pyo3(get)]
    pub is_probe_response: bool,
    #[pyo3(get)]
    pub is_data: bool,
    #[pyo3(get)]
    pub is_action: bool,
    #[pyo3(get)]
    pub ssid: Option<String>,
    #[pyo3(get)]
    pub frame_length: usize,
}

fn format_mac(bytes: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

fn type_name(t: u8) -> &'static str {
    match t {
        FRAME_TYPE_MANAGEMENT => "management",
        FRAME_TYPE_CONTROL => "control",
        FRAME_TYPE_DATA => "data",
        _ => "unknown",
    }
}

fn subtype_name(frame_type: u8, subtype: u8) -> &'static str {
    match (frame_type, subtype) {
        (FRAME_TYPE_MANAGEMENT, SUBTYPE_BEACON) => "beacon",
        (FRAME_TYPE_MANAGEMENT, SUBTYPE_PROBE_REQ) => "probe_request",
        (FRAME_TYPE_MANAGEMENT, SUBTYPE_PROBE_RESP) => "probe_response",
        (FRAME_TYPE_MANAGEMENT, SUBTYPE_AUTH) => "authentication",
        (FRAME_TYPE_MANAGEMENT, SUBTYPE_DEAUTH) => "deauthentication",
        (FRAME_TYPE_MANAGEMENT, SUBTYPE_ACTION) => "action",
        (FRAME_TYPE_MANAGEMENT, 0) => "association_request",
        (FRAME_TYPE_MANAGEMENT, 1) => "association_response",
        (FRAME_TYPE_MANAGEMENT, 2) => "reassociation_request",
        (FRAME_TYPE_MANAGEMENT, 3) => "reassociation_response",
        (FRAME_TYPE_MANAGEMENT, 10) => "disassociation",
        (FRAME_TYPE_CONTROL, 11) => "rts",
        (FRAME_TYPE_CONTROL, 12) => "cts",
        (FRAME_TYPE_CONTROL, 13) => "ack",
        (FRAME_TYPE_DATA, SUBTYPE_NULL) => "null",
        (FRAME_TYPE_DATA, SUBTYPE_QOS_DATA) => "qos_data",
        (FRAME_TYPE_DATA, 0) => "data",
        _ => "other",
    }
}

/// Extract SSID from beacon/probe management frame body.
/// Management frame body starts after fixed fields (timestamp(8) + interval(2) + capability(2) = 12).
fn extract_ssid(frame: &[u8], subtype: u8) -> Option<String> {
    if subtype != SUBTYPE_BEACON
        && subtype != SUBTYPE_PROBE_REQ
        && subtype != SUBTYPE_PROBE_RESP
    {
        return None;
    }

    // Management frame: FC(2) + Dur(2) + Addr1(6) + Addr2(6) + Addr3(6) + SeqCtl(2) = 24
    let body_offset = if subtype == SUBTYPE_PROBE_REQ {
        24 // Probe request has no fixed fields before tagged params
    } else {
        24 + 12 // Beacon/probe response: 12 bytes of fixed fields
    };

    if frame.len() <= body_offset {
        return None;
    }

    // Parse tagged parameters looking for SSID (tag 0)
    let mut pos = body_offset;
    while pos + 2 <= frame.len() {
        let tag_id = frame[pos];
        let tag_len = frame[pos + 1] as usize;
        pos += 2;

        if pos + tag_len > frame.len() {
            break;
        }

        if tag_id == 0 {
            // SSID tag
            if tag_len == 0 {
                return Some(String::new()); // Hidden SSID
            }
            return Some(String::from_utf8_lossy(&frame[pos..pos + tag_len]).to_string());
        }

        pos += tag_len;
    }

    None
}

/// Parse a single raw 802.11 frame into a FrameInfo.
#[pyfunction]
pub fn parse_raw_frame(data: &[u8]) -> PyResult<FrameInfo> {
    if data.len() < MIN_FRAME_LEN {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Frame too short for 802.11",
        ));
    }

    let fc0 = data[0];
    let frame_type = (fc0 >> 2) & 0x03;
    let subtype = (fc0 >> 4) & 0x0f;

    let addr1 = format_mac(&data[4..10]);

    // Address 2 present in most management and data frames (not in some control frames)
    let addr2 = if data.len() >= 16 && frame_type != FRAME_TYPE_CONTROL {
        Some(format_mac(&data[10..16]))
    } else {
        None
    };

    // Address 3 present in management and data frames
    let addr3 = if data.len() >= 22 && frame_type != FRAME_TYPE_CONTROL {
        Some(format_mac(&data[16..22]))
    } else {
        None
    };

    let ssid = extract_ssid(data, subtype);

    Ok(FrameInfo {
        frame_type: type_name(frame_type).to_string(),
        subtype: subtype_name(frame_type, subtype).to_string(),
        type_num: frame_type,
        subtype_num: subtype,
        addr1,
        addr2,
        addr3,
        is_beacon: frame_type == FRAME_TYPE_MANAGEMENT && subtype == SUBTYPE_BEACON,
        is_probe_request: frame_type == FRAME_TYPE_MANAGEMENT && subtype == SUBTYPE_PROBE_REQ,
        is_probe_response: frame_type == FRAME_TYPE_MANAGEMENT && subtype == SUBTYPE_PROBE_RESP,
        is_data: frame_type == FRAME_TYPE_DATA,
        is_action: frame_type == FRAME_TYPE_MANAGEMENT && subtype == SUBTYPE_ACTION,
        ssid,
        frame_length: data.len(),
    })
}

/// Classify a batch of raw frame bytes into FrameInfo objects.
/// Skips frames that are too short rather than erroring.
#[pyfunction]
pub fn classify_frames(frames: Vec<Vec<u8>>) -> Vec<FrameInfo> {
    frames
        .iter()
        .filter_map(|data| {
            if data.len() < MIN_FRAME_LEN {
                return None;
            }
            parse_raw_frame(data).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_beacon(ssid: &str) -> Vec<u8> {
        // FC: type=0 (mgmt), subtype=8 (beacon) → 0x80, 0x00
        let mut frame = vec![0x80, 0x00];
        // Duration
        frame.extend_from_slice(&[0x00, 0x00]);
        // Addr1 (destination, broadcast)
        frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Addr2 (source)
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        // Addr3 (BSSID)
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        // Sequence control
        frame.extend_from_slice(&[0x00, 0x00]);
        // Fixed params: Timestamp(8) + Interval(2) + Capability(2)
        frame.extend_from_slice(&[0; 12]);
        // Tagged: SSID (tag=0, len, data)
        frame.push(0x00); // Tag ID: SSID
        frame.push(ssid.len() as u8);
        frame.extend_from_slice(ssid.as_bytes());
        frame
    }

    #[test]
    fn test_parse_beacon() {
        let frame = make_beacon("TestNetwork");
        let info = parse_raw_frame(&frame).unwrap();
        assert_eq!(info.frame_type, "management");
        assert_eq!(info.subtype, "beacon");
        assert!(info.is_beacon);
        assert!(!info.is_data);
        assert_eq!(info.ssid, Some("TestNetwork".to_string()));
        assert_eq!(info.addr1, "ff:ff:ff:ff:ff:ff");
        assert_eq!(info.addr2, Some("aa:bb:cc:dd:ee:01".to_string()));
    }

    #[test]
    fn test_parse_data_frame() {
        // FC: type=2 (data), subtype=0 → 0x08, 0x00
        let mut frame = vec![0x08, 0x00];
        frame.extend_from_slice(&[0x00, 0x00]); // Duration
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // Addr1
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]); // Addr2
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]); // Addr3

        let info = parse_raw_frame(&frame).unwrap();
        assert_eq!(info.frame_type, "data");
        assert!(info.is_data);
        assert!(!info.is_beacon);
        assert_eq!(info.ssid, None);
    }

    #[test]
    fn test_too_short() {
        let frame = vec![0x80, 0x00, 0x00];
        assert!(parse_raw_frame(&frame).is_err());
    }

    #[test]
    fn test_classify_batch_skips_short() {
        let good = make_beacon("OK");
        let short = vec![0x80u8, 0x00, 0x00];
        let frames: Vec<Vec<u8>> = vec![good.clone(), short.clone()];
        let results = classify_frames(frames);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ssid, Some("OK".to_string()));
    }

    #[test]
    fn test_hidden_ssid() {
        let frame = make_beacon("");
        let info = parse_raw_frame(&frame).unwrap();
        assert_eq!(info.ssid, Some(String::new()));
    }

    #[test]
    fn test_probe_request() {
        // FC: type=0 (mgmt), subtype=4 (probe req) → 0x40, 0x00
        let mut frame = vec![0x40, 0x00];
        frame.extend_from_slice(&[0x00, 0x00]); // Duration
        frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // Addr1
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]); // Addr2
        frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // Addr3
        frame.extend_from_slice(&[0x00, 0x00]); // Seq ctrl
        // SSID tag (no fixed fields for probe request)
        frame.push(0x00); // Tag: SSID
        frame.push(4);
        frame.extend_from_slice(b"Test");

        let info = parse_raw_frame(&frame).unwrap();
        assert!(info.is_probe_request);
        assert_eq!(info.ssid, Some("Test".to_string()));
    }
}
