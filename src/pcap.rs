//! pcap file parsing — extracts raw 802.11 frames from pcap/pcapng byte streams.
//!
//! Returns frame bytes + metadata for Python-side classification.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Global pcap header (24 bytes).
const PCAP_MAGIC_LE: u32 = 0xa1b2c3d4;
const PCAP_MAGIC_BE: u32 = 0xd4c3b2a1;
const PCAP_MAGIC_NS_LE: u32 = 0xa1b23c4d;
const PCAP_MAGIC_NS_BE: u32 = 0x4d3cb2a1;
const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;

/// DLT types for 802.11
const DLT_IEEE802_11: u32 = 105;
const DLT_IEEE802_11_RADIOTAP: u32 = 127;
const DLT_IEEE802_11_PRISM: u32 = 119;

/// Pure-Rust pcap parser — returns Vec of (timestamp_us, frame_bytes).
/// No Python dependency, testable with `cargo test`.
fn parse_pcap_internal(data: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    if data.len() < PCAP_GLOBAL_HEADER_LEN {
        return Err("Data too short for pcap global header".to_string());
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (swap, nanosecond) = match magic {
        PCAP_MAGIC_LE => (false, false),
        PCAP_MAGIC_BE => (true, false),
        PCAP_MAGIC_NS_LE => (false, true),
        PCAP_MAGIC_NS_BE => (true, true),
        _ => return Err("Not a valid pcap file (bad magic number)".to_string()),
    };

    let read_u32 = |offset: usize| -> u32 {
        let bytes = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
        if swap {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    };

    let link_type = read_u32(20);
    let radiotap = match link_type {
        DLT_IEEE802_11 => false,
        DLT_IEEE802_11_RADIOTAP => true,
        DLT_IEEE802_11_PRISM => false,
        _ => return Err(format!("Unsupported link type: {} (expected 802.11)", link_type)),
    };

    let mut frames = Vec::new();
    let mut offset = PCAP_GLOBAL_HEADER_LEN;

    while offset + PCAP_RECORD_HEADER_LEN <= data.len() {
        let ts_sec = read_u32(offset) as u64;
        let ts_frac = read_u32(offset + 4) as u64;
        let incl_len = read_u32(offset + 8) as usize;
        let _orig_len = read_u32(offset + 12);

        let timestamp_us = if nanosecond {
            ts_sec * 1_000_000 + ts_frac / 1000
        } else {
            ts_sec * 1_000_000 + ts_frac
        };

        offset += PCAP_RECORD_HEADER_LEN;

        if offset + incl_len > data.len() {
            break;
        }

        let frame_bytes = &data[offset..offset + incl_len];

        let wifi_bytes = if radiotap && frame_bytes.len() >= 4 {
            let rt_len = u16::from_le_bytes([frame_bytes[2], frame_bytes[3]]) as usize;
            if rt_len <= frame_bytes.len() {
                &frame_bytes[rt_len..]
            } else {
                frame_bytes
            }
        } else {
            frame_bytes
        };

        if !wifi_bytes.is_empty() {
            frames.push((timestamp_us, wifi_bytes.to_vec()));
        }

        offset += incl_len;
    }

    Ok(frames)
}

/// Parse pcap bytes and return list of (timestamp_us, frame_bytes) tuples.
/// Python-facing wrapper that converts to PyBytes.
#[pyfunction]
pub fn parse_pcap_bytes<'py>(
    py: Python<'py>,
    data: &[u8],
) -> PyResult<Vec<(u64, Bound<'py, PyBytes>)>> {
    let frames = parse_pcap_internal(data)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;

    if frames.len() > 10000 {
        py.check_signals()?;
    }

    Ok(frames
        .into_iter()
        .map(|(ts, bytes)| (ts, PyBytes::new_bound(py, &bytes)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pcap_header(link_type: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&65535u32.to_le_bytes());
        buf.extend_from_slice(&link_type.to_le_bytes());
        buf
    }

    fn append_packet(buf: &mut Vec<u8>, ts_sec: u32, ts_usec: u32, data: &[u8]) {
        buf.extend_from_slice(&ts_sec.to_le_bytes());
        buf.extend_from_slice(&ts_usec.to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }

    #[test]
    fn test_too_short() {
        let result = parse_pcap_internal(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_bad_magic() {
        let result = parse_pcap_internal(&[0u8; 24]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_single_frame() {
        let mut buf = make_pcap_header(DLT_IEEE802_11);
        let frame = vec![0x80, 0x00, 0x00, 0x00];
        append_packet(&mut buf, 1000, 500000, &frame);

        let frames = parse_pcap_internal(&buf).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, 1000_500_000u64);
        assert_eq!(frames[0].1, vec![0x80, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_parse_multiple_frames() {
        let mut buf = make_pcap_header(DLT_IEEE802_11);
        for i in 0..100u32 {
            let frame = vec![0x80, 0x00, i as u8, 0x00];
            append_packet(&mut buf, i, 0, &frame);
        }

        let frames = parse_pcap_internal(&buf).unwrap();
        assert_eq!(frames.len(), 100);
    }

    #[test]
    fn test_radiotap_stripping() {
        let mut buf = make_pcap_header(DLT_IEEE802_11_RADIOTAP);
        let mut frame = vec![0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        frame.extend_from_slice(&[0x80, 0x00, 0xAA, 0xBB]);

        append_packet(&mut buf, 1, 0, &frame);

        let frames = parse_pcap_internal(&buf).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].1.len(), 4);
        assert_eq!(frames[0].1[0], 0x80);
    }

    #[test]
    fn test_unsupported_link_type() {
        let buf = make_pcap_header(1); // DLT_EN10MB
        let result = parse_pcap_internal(&buf);
        assert!(result.is_err());
    }
}
