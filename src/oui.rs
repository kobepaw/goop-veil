//! OUI (Organizationally Unique Identifier) database for identifying WiFi sensing hardware.
//!
//! Focuses on Espressif (ESP32/ESP8266) which is the primary platform for
//! commodity WiFi sensing systems like RuView.

use pyo3::prelude::*;

/// Known Espressif OUI prefixes (first 3 bytes of MAC address).
/// Source: IEEE OUI registry + Espressif documentation.
const ESPRESSIF_OUIS: &[[u8; 3]] = &[
    [0x24, 0x0A, 0xC4], // Espressif Inc.
    [0x24, 0x62, 0xAB], // Espressif Inc.
    [0x24, 0x6F, 0x28], // Espressif Inc.
    [0x24, 0xB2, 0xDE], // Espressif Inc.
    [0x30, 0xAE, 0xA4], // Espressif Inc.
    [0x3C, 0x61, 0x05], // Espressif Inc.
    [0x3C, 0x71, 0xBF], // Espressif Inc.
    [0x40, 0x22, 0xD8], // Espressif Inc.
    [0x40, 0xF5, 0x20], // Espressif Inc.
    [0x48, 0x3F, 0xDA], // Espressif Inc.
    [0x4C, 0x11, 0xAE], // Espressif Inc.
    [0x54, 0x43, 0xB2], // Espressif Inc.
    [0x58, 0xBF, 0x25], // Espressif Inc.
    [0x5C, 0xCF, 0x7F], // Espressif Inc.
    [0x60, 0x01, 0x94], // Espressif Inc.
    [0x68, 0xC6, 0x3A], // Espressif Inc.
    [0x7C, 0x9E, 0xBD], // Espressif Inc.
    [0x7C, 0xDF, 0xA1], // Espressif Inc.
    [0x84, 0x0D, 0x8E], // Espressif Inc.
    [0x84, 0xCC, 0xA8], // Espressif Inc.
    [0x84, 0xF3, 0xEB], // Espressif Inc.
    [0x8C, 0xAA, 0xB5], // Espressif Inc.
    [0x90, 0x97, 0xD5], // Espressif Inc.
    [0x94, 0x3C, 0xC6], // Espressif Inc.
    [0x94, 0xB5, 0x55], // Espressif Inc.
    [0x94, 0xB9, 0x7E], // Espressif Inc.
    [0x98, 0xCD, 0xAC], // Espressif Inc.
    [0x98, 0xF4, 0xAB], // Espressif Inc.
    [0xA0, 0x20, 0xA6], // Espressif Inc.
    [0xA4, 0xCF, 0x12], // Espressif Inc.
    [0xA4, 0x7B, 0x9D], // Espressif Inc.
    [0xAC, 0x67, 0xB2], // Espressif Inc.
    [0xB4, 0xE6, 0x2D], // Espressif Inc.
    [0xB8, 0xD6, 0x1A], // Espressif Inc.
    [0xBC, 0xDD, 0xC2], // Espressif Inc.
    [0xBC, 0xFF, 0x4D], // Espressif Inc.
    [0xC4, 0x4F, 0x33], // Espressif Inc.
    [0xC4, 0xDD, 0x57], // Espressif Inc.
    [0xC8, 0x2B, 0x96], // Espressif Inc.
    [0xCC, 0x50, 0xE3], // Espressif Inc.
    [0xD8, 0xA0, 0x1D], // Espressif Inc.
    [0xD8, 0xBF, 0xC0], // Espressif Inc.
    [0xDC, 0x4F, 0x22], // Espressif Inc.
    [0xE0, 0x98, 0x06], // Espressif Inc.
    [0xE8, 0xDB, 0x84], // Espressif Inc.
    [0xEC, 0x94, 0xCB], // Espressif Inc.
    [0xF0, 0x08, 0xD1], // Espressif Inc.
    [0xF4, 0xCF, 0xA2], // Espressif Inc.
    [0xFC, 0xF5, 0xC4], // Espressif Inc.
];

/// Other vendors known to ship WiFi sensing hardware.
const SENSING_VENDOR_OUIS: &[([u8; 3], &str)] = &[
    ([0x00, 0x1A, 0x2B], "Qualcomm (CSI-capable chipsets)"),
    ([0x00, 0x03, 0x7F], "Atheros (WiFi sensing research)"),
    ([0x00, 0x0E, 0x8E], "Intel (WiFi sensing research)"),
    ([0xB0, 0x6E, 0xBF], "TP-Link (WiFi sensing routers)"),
    ([0xC0, 0x25, 0x06], "TP-Link (WiFi sensing routers)"),
    ([0xE8, 0x48, 0xB8], "TP-Link (WiFi sensing routers)"),
];

/// Check if a MAC address belongs to Espressif (common in WiFi sensing devices).
#[pyfunction]
pub fn is_espressif_oui(mac: &str) -> PyResult<bool> {
    let oui = parse_mac_prefix(mac)?;
    Ok(ESPRESSIF_OUIS.iter().any(|e| *e == oui))
}

/// Look up the vendor for a MAC address OUI prefix.
/// Returns vendor name or "Unknown".
#[pyfunction]
pub fn lookup_oui(mac: &str) -> PyResult<String> {
    let oui = parse_mac_prefix(mac)?;

    if ESPRESSIF_OUIS.iter().any(|e| *e == oui) {
        return Ok("Espressif".to_string());
    }

    for (prefix, vendor) in SENSING_VENDOR_OUIS {
        if *prefix == oui {
            return Ok(vendor.to_string());
        }
    }

    Ok("Unknown".to_string())
}

/// Parse first 3 bytes from MAC string (colon, dash, or raw hex).
fn parse_mac_prefix(mac: &str) -> PyResult<[u8; 3]> {
    let clean: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() < 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "MAC address too short (need at least 3 bytes)",
        ));
    }

    let b0 = u8::from_str_radix(&clean[0..2], 16)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let b1 = u8::from_str_radix(&clean[2..4], 16)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let b2 = u8::from_str_radix(&clean[4..6], 16)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    Ok([b0, b1, b2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_espressif_known() {
        assert!(is_espressif_oui("24:0A:C4:00:11:22").unwrap());
        assert!(is_espressif_oui("30:AE:A4:FF:FF:FF").unwrap());
        assert!(is_espressif_oui("A4:CF:12:00:00:00").unwrap());
    }

    #[test]
    fn test_espressif_unknown() {
        assert!(!is_espressif_oui("00:11:22:33:44:55").unwrap());
    }

    #[test]
    fn test_lookup_espressif() {
        assert_eq!(lookup_oui("24:0A:C4:00:11:22").unwrap(), "Espressif");
    }

    #[test]
    fn test_lookup_tplink() {
        let result = lookup_oui("B0:6E:BF:00:00:00").unwrap();
        assert!(result.contains("TP-Link"));
    }

    #[test]
    fn test_lookup_unknown() {
        assert_eq!(lookup_oui("00:11:22:33:44:55").unwrap(), "Unknown");
    }

    #[test]
    fn test_dash_format() {
        assert!(is_espressif_oui("24-0A-C4-00-11-22").unwrap());
    }

    #[test]
    fn test_raw_hex() {
        assert!(is_espressif_oui("240AC4001122").unwrap());
    }

    #[test]
    fn test_too_short() {
        assert!(is_espressif_oui("24:0A").is_err());
    }
}
