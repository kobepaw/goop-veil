//! Fresnel zone physics — calculates WiFi signal propagation zones, body intersection
//! areas, CSI perturbation estimates, and material attenuation for passive defense.

use pyo3::prelude::*;
use std::f64::consts::PI;

/// Speed of light in m/s.
const C: f64 = 299_792_458.0;

/// WiFi channel center frequencies (MHz) for 2.4 GHz band (channels 1-14).
#[allow(dead_code)]
const WIFI_24GHZ_CHANNELS: &[(u8, f64)] = &[
    (1, 2412.0),
    (2, 2417.0),
    (3, 2422.0),
    (4, 2427.0),
    (5, 2432.0),
    (6, 2437.0),
    (7, 2442.0),
    (8, 2447.0),
    (9, 2452.0),
    (10, 2457.0),
    (11, 2462.0),
    (12, 2467.0),
    (13, 2472.0),
    (14, 2484.0),
];

/// WiFi 5 GHz channel frequencies (common UNII bands).
#[allow(dead_code)]
const WIFI_5GHZ_CHANNELS: &[(u8, f64)] = &[
    (36, 5180.0),
    (40, 5200.0),
    (44, 5220.0),
    (48, 5240.0),
    (52, 5260.0),
    (56, 5280.0),
    (60, 5300.0),
    (64, 5320.0),
    (100, 5500.0),
    (104, 5520.0),
    (108, 5540.0),
    (112, 5560.0),
    (116, 5580.0),
    (120, 5600.0),
    (124, 5620.0),
    (128, 5640.0),
    (132, 5660.0),
    (136, 5680.0),
    (140, 5700.0),
    (149, 5745.0),
    (153, 5765.0),
    (157, 5785.0),
    (161, 5805.0),
    (165, 5825.0),
];

/// Frequency in Hz from channel number (returns None for unknown channels).
#[allow(dead_code)]
pub fn channel_to_freq_hz(channel: u8) -> Option<f64> {
    WIFI_24GHZ_CHANNELS
        .iter()
        .chain(WIFI_5GHZ_CHANNELS.iter())
        .find(|(ch, _)| *ch == channel)
        .map(|(_, freq_mhz)| freq_mhz * 1e6)
}

/// Wavelength in meters for a given frequency in Hz.
fn wavelength(freq_hz: f64) -> f64 {
    C / freq_hz
}

/// Calculate the nth Fresnel zone radius at a point between TX and RX.
///
/// Args:
///     freq_mhz: Frequency in MHz.
///     d_tx_m: Distance from transmitter to the point (meters).
///     d_rx_m: Distance from the point to receiver (meters).
///     n: Fresnel zone number (1 = first zone, typically most important).
///
/// Returns:
///     Fresnel zone radius in meters.
///
/// The first Fresnel zone contains ~50% of the signal energy. Objects within
/// this zone significantly affect CSI. WiFi sensing exploits human body
/// perturbation of Fresnel zones.
#[pyfunction]
pub fn fresnel_radius(freq_mhz: f64, d_tx_m: f64, d_rx_m: f64, n: u32) -> PyResult<f64> {
    if freq_mhz <= 0.0 || d_tx_m <= 0.0 || d_rx_m <= 0.0 || n == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "All parameters must be positive",
        ));
    }

    let freq_hz = freq_mhz * 1e6;
    let lambda = wavelength(freq_hz);
    let d_total = d_tx_m + d_rx_m;

    // Fresnel zone radius: r_n = sqrt(n * lambda * d1 * d2 / (d1 + d2))
    let r = (n as f64 * lambda * d_tx_m * d_rx_m / d_total).sqrt();

    Ok(r)
}

/// Estimate the cross-sectional area where a human body intersects the Fresnel zone.
///
/// Models the body as an elliptical cylinder (torso cross-section).
///
/// Args:
///     fresnel_radius_m: Radius of the Fresnel zone at body position.
///     body_width_m: Body width (default ~0.4m for adult torso).
///     body_depth_m: Body depth (default ~0.25m for adult torso).
///
/// Returns:
///     Intersection area in square meters.
#[pyfunction]
#[pyo3(signature = (fresnel_radius_m, body_width_m=0.4, body_depth_m=0.25))]
pub fn body_intersection_area(
    fresnel_radius_m: f64,
    body_width_m: f64,
    body_depth_m: f64,
) -> PyResult<f64> {
    if fresnel_radius_m <= 0.0 || body_width_m <= 0.0 || body_depth_m <= 0.0 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "All parameters must be positive",
        ));
    }

    // Body ellipse area
    let body_area = PI * (body_width_m / 2.0) * (body_depth_m / 2.0);

    // Fresnel zone circle area
    let fresnel_area = PI * fresnel_radius_m * fresnel_radius_m;

    // If body is smaller than Fresnel zone, intersection is the body area
    // If body is larger, intersection is the Fresnel zone area
    let intersection = body_area.min(fresnel_area);

    Ok(intersection)
}

/// Estimate the CSI perturbation magnitude caused by a body in the Fresnel zone.
///
/// Based on the fraction of the Fresnel zone blocked and material properties
/// of the human body at WiFi frequencies (~70% water, high dielectric constant).
///
/// Args:
///     freq_mhz: Frequency in MHz.
///     d_tx_m: Distance from TX to body.
///     d_rx_m: Distance from body to RX.
///     body_width_m: Body width in meters.
///     body_depth_m: Body depth in meters.
///
/// Returns:
///     Tuple of (amplitude_perturbation_db, phase_perturbation_rad).
///     Amplitude: Reduction in received signal strength (negative dB).
///     Phase: Phase shift introduced by body (radians).
#[pyfunction]
#[pyo3(signature = (freq_mhz, d_tx_m, d_rx_m, body_width_m=0.4, body_depth_m=0.25))]
pub fn csi_perturbation_estimate(
    freq_mhz: f64,
    d_tx_m: f64,
    d_rx_m: f64,
    body_width_m: f64,
    body_depth_m: f64,
) -> PyResult<(f64, f64)> {
    let fz_radius = fresnel_radius(freq_mhz, d_tx_m, d_rx_m, 1)?;
    let intersection = body_intersection_area(fz_radius, body_width_m, body_depth_m)?;
    let fz_area = PI * fz_radius * fz_radius;

    // Fraction of Fresnel zone blocked
    let blocked_fraction = intersection / fz_area;

    // Amplitude perturbation:
    // Human body at 2.4 GHz has ~15-25 dB attenuation for full blockage.
    // Scale linearly with blocked fraction (simplification).
    let body_attenuation_db = 20.0; // Typical for torso at 2.4 GHz
    let amplitude_db = -blocked_fraction * body_attenuation_db;

    // Phase perturbation:
    // Body introduces additional path length and dielectric phase shift.
    // Human tissue has relative permittivity ~50 at 2.4 GHz.
    // Phase shift ≈ blocked_fraction * body_depth * (sqrt(epsilon_r) - 1) * 2π/λ
    let freq_hz = freq_mhz * 1e6;
    let lambda = wavelength(freq_hz);
    let epsilon_r: f64 = 50.0; // Relative permittivity of muscle tissue at 2.4 GHz
    let phase_shift = blocked_fraction
        * body_depth_m
        * (epsilon_r.sqrt() - 1.0)
        * 2.0
        * PI
        / lambda;

    Ok((amplitude_db, phase_shift))
}

/// Calculate material attenuation in dB for a given material and thickness.
///
/// Used for passive defense: recommending materials to place between
/// WiFi transmitters and protected areas to degrade CSI quality.
///
/// Args:
///     material: Material type string.
///     thickness_m: Material thickness in meters.
///     freq_mhz: Frequency in MHz.
///
/// Returns:
///     Attenuation in dB.
#[pyfunction]
#[pyo3(signature = (material, thickness_m, freq_mhz=2437.0))]
pub fn material_attenuation_db(
    material: &str,
    thickness_m: f64,
    freq_mhz: f64,
) -> PyResult<f64> {
    if thickness_m < 0.0 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Thickness must be non-negative",
        ));
    }

    // Attenuation per meter for common building materials at 2.4 GHz.
    // Source: ITU-R P.2040 and published measurement studies.
    let attenuation_per_m = match material.to_lowercase().as_str() {
        "drywall" | "gypsum" | "plasterboard" => 2.5,
        "wood" | "plywood" | "timber" => 3.5,
        "glass" | "window" => 2.0,
        "brick" => 5.0,
        "concrete" | "reinforced_concrete" => 12.0,
        "concrete_block" | "cinder_block" => 8.0,
        "metal" | "steel" | "aluminum" | "aluminium" => 50.0,
        "metal_foil" | "foil" | "aluminum_foil" => 40.0,
        "water" => 15.0, // High dielectric
        "fiberglass" | "insulation" => 1.5,
        "ceramic" | "tile" => 4.0,
        "marble" | "stone" => 6.0,
        "rf_absorber" | "absorber" => 30.0, // Purpose-built RF absorber
        "rf_reflector" | "reflector" => 45.0, // Metallic reflector
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown material: '{}'. Use: drywall, wood, glass, brick, concrete, metal, \
                 metal_foil, water, fiberglass, ceramic, marble, rf_absorber, rf_reflector",
                material
            )));
        }
    };

    // Frequency scaling: attenuation generally increases with frequency
    // Using simplified model: attenuation ∝ sqrt(f/f_ref)
    let freq_factor = (freq_mhz / 2437.0).sqrt();

    Ok(attenuation_per_m * thickness_m * freq_factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresnel_radius_2ghz() {
        // At 2.4 GHz, 5m from TX, 5m from RX → first Fresnel zone radius ~0.55m
        let r = fresnel_radius(2437.0, 5.0, 5.0, 1).unwrap();
        assert!(r > 0.50 && r < 0.60, "Expected ~0.55m, got {}", r);
    }

    #[test]
    fn test_fresnel_radius_5ghz() {
        // At 5 GHz, smaller wavelength → smaller Fresnel zone
        let r_24 = fresnel_radius(2437.0, 5.0, 5.0, 1).unwrap();
        let r_50 = fresnel_radius(5200.0, 5.0, 5.0, 1).unwrap();
        assert!(r_50 < r_24, "5 GHz should have smaller Fresnel zone");
    }

    #[test]
    fn test_fresnel_asymmetric() {
        // Peak at midpoint, smaller near endpoints
        let r_mid = fresnel_radius(2437.0, 5.0, 5.0, 1).unwrap();
        let r_near = fresnel_radius(2437.0, 1.0, 9.0, 1).unwrap();
        assert!(
            r_mid > r_near,
            "Midpoint radius should be larger: {} vs {}",
            r_mid,
            r_near
        );
    }

    #[test]
    fn test_fresnel_invalid() {
        assert!(fresnel_radius(0.0, 5.0, 5.0, 1).is_err());
        assert!(fresnel_radius(2437.0, -1.0, 5.0, 1).is_err());
        assert!(fresnel_radius(2437.0, 5.0, 5.0, 0).is_err());
    }

    #[test]
    fn test_body_intersection() {
        // Fresnel radius 0.4m, body 0.4m x 0.25m
        let area = body_intersection_area(0.4, 0.4, 0.25).unwrap();
        let body_ellipse = PI * 0.2 * 0.125; // ~0.0785 m²
        assert!((area - body_ellipse).abs() < 1e-6);
    }

    #[test]
    fn test_body_larger_than_fresnel() {
        // Tiny Fresnel zone (near endpoint) → Fresnel area limits intersection
        let area = body_intersection_area(0.05, 0.4, 0.25).unwrap();
        let fz_area = PI * 0.05 * 0.05;
        assert!((area - fz_area).abs() < 1e-6);
    }

    #[test]
    fn test_csi_perturbation() {
        let (amp_db, phase_rad) =
            csi_perturbation_estimate(2437.0, 3.0, 3.0, 0.4, 0.25).unwrap();
        // Amplitude should be negative (signal reduction)
        assert!(amp_db < 0.0, "Should reduce signal: {}", amp_db);
        // Phase should be positive (additional path delay)
        assert!(phase_rad > 0.0, "Should shift phase: {}", phase_rad);
    }

    #[test]
    fn test_material_attenuation() {
        let drywall = material_attenuation_db("drywall", 0.013, 2437.0).unwrap();
        let concrete = material_attenuation_db("concrete", 0.15, 2437.0).unwrap();
        let metal = material_attenuation_db("metal", 0.001, 2437.0).unwrap();

        // Concrete >> drywall
        assert!(concrete > drywall);
        // Metal even thin is significant
        assert!(metal > 0.01);

        // Zero thickness = zero attenuation
        assert_eq!(material_attenuation_db("drywall", 0.0, 2437.0).unwrap(), 0.0);
    }

    #[test]
    fn test_material_freq_scaling() {
        let atten_24 = material_attenuation_db("concrete", 0.15, 2437.0).unwrap();
        let atten_50 = material_attenuation_db("concrete", 0.15, 5200.0).unwrap();
        assert!(atten_50 > atten_24, "Higher freq should attenuate more");
    }

    #[test]
    fn test_unknown_material() {
        assert!(material_attenuation_db("unobtanium", 0.1, 2437.0).is_err());
    }

    #[test]
    fn test_channel_to_freq() {
        assert_eq!(channel_to_freq_hz(1), Some(2412e6));
        assert_eq!(channel_to_freq_hz(6), Some(2437e6));
        assert_eq!(channel_to_freq_hz(36), Some(5180e6));
        assert_eq!(channel_to_freq_hz(165), Some(5825e6));
        assert_eq!(channel_to_freq_hz(255), None);
    }
}
