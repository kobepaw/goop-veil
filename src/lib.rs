use pyo3::prelude::*;

mod frames;
mod fresnel;
mod oui;
mod pcap;
mod signal;

/// goop-veil Rust core — high-performance WiFi frame parsing, signal processing,
/// and Fresnel zone physics for WiFi privacy defense.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Version
    m.add("__version__", "0.1.0")?;

    // pcap parsing
    m.add_function(wrap_pyfunction!(pcap::parse_pcap_bytes, m)?)?;

    // Frame classification
    m.add_class::<frames::FrameInfo>()?;
    m.add_function(wrap_pyfunction!(frames::classify_frames, m)?)?;
    m.add_function(wrap_pyfunction!(frames::parse_raw_frame, m)?)?;

    // OUI database
    m.add_function(wrap_pyfunction!(oui::is_espressif_oui, m)?)?;
    m.add_function(wrap_pyfunction!(oui::lookup_oui, m)?)?;

    // Signal processing
    m.add_function(wrap_pyfunction!(signal::compute_fft_magnitudes, m)?)?;
    m.add_function(wrap_pyfunction!(signal::compute_csi_features, m)?)?;
    m.add_function(wrap_pyfunction!(signal::detect_periodic_signal, m)?)?;

    // Fresnel zone physics
    m.add_function(wrap_pyfunction!(fresnel::fresnel_radius, m)?)?;
    m.add_function(wrap_pyfunction!(fresnel::body_intersection_area, m)?)?;
    m.add_function(wrap_pyfunction!(fresnel::csi_perturbation_estimate, m)?)?;
    m.add_function(wrap_pyfunction!(fresnel::material_attenuation_db, m)?)?;

    Ok(())
}
