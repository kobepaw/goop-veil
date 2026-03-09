//! Signal processing — FFT, spectral analysis, and periodic signal detection
//! for CSI (Channel State Information) analysis.

use pyo3::prelude::*;
use rustfft::{num_complex::Complex, FftPlanner};
use std::f64::consts::PI;

/// Compute FFT magnitudes from a real-valued signal.
/// Returns magnitude spectrum (first N/2+1 bins, single-sided).
#[pyfunction]
pub fn compute_fft_magnitudes(signal: Vec<f64>) -> PyResult<Vec<f64>> {
    let n = signal.len();
    if n == 0 {
        return Ok(vec![]);
    }

    let mut planner = FftPlanner::<f64>::new();
    let fft = planner.plan_fft_forward(n);

    let mut buffer: Vec<Complex<f64>> = signal
        .iter()
        .map(|&s| Complex::new(s, 0.0))
        .collect();

    fft.process(&mut buffer);

    // Return single-sided magnitude spectrum
    let half = n / 2 + 1;
    let magnitudes: Vec<f64> = buffer[..half]
        .iter()
        .map(|c| c.norm() / n as f64)
        .collect();

    Ok(magnitudes)
}

/// Extract CSI features from amplitude and phase arrays.
///
/// Returns a dict-like tuple of:
/// (mean_amplitude, std_amplitude, mean_phase, std_phase, amplitude_range, dominant_freq_bin)
#[pyfunction]
pub fn compute_csi_features(
    amplitudes: Vec<f64>,
    phases: Vec<f64>,
    sample_rate_hz: f64,
) -> PyResult<(f64, f64, f64, f64, f64, f64)> {
    if amplitudes.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Empty amplitude array",
        ));
    }

    let n = amplitudes.len() as f64;

    // Amplitude statistics
    let mean_amp = amplitudes.iter().sum::<f64>() / n;
    let var_amp = amplitudes.iter().map(|a| (a - mean_amp).powi(2)).sum::<f64>() / n;
    let std_amp = var_amp.sqrt();
    let amp_min = amplitudes.iter().cloned().fold(f64::INFINITY, f64::min);
    let amp_max = amplitudes.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let amp_range = amp_max - amp_min;

    // Phase statistics
    let mean_phase = if phases.is_empty() {
        0.0
    } else {
        phases.iter().sum::<f64>() / phases.len() as f64
    };
    let std_phase = if phases.len() < 2 {
        0.0
    } else {
        let var = phases
            .iter()
            .map(|p| (p - mean_phase).powi(2))
            .sum::<f64>()
            / phases.len() as f64;
        var.sqrt()
    };

    // Find dominant frequency via FFT of amplitudes
    let dominant_freq = if amplitudes.len() >= 4 {
        // Remove DC (mean) before FFT
        let detrended: Vec<f64> = amplitudes.iter().map(|a| a - mean_amp).collect();

        let mut planner = FftPlanner::<f64>::new();
        let fft = planner.plan_fft_forward(detrended.len());
        let mut buffer: Vec<Complex<f64>> = detrended
            .iter()
            .map(|&s| Complex::new(s, 0.0))
            .collect();
        fft.process(&mut buffer);

        let half = buffer.len() / 2;
        // Skip bin 0 (DC)
        let (max_bin, _) = buffer[1..=half]
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.norm().partial_cmp(&b.norm()).unwrap())
            .unwrap_or((0, &Complex::new(0.0, 0.0)));

        let bin_idx = max_bin + 1; // +1 because we skipped bin 0
        let freq_resolution = sample_rate_hz / amplitudes.len() as f64;
        bin_idx as f64 * freq_resolution
    } else {
        0.0
    };

    Ok((mean_amp, std_amp, mean_phase, std_phase, amp_range, dominant_freq))
}

/// Detect periodic signals in CSI data that indicate human activity sensing.
///
/// WiFi sensing systems exploit periodic CSI variations caused by:
/// - Breathing: 0.15-0.5 Hz (9-30 breaths/min)
/// - Heartbeat: 0.8-2.0 Hz (48-120 bpm)
/// - Walking: 0.5-2.0 Hz (step frequency)
/// - Gestures: 1.0-5.0 Hz
///
/// Returns list of (frequency_hz, magnitude, label) for detected periodic components.
#[pyfunction]
pub fn detect_periodic_signal(
    amplitudes: Vec<f64>,
    sample_rate_hz: f64,
    min_snr_db: f64,
) -> PyResult<Vec<(f64, f64, String)>> {
    if amplitudes.len() < 8 {
        return Ok(vec![]);
    }

    let n = amplitudes.len();
    let mean = amplitudes.iter().sum::<f64>() / n as f64;

    // Apply Hanning window + detrend
    let windowed: Vec<f64> = amplitudes
        .iter()
        .enumerate()
        .map(|(i, &a)| {
            let w = 0.5 * (1.0 - (2.0 * PI * i as f64 / (n - 1) as f64).cos());
            (a - mean) * w
        })
        .collect();

    // FFT
    let mut planner = FftPlanner::<f64>::new();
    let fft = planner.plan_fft_forward(n);
    let mut buffer: Vec<Complex<f64>> = windowed
        .iter()
        .map(|&s| Complex::new(s, 0.0))
        .collect();
    fft.process(&mut buffer);

    let half = n / 2;
    let freq_resolution = sample_rate_hz / n as f64;

    // Compute power spectrum
    let power: Vec<f64> = buffer[..=half].iter().map(|c| c.norm_sqr()).collect();

    // Noise floor (median of power spectrum)
    let mut sorted_power = power.clone();
    sorted_power.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let noise_floor = sorted_power[sorted_power.len() / 2].max(1e-15);

    // Frequency bands of interest for human activity
    let bands = [
        (0.10, 0.55, "breathing"),
        (0.75, 2.10, "heartbeat"),
        (0.45, 2.10, "walking"),
        (0.80, 5.50, "gesture"),
    ];

    let mut detections = Vec::new();

    for (lo, hi, label) in &bands {
        let bin_lo = (*lo / freq_resolution).ceil() as usize;
        let bin_hi = (*hi / freq_resolution).floor() as usize;

        if bin_lo >= half || bin_hi >= half || bin_lo > bin_hi {
            continue;
        }

        // Find peak in this band
        let (peak_bin, peak_power) = power[bin_lo..=bin_hi.min(half)]
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .map(|(i, &p)| (i + bin_lo, p))
            .unwrap_or((0, 0.0));

        if peak_power <= 0.0 {
            continue;
        }

        let snr_db = 10.0 * (peak_power / noise_floor).log10();

        if snr_db >= min_snr_db {
            let freq = peak_bin as f64 * freq_resolution;
            let magnitude = peak_power.sqrt();
            detections.push((freq, magnitude, label.to_string()));
        }
    }

    // Deduplicate overlapping detections (keep highest magnitude)
    detections.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    let mut seen_bins: Vec<usize> = Vec::new();
    let mut unique = Vec::new();
    for (freq, mag, label) in detections {
        let bin = (freq / freq_resolution).round() as usize;
        if !seen_bins.iter().any(|&b| (b as i64 - bin as i64).unsigned_abs() < 3) {
            seen_bins.push(bin);
            unique.push((freq, mag, label));
        }
    }

    Ok(unique)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fft_empty() {
        let result = compute_fft_magnitudes(vec![]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_fft_dc() {
        let signal = vec![1.0; 64];
        let mags = compute_fft_magnitudes(signal).unwrap();
        assert!(mags[0] > 0.9); // DC component
        // All other bins should be near zero
        for mag in &mags[1..] {
            assert!(*mag < 1e-10);
        }
    }

    #[test]
    fn test_fft_sine() {
        let n = 256;
        let freq = 10.0;
        let sample_rate = 256.0;
        let signal: Vec<f64> = (0..n)
            .map(|i| (2.0 * PI * freq * i as f64 / sample_rate).sin())
            .collect();

        let mags = compute_fft_magnitudes(signal).unwrap();
        // Peak should be at bin 10
        let peak_bin = mags[1..]
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .unwrap()
            .0
            + 1;
        assert_eq!(peak_bin, 10);
    }

    #[test]
    fn test_csi_features_basic() {
        let amps = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let phases = vec![0.1, 0.2, 0.15, 0.25, 0.1, 0.2, 0.15, 0.25];
        let (mean_a, std_a, mean_p, std_p, range_a, _) =
            compute_csi_features(amps, phases, 100.0).unwrap();

        assert!((mean_a - 4.5).abs() < 1e-10);
        assert!(std_a > 0.0);
        assert!(mean_p > 0.0);
        assert!(std_p > 0.0);
        assert!((range_a - 7.0).abs() < 1e-10);
    }

    #[test]
    fn test_detect_breathing_signal() {
        // Simulate 0.25 Hz breathing signal (15 breaths/min) sampled at 10 Hz
        let sample_rate = 10.0;
        let n = 512;
        let breathing_freq = 0.25;
        let signal: Vec<f64> = (0..n)
            .map(|i| {
                let t = i as f64 / sample_rate;
                // Strong breathing component + noise
                5.0 * (2.0 * PI * breathing_freq * t).sin() + 0.1 * (i as f64 * 0.1).sin()
            })
            .collect();

        let detections = detect_periodic_signal(signal, sample_rate, 3.0).unwrap();
        // Should detect a breathing-band signal
        let has_breathing = detections.iter().any(|(_, _, label)| label == "breathing");
        assert!(
            has_breathing,
            "Should detect breathing signal, got: {:?}",
            detections
        );
    }

    #[test]
    fn test_detect_no_signal_in_noise() {
        // Pure random-ish signal with no periodicity
        let signal: Vec<f64> = (0..256)
            .map(|i| ((i * 7 + 13) % 100) as f64 / 100.0)
            .collect();

        let detections = detect_periodic_signal(signal, 10.0, 30.0).unwrap();
        // With very high SNR threshold, noise shouldn't trigger
        assert!(
            detections.is_empty(),
            "Should not detect signals in noise: {:?}",
            detections
        );
    }

    #[test]
    fn test_detect_short_signal() {
        let signal = vec![1.0, 2.0, 3.0];
        let detections = detect_periodic_signal(signal, 10.0, 3.0).unwrap();
        assert!(detections.is_empty());
    }
}
