//! Small reproducible benchmarks; no shell startup, filesystem reads or compilation in timed loops.
use std::{fs, hint::black_box, path::PathBuf, time::Instant};

fn main() {
    let iterations: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    assert!(iterations > 0);
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut measurements = Vec::new();
    for (name, file) in [
        ("detect_plain_pe", "pe32.original"),
        ("detect_upx_pe", "pe32.packed"),
    ] {
        let data = fs::read(root.join("testdata/upx").join(file)).unwrap();
        let mut samples = Vec::new();
        for _ in 0..5 {
            let started = Instant::now();
            for _ in 0..iterations {
                black_box(unpack::detect(black_box(&data)).unwrap());
            }
            samples.push(started.elapsed().as_nanos() as f64 / iterations as f64);
        }
        samples.sort_by(f64::total_cmp);
        measurements.push(serde_json::json!({"name":name,"iterations":iterations,"median_ns":samples[2],"samples_ns":samples}));
    }
    println!("{}", serde_json::to_string_pretty(&measurements).unwrap());
}
