//! Measures CRC and AP32 decoding with an unchanged fixture, outside process and filesystem costs.
use std::{fs, hint::black_box, path::PathBuf, time::Instant};

fn measure<T>(
    name: &str,
    iterations: usize,
    mut operation: impl FnMut() -> T,
) -> serde_json::Value {
    let mut samples = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        for _ in 0..iterations {
            black_box(operation());
        }
        samples.push(started.elapsed().as_nanos() as f64 / iterations as f64);
    }
    samples.sort_by(f64::total_cmp);
    serde_json::json!({"name":name,"iterations":iterations,"median_ns":samples[2],"samples_ns":samples})
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let data = fs::read(root.join("testdata/upx/pe32.original")).unwrap();
    let ap32 = fs::read(root.join("testdata/aplib/pe32.ap32")).unwrap();
    let measurements = [
        measure("crc32_65kib", 200, || {
            unpack::aplib::crc32(black_box(&data))
        }),
        measure("ap32_65kib", 200, || {
            unpack::aplib::unpack(black_box(&ap32), data.len()).unwrap()
        }),
    ];
    println!("{}", serde_json::to_string_pretty(&measurements).unwrap());
}
