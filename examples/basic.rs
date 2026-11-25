use unpack::{Options, unpack_path};

fn main() -> unpack::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| unpack::Error::invalid("usage: cargo run --example basic -- FILE"))?;
    let result = unpack_path(path, &Options::default())?;
    for layer in result.history {
        println!(
            "Layer {}: {} ({:?})",
            layer.layer, layer.packer_name, layer.support
        );
    }
    for warning in result.warnings {
        eprintln!("Warning: {warning}");
    }
    println!("Output: {} bytes", result.data.len());
    Ok(())
}
