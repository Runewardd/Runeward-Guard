use runeward_guard::host;
use std::io;

fn run() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 2 {
        return Err("expected Chrome extension origin".into());
    }
    let config = host::load_config()?;
    if arguments[1].trim_end_matches('/') != config.allowed_origin.trim_end_matches('/') {
        return Err("unexpected extension origin".into());
    }
    host::serve_native(
        &mut io::stdin().lock(),
        &mut io::stdout().lock(),
        &config.socket,
    )
}

fn main() {
    if let Err(error) = run() {
        eprintln!("guard-browser-host: {error}");
        std::process::exit(1);
    }
}
