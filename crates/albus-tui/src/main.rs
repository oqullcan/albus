#![forbid(unsafe_code)]
#![doc = "Terminal user interface entry point for Albus."]

const HELP_TEXT: &str = "\
Albus offline TOTP vault

Usage:
  albus
  albus --help
  albus --version
";

fn main() -> Result<(), albus_tui::AppError> {
    let mut args = std::env::args().skip(1);
    if let Some(flag) = args.next() {
        if args.next().is_some() {
            eprintln!("expected at most one argument\n\n{HELP_TEXT}");
            std::process::exit(2);
        }

        match flag.as_str() {
            "--help" | "-h" => {
                print!("{HELP_TEXT}");
                return Ok(());
            }
            "--version" | "-V" => {
                println!("albus {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ => {
                eprintln!("unrecognized argument: {flag}\n\n{HELP_TEXT}");
                std::process::exit(2);
            }
        }
    }

    albus_tui::run()
}
