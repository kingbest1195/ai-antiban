// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = zastava_lib::try_handle_early_cli_args(&args) {
        std::process::exit(code);
    }
    zastava_lib::run()
}
