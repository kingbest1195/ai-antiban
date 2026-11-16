// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--cleanup") {
        std::process::exit(zastava_lib::sysproxy::run_cleanup_cli());
    }
    if let Some(error_file) = zastava_lib::cowork_guard::parse_install_cli_args(&args) {
        std::process::exit(
            zastava_lib::cowork_guard::run_install_cowork_guard_cli_with_error_file(
                error_file.as_deref(),
            ),
        );
    }
    zastava_lib::run()
}
