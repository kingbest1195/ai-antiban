// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if std::env::args().skip(1).any(|a| a == "--cleanup") {
        std::process::exit(zastava_lib::sysproxy::run_cleanup_cli());
    }
    if std::env::args()
        .skip(1)
        .any(|a| a == zastava_lib::cowork_guard::INSTALL_COWORK_GUARD_ARG)
    {
        std::process::exit(zastava_lib::cowork_guard::run_install_cowork_guard_cli());
    }
    zastava_lib::run()
}
