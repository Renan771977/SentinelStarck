// Esconde o console do Windows em build de release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    sentinelstack_lib::run()
}
