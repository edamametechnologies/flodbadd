fn main() {
    let s: &str = &flodbadd::sensitive_paths_db::SENSITIVE_PATHS_DB;
    println!("len={}", s.len());
}
