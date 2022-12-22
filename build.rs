use std::env;

fn main() {
    let methods_dir = env::var("METHODS_DIR")
        .unwrap_or(env::current_dir().unwrap().join("methods-guest").to_str().unwrap().to_owned());
    println!("cargo:rustc-env=METHODS_DIR={}", methods_dir);
}
