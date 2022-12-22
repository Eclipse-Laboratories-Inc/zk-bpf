fn main() {
    println!("cargo:rustc-link-search={}", std::env::var("BPF_LIB_DIR").unwrap());
    risc0_build::link();
}
