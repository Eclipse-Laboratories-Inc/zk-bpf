// Copyright 2022 Eclipse Labs
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::path::Path;

fn main() {
    let bpf_lib_dir = std::env::var("BPF_LIB_DIR").unwrap();
    let bpf_lib_path = Path::new(&bpf_lib_dir).join("libbpf.a");
    println!("cargo:rustc-link-search={}", bpf_lib_dir);
    println!("cargo:rerun-if-changed=<{}", bpf_lib_path.to_str().unwrap());
    risc0_build::link();
}
