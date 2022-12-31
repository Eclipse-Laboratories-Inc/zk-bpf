// Copyright 2022 Eclipse Labs
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>.
// This file may not be copied, modified, or distributed except according to those terms.

fn main() {
    println!("cargo:rustc-link-search={}", std::env::var("BPF_LIB_DIR").unwrap());
    risc0_build::link();
}
