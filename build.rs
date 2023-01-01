// Copyright 2022 Eclipse Labs
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::env;

fn main() {
    let methods_dir = env::var("METHODS_DIR").unwrap_or(
        env::current_dir()
            .unwrap()
            .join("methods-guest")
            .to_str()
            .unwrap()
            .to_owned(),
    );
    println!("cargo:rustc-env=METHODS_DIR={}", methods_dir);
}
