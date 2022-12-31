#![no_main]
#![no_std]
// Copyright 2022 Eclipse Labs
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>.
// This file may not be copied, modified, or distributed except according to those terms.


use risc0_zkvm_guest::env;

risc0_zkvm_guest::entry!(main);

#[link(name = "bpf", kind = "static")]
extern "C" {
    fn program_main();
    static bpf_ro_section_size : u32;
    #[link_name = "bpf_ro_section"]
    static bpf_ro_section : [u32; 0];
}

static mut BPF_STACK : [u8; 64 * 4 * 1024] = [0; 64 * 4 * 1024];
static mut BPF_HEAP  : [u8;     32 * 1024] = [0;     32 * 1024];
static mut INPUT_DATA  : [u8; 8] = [0; 8];

#[no_mangle]
extern "C" fn translate_memory_address(bpf_addr: u64) -> u32 {
    /*
     * The Solana memory model is as follows:
     *   program data is loaded at 0x100000000 (2^32)
     *   the stack starts at 0x200000000 and has a maximum size of 64 * 4 KiB
     *   the heap starts at 0x300000000 and is 32 KiB
     *   input data is loaded at 0x400000000
     *
     * More details are at https://docs.solana.com/developing/on-chain-programs/overview
     */
    if 1 << 32 <= bpf_addr && bpf_addr < 2 << 32 {
        if (bpf_addr as u32) < unsafe { bpf_ro_section_size } {
            return unsafe { (bpf_ro_section.as_ptr() as u32) + (bpf_addr as u32) };
        } else {
            panic!("Attempted to access illegal memory location {:#018x}!", bpf_addr);
        }
    } else if 2 << 32 <= bpf_addr && bpf_addr < 3 << 32 {
        if (bpf_addr as u32) < (unsafe { BPF_STACK.len() } as u32) {
            return unsafe { BPF_STACK.as_ptr() as u32 } + (bpf_addr as u32);
        } else {
            panic!("Attempted to access illegal memory location {:#018x}!", bpf_addr);
        }
    } else if 3 << 32 <= bpf_addr && bpf_addr < 4 << 32 {
        if (bpf_addr as u32) < (unsafe { BPF_HEAP.len() } as u32) {
            return unsafe { BPF_HEAP.as_ptr() as u32 } + (bpf_addr as u32);
        } else {
            panic!("Attempted to access illegal memory location {:#018x}!", bpf_addr);
        }
    } else if 4 << 32 <= bpf_addr {
        // TODO actually implement input data
        if (bpf_addr as u32) < (unsafe { INPUT_DATA.len() } as u32) {
            return unsafe { INPUT_DATA.as_ptr() as u32 } + (bpf_addr as u32);
        } else {
            panic!("Attempted to access illegal memory location {:#018x}!", bpf_addr);
        }
    } else {
        panic!("Attempted to access illegal memory location {:#018x}!", bpf_addr);
    }
}

#[no_mangle]
extern "C" fn write_to_journal(output: u64) {
    env::commit(&output);
}

pub fn main() {
    unsafe { program_main() };
    // commit the values of the 11 BPF registers
    let ptr = unsafe { BPF_STACK.as_ptr() as *const u64 };
    for i in 0..11 {
        env::commit(unsafe { &*ptr.offset(i) });
    }
}
