#![no_main]
#![no_std]
// Copyright 2022 Eclipse Labs
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>.
// This file may not be copied, modified, or distributed except according to those terms.

extern crate alloc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use lazy_static::lazy_static;
use risc0_zkvm_guest::env;

risc0_zkvm_guest::entry!(main);

#[link(name = "bpf", kind = "static")]
extern "C" {
    fn program_main();
    static bpf_ro_section_size: u32;
    #[link_name = "bpf_ro_section"]
    static bpf_ro_section: [u32; 0];
}

struct UnsafeData<T: Sized, const N: usize> {
    cell: UnsafeCell<[T; N]>,
}
impl<T, const N: usize> UnsafeData<T, N> {
    fn as_ptr(&self) -> *mut T {
        self.cell.get() as *mut T
    }
    fn len(&self) -> usize {
        N
    }
}
unsafe impl<T, const N: usize> Sync for UnsafeData<T, N> {}

static BPF_STACK: UnsafeData<u8, { 64 * 4 * 1024 }> = UnsafeData {
    cell: UnsafeCell::new([0; 64 * 4 * 1024]),
};
static BPF_HEAP: UnsafeData<u8, { 32 * 1024 }> = UnsafeData {
    cell: UnsafeCell::new([0; 32 * 1024]),
};
lazy_static! {
    static ref INPUT_DATA: Vec<u8> = env::read();
}

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
    if 1 << 32 <= bpf_addr && bpf_addr < 2 << 32
        && (bpf_addr as u32) < unsafe { bpf_ro_section_size }
    {
        return (unsafe { bpf_ro_section.as_ptr() } as u32) + (bpf_addr as u32);
    } else if 2 << 32 <= bpf_addr && bpf_addr < 3 << 32
        && (bpf_addr as u32) < (BPF_STACK.len() as u32)
    {
        return (BPF_STACK.as_ptr() as u32) + (bpf_addr as u32);
    } else if 3 << 32 <= bpf_addr && bpf_addr < 4 << 32
        && (bpf_addr as u32) < (BPF_HEAP.len() as u32)
    {
        return (BPF_HEAP.as_ptr() as u32) + (bpf_addr as u32);
    } else if 4 << 32 <= bpf_addr
        && (bpf_addr as u32) < (INPUT_DATA.len() as u32)
    {
        return (INPUT_DATA.as_ptr() as u32) + (bpf_addr as u32);
    } else {
        panic!(
            "Attempted to access illegal memory location {:#018x}!",
            bpf_addr
        );
    }
}

#[no_mangle]
extern "C" fn write_to_journal(output: u64) {
    env::commit(&output);
}

#[no_mangle]
extern "C" fn bpf_div64(dst: u64, src: u64) -> u64 {
    dst / src
}

#[no_mangle]
extern "C" fn bpf_sdiv64(dst: i64, src: i64) -> i64 {
    dst / src
}

#[no_mangle]
extern "C" fn bpf_mod64(dst: u64, src: u64) -> u64 {
    dst % src
}

#[no_mangle]
extern "C" fn bpf_lsh64(dst: u64, src: u64) -> u64 {
    dst << src
}

#[no_mangle]
extern "C" fn bpf_rsh64(dst: u64, src: u64) -> u64 {
    dst >> src
}

#[no_mangle]
extern "C" fn bpf_arsh64(dst: i64, src: u64) -> i64 {
    dst >> src
}

pub fn main() {
    unsafe { program_main() };
    // commit the values of the 10 ordinary BPF registers
    let ptr = BPF_STACK.as_ptr() as *const [u64; 10];
    env::commit(&unsafe { *ptr });
}
