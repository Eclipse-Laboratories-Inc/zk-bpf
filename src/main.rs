use std::{
    env,
    fs::{
        File,
        canonicalize,
        create_dir_all,
    },
    io::{
        BufWriter,
        Read,
    },
    path::{
        Path,
        PathBuf,
    },
    process::Command,
};

use clap::{App, Arg};
use solana_rbpf::{
    assembler::assemble,
    compiler::Compiler,
    elf::Executable,
    user_error::UserError,
    vm::{
        Config, SyscallRegistry, TestInstructionMeter,
    },
};
use object::{
    Architecture,
    BinaryFormat,
    Endianness,
    RelocationEncoding,
    RelocationKind,
    SectionKind,
    SymbolFlags,
    SymbolKind,
    SymbolScope,
    write::{
        Object,
        Relocation,
        StandardSegment,
        Symbol,
        SymbolSection,
    },
};
use ar::Builder;

use risc0_build::{
    GuestOptions,
    get_package,
    setup_guest_build_env,
    guest_methods,
};

use risc0_zkvm::{
    host::Prover,
    serde::from_slice,
};

const METHODS_DIR : &'static str = env!("METHODS_DIR");

fn main() {
    let matches = App::new("ZK eBPF tool")
        .author("Eclipse Labs")
        .arg(
            Arg::new("assembler")
                .short('a')
                .long("asm")
                .value_name("FILE")
                .takes_value(true)
                .required_unless_present("elf"),
        )
        .arg(
            Arg::new("elf")
                .short('e')
                .long("elf")
                .value_name("FILE")
                .takes_value(true)
                .required_unless_present("assembler"),
        )
        .arg(
            Arg::new("build directory")
                .short('d')
                .long("build-directory")
                .value_name("DIR")
                .takes_value(true)
                .default_value("build"),
        )
        .arg(
            Arg::new("no execute")
                .short('n')
                .long("no-execute")
                .takes_value(false),
        ).get_matches();

    let target_dir_relative = Path::new(matches.value_of("build directory").unwrap());
    let target_dir = canonicalize(target_dir_relative).unwrap(); // should be replaced by std::path::absolute once it's out of nightly
    create_dir_all(target_dir.clone()).unwrap();

    let (input_filename, needs_assembly) = if let Some(filename) = matches.value_of("assembler") {
        (filename, true)
    } else {
        (matches.value_of("elf").unwrap(), false)
    };

    let bpf_dir = compile_bpf(&Path::new(input_filename), target_dir.clone(), needs_assembly);

    let (method_path, method_id_vec) = compile_methods(target_dir, bpf_dir);
    let method_id = method_id_vec.as_slice();

    if !matches.contains_id("no execute") {
        eprintln!("Executing program...");

        let prover = Prover::new(&std::fs::read(method_path).unwrap(), method_id).unwrap();

        let receipt = prover.run().unwrap();

        let output : [u64; 11] = from_slice(&receipt.get_journal_vec().unwrap()).unwrap();

        println!("The final BPF register values were:");
        for i in 0..11 {
            println!(" {:>3}: {:#016x}", format!("r{}", i), output[i]);
        }

        receipt.verify(method_id).unwrap();
    }
}

fn compile_bpf<P: AsRef<Path>, Q: AsRef<Path>>(input_path: P, target_dir: Q, needs_assembly: bool) -> PathBuf {
    let config = Config {
        encrypt_environment_registers: false,
        noop_instruction_rate: 0,
        ..Config::default()
    };
    let syscall_registry = SyscallRegistry::default();
    let executable = if needs_assembly {
        let mut file = File::open(input_path).unwrap();
        let mut source = Vec::new();
        file.read_to_end(&mut source).unwrap();
        assemble::<UserError, TestInstructionMeter>(
            std::str::from_utf8(source.as_slice()).unwrap(),
            config,
            syscall_registry,
        )
    } else {
        let mut file = File::open(input_path).unwrap();
        let mut elf = Vec::new();
        file.read_to_end(&mut elf).unwrap();
        Executable::<UserError, TestInstructionMeter>::from_elf(&elf, config, syscall_registry)
            .map_err(|err| format!("Executable constructor failed: {:?}", err))
    }
    .unwrap();

    let (_, text_bytes) = executable.get_text_bytes();
    let mut compiler = Compiler::new::<UserError>(text_bytes, &config).unwrap();

    compiler.compile(&executable).unwrap();

    let bpf_elf_bytes = executable.get_ro_section();
    let riscv_bytes = compiler.result.text_section;

    let mut obj = Object::new(BinaryFormat::Elf, Architecture::Riscv32, Endianness::Little);

    let rodata_section = obj.add_section(obj.segment_name(StandardSegment::Data).to_vec(), b".rodata".to_vec(), SectionKind::Text);
    let bpf_ro_section_size_symbol = obj.add_symbol(Symbol {
        name: b"bpf_ro_section_size".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(rodata_section),
        flags: SymbolFlags::None,
    });
    obj.add_symbol_data(bpf_ro_section_size_symbol, rodata_section, &(bpf_elf_bytes.len() as u32).to_le_bytes(), 0x10);
    let bpf_ro_section_symbol = obj.add_symbol(Symbol {
        name: b"bpf_ro_section".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(rodata_section),
        flags: SymbolFlags::None,
    });
    obj.add_symbol_data(bpf_ro_section_symbol, rodata_section, bpf_elf_bytes, 0x10);

    let text_section = obj.add_section(obj.segment_name(StandardSegment::Text).to_vec(), b".text".to_vec(), SectionKind::Text);
    let program_main_symbol = obj.add_symbol(Symbol {
        name: b"program_main".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(rodata_section),
        flags: SymbolFlags::None,
    });
    obj.add_symbol_data(program_main_symbol, text_section, riscv_bytes, 0x1000); // TODO determine what alignment is necessary

    for reloc in compiler.relocations.iter() {
        let symbol = obj.add_symbol(Symbol {
            name: reloc.symbol.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Unknown,
            scope: SymbolScope::Unknown,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
        let obj_reloc = Relocation {
            offset: reloc.offset as u64,
            size: 0,
            kind: RelocationKind::Elf(18), // R_RISCV_CALL
            encoding: RelocationEncoding::Generic,
            symbol,
            addend: 0,
        };
        obj.add_relocation(text_section, obj_reloc).unwrap();
    }

    let bpf_target_dir = PathBuf::new().join(target_dir).join("bpf-riscv");
    create_dir_all(bpf_target_dir.clone()).unwrap();

    let obj_path = bpf_target_dir.join("bpf.o");
    let obj_file = File::create(&obj_path).unwrap();
    obj.write_stream(BufWriter::new(obj_file)).unwrap();

    let ar_path = bpf_target_dir.join("libbpf.a");
    let ar_file = File::create(ar_path).unwrap();
    let mut ar_builder = Builder::new(ar_file);
    ar_builder.append_path(obj_path).unwrap();

    return bpf_target_dir;
}

fn compile_methods<P: AsRef<Path>, Q: AsRef<Path>>(target_dir: P, bpf_target_dir: Q) -> (PathBuf, Vec<u8>) {
    let pkg = get_package(METHODS_DIR);
    let guest_build_env = setup_guest_build_env(target_dir.as_ref());

    let target_dir_guest = target_dir.as_ref().join("riscv-guest");

    // mostly taken from risc0-build
    let args = vec![
        "build",
        "--release",
        "--target",
        guest_build_env.target_spec.to_str().unwrap(),
        "-Z",
        "build-std=core,alloc,std,proc_macro,panic_abort",
        "-Z",
        "build-std-features=compiler-builtins-mem",
        "--manifest-path",
        pkg.manifest_path.as_str(),
        "--target-dir",
        target_dir_guest.to_str().unwrap(),
    ];
    eprintln!("Building guest package: cargo {}", args.join(" "));
    // The RISC0_STANDARD_LIB variable can be set for testing purposes
    // to override the downloaded standard library.  It should point
    // to the root of the rust repository.
    let risc0_standard_lib: String = if let Ok(path) = env::var("RISC0_STANDARD_LIB") {
        path
    } else {
        guest_build_env.rust_lib_src.to_str().unwrap().into()
    };

    eprintln!("Using rust standard library root: {}", risc0_standard_lib);

    let mut cmd = Command::new("cargo");
    cmd
        .env("BPF_LIB_DIR", bpf_target_dir.as_ref().as_os_str())
        .env("CARGO_ENCODED_RUSTFLAGS", "-C\x1fpasses=loweratomic")
        .env("__CARGO_TESTS_ONLY_SRC_ROOT", risc0_standard_lib)
        .args(args)
        .spawn()
        .unwrap();

    let status = cmd.status().unwrap();

    if !status.success() {
        std::process::exit(status.code().unwrap());
    }

    let method = guest_methods(&pkg, target_dir).remove(0);
    return (method.elf_path.clone(), method.make_method_id(GuestOptions::default().code_limit));
}
