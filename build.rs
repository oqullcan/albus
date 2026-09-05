use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bpf_src = PathBuf::from("bpf/sockops.bpf.c");
    let bpf_out = out_dir.join("sockops.bpf.o");

    println!("cargo:rerun-if-changed=bpf/sockops.bpf.c");
    println!("cargo:rerun-if-changed=bpf/include/bpf_helpers.h");
    println!("cargo:rerun-if-changed=bpf/include/bpf_endian.h");

    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            "-I",
            "bpf",
            "-c",
            bpf_src.to_str().unwrap(),
            "-o",
            bpf_out.to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!(
                "cargo:rustc-env=ALBUS_BPF_BYTECODE={}",
                bpf_out.to_str().unwrap()
            );
        }
        Ok(s) => {
            panic!(
                    "clang failed to compile eBPF bytecode (exit code: {:?}). Please ensure 'clang', 'llvm', and kernel headers ('linux-libc-dev') are installed.\n\
                     Run: sudo apt-get install clang llvm libelf-dev linux-libc-dev",
                    s.code()
                );
        }
        Err(e) => {
            panic!(
                    "Failed to execute clang ({e}). Please ensure 'clang' is installed and available in PATH.\n\
                     Run: sudo apt-get install clang llvm libelf-dev linux-libc-dev"
                );
        }
    }
}
