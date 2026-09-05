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
        _ => {
            // If clang isn't available or fails, check if a pre-compiled bpf.o is present in bpf/
            let fallback = env::current_dir().unwrap().join("bpf/sockops.bpf.o");
            if fallback.exists() {
                println!(
                    "cargo:rustc-env=ALBUS_BPF_BYTECODE={}",
                    fallback.to_str().unwrap()
                );
            } else {
                panic!("Failed to compile eBPF bytecode and no fallback sockops.bpf.o found");
            }
        }
    }
}
