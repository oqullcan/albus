use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn clang_binary() -> String {
    // pin CC env if valid absolute path, else prefer absolute system clang
    if let Ok(cc) = env::var("CC") {
        if cc.starts_with('/') && PathBuf::from(&cc).exists() {
            return cc;
        }
    }
    for p in ["/usr/bin/clang", "/usr/lib/llvm/bin/clang"] {
        if PathBuf::from(p).exists() {
            return p.to_string();
        }
    }
    "clang".to_string()
}

// Debian/Ubuntu multiarch ships kernel UAPI `asm/` only under the target
// triplet dir (e.g. /usr/include/x86_64-linux-gnu/asm) with NO top-level
// /usr/include/asm symlink — while Arch/Fedora have it directly. Probe the
// candidates so `#include <asm/types.h>` resolves on both layouts
// (this exact failure broke CI on ubuntu-latest).
fn asm_include_args() -> Vec<String> {
    asm_include_args_under(Path::new("/usr/include"))
}

fn asm_include_args_under(root: &Path) -> Vec<String> {
    let mut args = vec!["-I".to_string(), "bpf".to_string()];
    for tri in [
        "x86_64-linux-gnu",
        "aarch64-linux-gnu",
        "riscv64-linux-gnu",
        "loongarch64-linux-gnu",
    ] {
        let dir = root.join(tri);
        if dir.join("asm").join("types.h").exists() {
            args.push("-I".to_string());
            args.push(dir.to_str().unwrap().to_string());
            break;
        }
    }
    args
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bpf_src = PathBuf::from("bpf/sockops.bpf.c");
    let bpf_out = out_dir.join("sockops.bpf.o");

    println!("cargo:rerun-if-changed=bpf/sockops.bpf.c");
    println!("cargo:rerun-if-changed=bpf/include/bpf_helpers.h");
    println!("cargo:rerun-if-changed=bpf/include/bpf_endian.h");
    println!("cargo:rerun-if-env-changed=CC");

    let mut cmd = Command::new(clang_binary());
    cmd.args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror"]);
    cmd.args(asm_include_args());
    let status = cmd
        .args([
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
            let fallback = PathBuf::from("bpf/sockops.bpf.o");
            if fallback.exists() {
                eprintln!(
                    "warning: clang failed, using stale fallback bpf/sockops.bpf.o — verify hash before release"
                );
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
