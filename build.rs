use std::env;
use std::path::PathBuf;
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

/// Locate a sysroot include dir providing `asm/types.h` (needed by
/// kernel UAPI headers under `-target bpf`). Debian/Ubuntu multiarch
/// keeps it under `/usr/include/<triplet>/`, not `/usr/include/`.
fn system_include_dir() -> Option<PathBuf> {
    for cand in [
        "/usr/include",
        "/usr/include/x86_64-linux-gnu",
        "/usr/include/aarch64-linux-gnu",
    ] {
        if PathBuf::from(cand).join("asm/types.h").exists() {
            return Some(PathBuf::from(cand));
        }
    }
    None
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
    cmd.args([
        "-target", "bpf", "-O2", "-g", "-Wall", "-Werror", "-I", "bpf",
    ]);
    if let Some(dir) = system_include_dir() {
        cmd.arg("-I").arg(dir);
    }
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
