# Architecture & repository layout

Albus is a single Rust binary plus an eBPF object and an optional desktop panel.
This document maps the tree so a new reader can find the right surface quickly.

## Top-level layout

| Path | Responsibility |
| :--- | :--- |
| `src/` | Rust crate (library + binary entrypoint). |
| `bpf/` | eBPF `sock_ops` C source and shared headers; embedded at build time. |
| `plugins/omarchy/` | Omarchy panel widget (`manifest.json`, QML files, assets). |
| `scripts/` | Grouped tooling: `scripts/dpi/` simulator+checker, `scripts/panel/` QML logic tests. |
| `tests/` | Integration, fuzz, net, docs and root/gated suites. |
| `docs/` | TESTING, TEST_RESULTS, OMARCHY, PANEL_TESTING, OPEN_QUESTIONS, ARCHITECTURE. |
| `.github/workflows/` | CI: gates, live-network proof, security gates. |
| `Cargo.toml`, `Cargo.lock` | Rust manifest and pinned lockfile. |
| `build.rs` | Embeds the compiled BPF object into the binary. |

## `src/` map

| Module | Responsibility |
| :--- | :--- |
| `src/main.rs`, `src/lib.rs` | CLI dispatch and public crate surface. |
| `src/app/` | CLI (`cli.rs`), config (`config.rs`), service install/uninstall (`service.rs`), monitor/status. |
| `src/core/` | Engine lifecycle (`engine.rs`), eBPF loader/manager (`ebpf/`), firewall rules (`firewall.rs`), raw-socket injection (`rawsock/`), fake ClientHello builders (`fake/`), Auto-TTL estimator (`autottl/`). |
| `src/dns/` | Local DoH proxy (`doh.rs`), DNSSEC validator (`dnssec.rs`), cache, ECH discovery, SSRF blocklist, system DNS rewriting. |

## Gate commands

```bash
cargo fmt --check && cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo test --test fuzz --test docs --test net
node --test scripts/panel/panel-logic-test.mjs
```

Privileged (root): `sudo -E cargo test --test ebpf -- --ignored`, `sudo -E cargo test --test root -- --ignored`.

## Where things live at runtime

- Binary: `/usr/local/bin/albus`
- Config: `/etc/albus/config.json` (service) or `~/.config/albus/config.json` (interactive)
- Service user: `albus` (capabilities only, no full root)
- BPF + raw socket run as the service user under the listed capabilities.
