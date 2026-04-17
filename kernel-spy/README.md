# kernel-spy

eBPF-based network monitor/controller. Build from the **repository root** workspace:

```sh
cd ..
cargo build --release -p kernel-spy
```

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
2. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
3. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
4. (if cross-compiling) LLVM and C toolchain for the target
5. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Run

```sh
sudo ../target/release/kernel-spy --help
```

## License

With the exception of eBPF code, kernel-spy is distributed under the terms of either the [MIT license] or the [Apache License] (version 2.0), at your option.

### eBPF

All eBPF code is distributed under either the terms of the [GNU General Public License, Version 2] or the [MIT license], at your option.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
