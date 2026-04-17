//! Fork of `aya_build::build_ebpf` that uses `cargo build --manifest-path` instead of
//! `--package`, so the eBPF crate does not need to be a workspace member (avoids host builds).

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead as _, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::{env, path::Path};

use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;
use cargo_metadata::{Artifact, CompilerMessage, Message, Target};
use rustc_version::Channel;
use which::which;

fn target_arch_fixup(target_arch: Cow<'_, str>) -> Cow<'_, str> {
    if target_arch.starts_with("riscv64") {
        "riscv64".into()
    } else {
        target_arch
    }
}

fn main() -> anyhow::Result<()> {
    let ebpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../kernel-spy-ebpf");
    let ebpf_manifest = ebpf_dir.join("Cargo.toml");
    let package_name = "kernel-spy-ebpf";

    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join("src/main.rs").display()
    );
    println!("cargo:rerun-if-changed={}", ebpf_manifest.display());
    println!(
        "cargo:rerun-if-changed={}",
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kernel-spy-common/src")
            .display()
    );

    build_ebpf_manifest(
        package_name,
        &ebpf_manifest,
        ebpf_dir.as_path(),
        Toolchain::default(),
    )
}

fn build_ebpf_manifest(
    package_name: &str,
    manifest_path: &Path,
    root_dir: &Path,
    toolchain: Toolchain<'_>,
) -> anyhow::Result<()> {
    const AYA_BUILD_SKIP: &str = "AYA_BUILD_SKIP";
    println!("cargo:rerun-if-env-changed={AYA_BUILD_SKIP}");
    if let Some(aya_build_skip) = env::var_os(AYA_BUILD_SKIP)
        && (aya_build_skip.eq("1") || aya_build_skip.eq_ignore_ascii_case("true"))
    {
        println!(
            "cargo:warning={AYA_BUILD_SKIP}={}; skipping eBPF build",
            aya_build_skip.display()
        );
        return Ok(());
    }

    const OUT_DIR: &str = "OUT_DIR";
    let out_dir = env::var_os(OUT_DIR).ok_or_else(|| anyhow!("{OUT_DIR} not set"))?;
    let out_dir = PathBuf::from(out_dir);

    const CARGO_CFG_TARGET_ENDIAN: &str = "CARGO_CFG_TARGET_ENDIAN";
    let endian = env::var_os(CARGO_CFG_TARGET_ENDIAN)
        .ok_or_else(|| anyhow!("{CARGO_CFG_TARGET_ENDIAN} not set"))?;
    let target = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        return Err(anyhow!("unsupported endian={}", endian.display()));
    };

    const TARGET_ARCH: &str = "CARGO_CFG_TARGET_ARCH";
    let bpf_target_arch =
        env::var_os(TARGET_ARCH).ok_or_else(|| anyhow!("{TARGET_ARCH} not set"))?;
    let bpf_target_arch = bpf_target_arch.into_string().map_err(|bpf_target_arch| {
        anyhow!(
            "OsString::into_string({TARGET_ARCH}={})",
            bpf_target_arch.display()
        )
    })?;
    let bpf_target_arch = target_arch_fixup(bpf_target_arch.into());
    let target = format!("{target}-unknown-none");

    const RUSTUP: &str = "rustup";
    let rustup = which(RUSTUP);
    let toolchain_spec: &str = match &toolchain {
        Toolchain::Nightly => "nightly",
        Toolchain::Custom(spec) => spec,
    };
    let prefix: &[_] = match rustup.as_ref() {
        Ok(rustup) => &[
            rustup.as_os_str(),
            OsStr::new("run"),
            OsStr::new(toolchain_spec),
        ],
        Err(err) => {
            println!("cargo:warning=which({RUSTUP})={err}; proceeding with current toolchain");
            &[]
        }
    };

    let cmd = |program| match prefix {
        [] => Command::new(program),
        [wrapper, args @ ..] => {
            let mut cmd = Command::new(wrapper);
            cmd.args(args).arg(program);
            cmd
        }
    };

    let rustc_version::VersionMeta {
        semver: _,
        commit_hash: _,
        commit_date: _,
        build_date: _,
        channel,
        host: _,
        short_version_string: _,
        llvm_version: _,
    } = rustc_version::VersionMeta::for_command(cmd("rustc"))
        .context("failed to get rustc version meta")?;

    let rustc_bootstrap = env::var_os("RUSTC_BOOTSTRAP");

    println!("cargo:rerun-if-changed={}", root_dir.display());

    let manifest_str = manifest_path
        .to_str()
        .ok_or_else(|| anyhow!("eBPF manifest path is not valid UTF-8"))?;

    let mut cmd = cmd("cargo");
    cmd.args([
        "build",
        "--manifest-path",
        manifest_str,
        "--bins",
        "--message-format=json",
        "--release",
        "--target",
        &target,
    ]);

    let use_build_std = match rustc_bootstrap.as_ref() {
        Some(rustc_bootstrap) => {
            if rustc_bootstrap == "1" || rustc_bootstrap == package_name {
                true
            } else if rustc_bootstrap == "-1" {
                false
            } else {
                channel == Channel::Nightly
            }
        }
        None => channel == Channel::Nightly,
    };

    if use_build_std {
        cmd.args(["-Z", "build-std=core"]);
    }

    {
        const SEPARATOR: &str = "\x1f";

        let mut rustflags = OsString::new();

        for s in [
            "--cfg=bpf_target_arch=\"",
            &bpf_target_arch,
            "\"",
            SEPARATOR,
            "-Cdebuginfo=2",
            SEPARATOR,
            "-Clink-arg=--btf",
        ] {
            rustflags.push(s);
        }

        cmd.env("CARGO_ENCODED_RUSTFLAGS", rustflags);
    }

    for key in ["RUSTC", "RUSTC_WORKSPACE_WRAPPER"] {
        cmd.env_remove(key);
    }

    let target_dir = out_dir.join("aya-build").join("target").join(package_name);
    cmd.arg("--target-dir").arg(&target_dir);

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {cmd:?}"))?;
    let Child { stdout, stderr, .. } = &mut child;

    let stderr = stderr.take().expect("stderr");
    let stderr = BufReader::new(stderr);
    let stderr = std::thread::spawn(move || {
        for line in stderr.lines() {
            let line = line.expect("read line");
            println!("cargo:warning={line}");
        }
    });

    let stdout = stdout.take().expect("stdout");
    let stdout = BufReader::new(stdout);
    let mut executables = Vec::new();
    for message in Message::parse_stream(stdout) {
        #[expect(clippy::collapsible_match, reason = "better captures intent")]
        match message.with_context(|| anyhow!("cargo stdout stream contains invalid JSON"))? {
            Message::CompilerArtifact(Artifact {
                executable,
                target: Target { name, .. },
                ..
            }) => {
                if let Some(executable) = executable {
                    executables.push((name, executable.into_std_path_buf()));
                }
            }
            Message::CompilerMessage(CompilerMessage { message, .. }) => {
                for line in message.rendered.unwrap_or_default().split('\n') {
                    println!("cargo:warning={line}");
                }
            }
            Message::TextLine(line) => {
                println!("cargo:warning={line}");
            }
            _ => {}
        }
    }

    let status = child
        .wait()
        .with_context(|| format!("failed to wait for {cmd:?}"))?;
    if !status.success() {
        return Err(anyhow!("{cmd:?} failed: {status:?}"));
    }

    match stderr.join().map_err(std::panic::resume_unwind) {
        Ok(()) => {}
        Err(err) => match err {},
    }

    for (name, binary) in executables {
        let dst = out_dir.join(name);
        let _: u64 = fs::copy(&binary, &dst).with_context(|| {
            format!("failed to copy {} to {}", binary.display(), dst.display())
        })?;
    }

    Ok(())
}
