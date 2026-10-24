//! Builds the C shim and links it with the oracle that `cargo xtask fetch-oracle` built.
//!
//! The oracle folder is `target/oracle/<version>` in the workspace, with the version from
//! `LIBOQS_VERSION`. The variable `OQS_ORACLE_DIR` names another folder with the same layout.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=OQS_ORACLE_DIR");
    println!("cargo:rerun-if-changed=Shim/OracleShim.c");
    println!("cargo:rerun-if-changed=../../LIBOQS_VERSION");
    // Without `std` the crate is empty and links nothing.
    if env::var_os("CARGO_FEATURE_STD").is_none() {
        return;
    }
    let manifestFolder = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest folder"));
    let oracleFolder = oracleFolder(&manifestFolder);
    let library = oracleFolder.join("build/lib/liboqs.a");
    let internalLibrary = oracleFolder.join("build/lib/liboqs-internal.a");
    let includeFolder = oracleFolder.join("build/include");
    let testHelpers = oracleFolder.join("source/tests/test_helpers.c");
    // The hash-sigs code of LMS, whose working key the shim keeps between signatures.
    let lmsFolder = oracleFolder.join("source/src/sig_stfl/lms/external");
    for required in [
        &library,
        &internalLibrary,
        &includeFolder,
        &testHelpers,
        &lmsFolder,
    ] {
        if !required.exists() {
            panic!(
                "the C oracle is missing: {} does not exist. Run `cargo xtask fetch-oracle` first.",
                required.display()
            );
        }
    }
    println!("cargo:rerun-if-changed={}", library.display());
    let outputFolder = PathBuf::from(env::var("OUT_DIR").expect("output folder"));
    let sources = [manifestFolder.join("Shim/OracleShim.c"), testHelpers];
    let mut objects = Vec::new();
    for source in &sources {
        let object = outputFolder.join(
            source
                .file_stem()
                .expect("source file name")
                .to_string_lossy()
                .to_string()
                + ".o",
        );
        run(Command::new(tool("CC", "cc"))
            .args(["-c", "-O2", "-fPIC", "-std=c11"])
            .arg("-I")
            .arg(&includeFolder)
            .arg("-I")
            .arg(oracleFolder.join("source/tests"))
            // Only for quoted includes: the folder holds an endian.h that must not hide the
            // endian.h of the system.
            .arg("-iquote")
            .arg(&lmsFolder)
            .arg("-o")
            .arg(&object)
            .arg(source));
        objects.push(object);
    }
    let archive = outputFolder.join("libOracleShim.a");
    let _ = std::fs::remove_file(&archive);
    run(Command::new(tool("AR", "ar"))
        .arg("crs")
        .arg(&archive)
        .args(&objects));
    println!("cargo:rustc-link-search=native={}", outputFolder.display());
    println!("cargo:rustc-link-lib=static=OracleShim");
    println!(
        "cargo:rustc-link-search=native={}",
        oracleFolder.join("build/lib").display()
    );
    // The NIST KAT generator is in the internal library. liboqs links its own tests the same
    // way, with the internal library after the main one, so that the main one takes precedence.
    println!("cargo:rustc-link-lib=static=oqs");
    println!("cargo:rustc-link-lib=static=oqs-internal");
}

/// The oracle folder: `OQS_ORACLE_DIR`, or else `target/oracle/<version>` in the workspace.
fn oracleFolder(manifestFolder: &Path) -> PathBuf {
    if let Some(folder) = env::var_os("OQS_ORACLE_DIR") {
        return PathBuf::from(folder);
    }
    let workspaceFolder = manifestFolder.join("../..");
    let version = std::fs::read_to_string(workspaceFolder.join("LIBOQS_VERSION"))
        .expect("LIBOQS_VERSION in the workspace root");
    workspaceFolder.join("target/oracle").join(version.trim())
}

/// The program of a build tool: the value of its variable, or else its usual name.
fn tool(variable: &str, usualName: &str) -> String {
    println!("cargo:rerun-if-env-changed={variable}");
    env::var(variable).unwrap_or_else(|_| usualName.to_string())
}

/// Runs a build command and stops the build with its output when it fails.
fn run(command: &mut Command) {
    let output = command.output().expect("start a build tool");
    if !output.status.success() {
        panic!(
            "{command:?} failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
