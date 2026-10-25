// Build-script helper shared by the native check crates (included with `include!` from their
// build.rs). It turns a kernel's sources into a module of an ordinary std test crate, so tests
// -- natively and under Miri -- call the SAME function bodies the wasm kernel is built from.
//
// A kernel crate cannot be a dependency of a test crate as it is: it is a `no_std` staticlib, the
// SDK defines `#[panic_handler]` and `#[global_allocator]`, and every family exports unmangled
// names (`public_key` exists in three families). The rewrite is line-local and leaves every
// line in place (so line numbers in panics and Miri reports match the real file); it changes
// ONLY these, and `rewrite` refuses a line it would change in any other way:
//  - `//!` inner doc lines become `// !`, and `#![...]` crate attributes become comments
//    (an `include!`d file cannot carry inner attributes);
//  - `#[no_mangle]` is dropped (no symbol clashes between families);
//  - `extern "C"` becomes `extern "C-unwind"`, on exported functions and on the SDK's import
//    block: the native `kernel_trap` unwinds (a panic the test catches) where the real one
//    traps the message, and unwinding out of an `extern "C"` function aborts the process;
//  - `#[panic_handler]` / `#[global_allocator]` become `#[allow(dead_code)]` (std provides
//    both; the SDK's allocator is tested directly through `GlobalAlloc`);
//  - `mod x;` gets `#[path]` pointing at x.rs, rewritten the same way, and becomes `pub`;
//  - `crate::` becomes `crate::<module>::` (the kernel is a module of the test crate), and
//    `moxzi_kernel::` becomes `crate::moxzi_kernel::` (the SDK is a module too);
//  - per-crate dependency renames, e.g. `sha2::` -> `sha2_09::` where one test crate needs
//    two versions of a dependency.
use std::path::{Path, PathBuf};

pub struct Rewrite<'a> {
    /// Module path of the kernel inside the test crate, e.g. "k_rsa".
    pub module: &'a str,
    /// (from, to) dependency path renames, e.g. ("sha2::", "sha2_09::").
    pub renames: &'a [(&'a str, &'a str)],
    /// Rewrite `moxzi_kernel::` paths to the test crate's SDK module.
    pub sdk_module: bool,
}

/// Rewrite `src` (a kernel source file) and the modules it declares into `out_dir`; returns the
/// rewritten root file's path. Prints `cargo:rerun-if-changed` for every source read.
pub fn rewrite(src: &Path, out_dir: &Path, rw: &Rewrite) -> PathBuf {
    println!("cargo:rerun-if-changed={}", src.display());
    let text = std::fs::read_to_string(src).unwrap_or_else(|e| panic!("{}: {e}", src.display()));
    std::fs::create_dir_all(out_dir).unwrap();
    let mut out = String::new();
    for (i, line) in text.lines().enumerate() {
        let new = rewrite_line(line, src, out_dir, rw);
        check_only_allowed(line, &new, rw).unwrap_or_else(|e| panic!("{}:{}: {e}", src.display(), i + 1));
        out.push_str(&new);
        out.push('\n');
    }
    let dst = out_dir.join(src.file_name().unwrap());
    std::fs::write(&dst, out).unwrap();
    dst
}

fn rewrite_line(line: &str, src: &Path, out_dir: &Path, rw: &Rewrite) -> String {
    let t = line.trim_start();
    let indent = &line[..line.len() - t.len()];
    if t.starts_with("//!") {
        return format!("{indent}// !{}", &t[3..]);
    }
    if t.starts_with("#![") {
        return format!("{indent}// {t}");
    }
    // `mod x;` / `pub mod x;` -> the rewritten x.rs, public so tests can reach it.
    let decl = t.strip_prefix("pub ").unwrap_or(t);
    if let Some(name) = decl.strip_prefix("mod ").and_then(|r| r.strip_suffix(';')) {
        if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            let child = src.parent().unwrap().join(format!("{name}.rs"));
            let dst = rewrite(&child, out_dir, rw);
            return format!("{indent}#[path = {:?}] pub mod {name};", dst.display().to_string());
        }
    }
    let mut s = line.replace("#[no_mangle]", "");
    s = s.replace("extern \"C\" ", "extern \"C-unwind\" ");
    s = s.replace("#[panic_handler]", "#[allow(dead_code)]").replace("#[global_allocator]", "#[allow(dead_code)]");
    s = s.replace("crate::", &format!("crate::{}::", rw.module));
    if rw.sdk_module {
        s = replace_path(&s, "moxzi_kernel::", "crate::moxzi_kernel::");
    }
    for (from, to) in rw.renames {
        s = replace_path(&s, from, to);
    }
    s
}

/// Replace `from` where it starts a path (not preceded by an identifier character or `::`).
fn replace_path(s: &str, from: &str, to: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(from) {
        let before = &rest[..i];
        let prev = before.chars().last();
        let starts_path = !matches!(prev, Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == ':');
        out.push_str(before);
        out.push_str(if starts_path { to } else { from });
        rest = &rest[i + from.len()..];
    }
    out.push_str(rest);
    out
}

/// The rewritten line must equal the original once the allowed edits are undone.
fn check_only_allowed(orig: &str, new: &str, rw: &Rewrite) -> Result<(), String> {
    if orig == new {
        return Ok(());
    }
    let t = orig.trim_start();
    if t.starts_with("//!") || t.starts_with("#![") {
        return Ok(());
    }
    let decl = t.strip_prefix("pub ").unwrap_or(t);
    if decl.starts_with("mod ") && new.contains("#[path = ") {
        return Ok(());
    }
    let mut undo = new.replace("extern \"C-unwind\" ", "extern \"C\" ");
    undo = undo.replace(&format!("crate::{}::", rw.module), "crate::");
    if rw.sdk_module {
        undo = undo.replace("crate::moxzi_kernel::", "moxzi_kernel::");
    }
    for (from, to) in rw.renames {
        undo = undo.replace(to, from);
    }
    let orig_norm = orig
        .replace("#[no_mangle]", "")
        .replace("#[panic_handler]", "#[allow(dead_code)]")
        .replace("#[global_allocator]", "#[allow(dead_code)]");
    if undo == orig_norm { Ok(()) } else { Err(format!("unexpected rewrite:\n  {orig}\n  {new}")) }
}
