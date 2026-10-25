// Tests of the SDK (../src/lib.rs), compiled INSIDE its rewritten module (build.rs), so they
// reach its private items (the panic handler's buffer) as well as its API.
use crate::native::{free_scratch, run, scratch_count, take_output, Stop};

#[test]
fn sdk_bytes() {
    // An empty argument: the slice is empty whatever the pointer (null included).
    assert!(unsafe { bytes(std::ptr::null(), 0) }.is_empty());
    assert!(unsafe { bytes(std::ptr::NonNull::<u8>::dangling().as_ptr(), 0) }.is_empty());
    let v: Vec<u8> = (0..=255).collect();
    for n in [1, 7, 8, 255, 256] {
        assert_eq!(unsafe { bytes(v.as_ptr(), n) }, &v[..n]);
    }
}

#[test]
fn sdk_output_and_text() {
    for n in [0usize, 1, 7, 8, 9, 63, 64, 1000] {
        let data: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
        let r = run(|| output(&data)).unwrap();
        assert_eq!(scratch_count(), 1, "output takes one block");
        assert_eq!(take_output(r).unwrap(), data);
        free_scratch();
    }
    let r = run(|| text("é ⊕ 𝔸")).unwrap();
    assert_eq!(String::from_utf8(take_output(r).unwrap()).unwrap(), "é ⊕ 𝔸");
    free_scratch();
    assert_eq!(NONE, 0);
}

#[test]
fn sdk_trap() {
    assert_eq!(run(|| trap(b"kernel says no")), Err(Stop::Trap("kernel says no".into())));
    assert_eq!(run(|| trap(b"")), Err(Stop::Trap(String::new())));
}

#[test]
fn sdk_allocator() {
    use std::alloc::{GlobalAlloc, Layout};
    let a = KernelAllocator;
    for align in [1usize, 2, 4, 8, 16, 64, 4096] {
        for size in [1usize, 3, 8, 100, 4097] {
            let l = Layout::from_size_align(size, align).unwrap();
            unsafe {
                let p = a.alloc(l);
                assert_eq!(p.addr() % align, 0, "alignment {align}");
                p.write_bytes(0xab, size);
                // dealloc frees nothing (the program's collector does, after the call).
                a.dealloc(p, l);
                assert_eq!(*p.add(size - 1), 0xab);
                // realloc (GlobalAlloc's default: a new block and a copy) keeps the contents.
                let q = a.realloc(p, l, size * 2 + 1);
                assert_eq!(std::slice::from_raw_parts(q, size), &vec![0xab; size][..]);
                q.add(size * 2).write(1);
                let z = a.alloc_zeroed(l);
                assert!(std::slice::from_raw_parts(z, size).iter().all(|&b| b == 0));
            }
        }
    }
    assert!(scratch_count() > 0);
    free_scratch();
}

/// The panic handler's buffer: the message is cut at 256 bytes -- at a byte, so a multi-byte
/// character there is cut in the middle (kernel_trap's text then ends in a partial UTF-8
/// sequence; ic0.trap takes bytes, so this costs at most one garbled character).
#[test]
fn sdk_panic_message_buffer() {
    use core::fmt::Write;
    let mut b = Buf { bytes: [0; 256], len: 0 };
    write!(b, "native kernel panicked: {}", "x".repeat(300)).unwrap();
    assert_eq!(b.len, 256);
    assert!(b.bytes.starts_with(b"native kernel panicked: xxx"));
    let mut b = Buf { bytes: [0; 256], len: 0 };
    write!(b, "{}{}", "x".repeat(255), "é").unwrap();
    assert_eq!(b.len, 256);
    assert!(std::str::from_utf8(&b.bytes[..b.len]).is_err(), "cut inside 'é'");
}

