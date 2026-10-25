//! Raw Bitcoin transactions: Bitcoin Core's (de)serialization and the three signature hashes
//! (Core's legacy `SignatureHash`, BIP143, BIP341). The Motoko body in src/Transaction.mo is the
//! same algorithm, step for step.
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Core's MAX_SIZE: the largest CompactSize a deserializer accepts.
const MAX_SIZE: u64 = 0x0200_0000;

pub struct TxIn<'a> {
    pub outpoint: &'a [u8], // 36 bytes: txid, output index
    pub script: &'a [u8],
    pub sequence: &'a [u8], // 4 bytes
    pub witness: Vec<&'a [u8]>,
}

pub struct Tx<'a> {
    pub version: &'a [u8], // 4 bytes
    pub inputs: Vec<TxIn<'a>>,
    pub outputs: Vec<&'a [u8]>, // each a serialized output: value (8) + CompactSize + script
    pub lock_time: &'a [u8], // 4 bytes
}

pub struct Reader<'a> {
    pub b: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.b.len() - self.pos < n {
            return None;
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    /// A canonical CompactSize no larger than MAX_SIZE (Core's ReadCompactSize).
    pub fn compact(&mut self) -> Option<u64> {
        let first = self.byte()?;
        let n = match first {
            0xfd => {
                let s = self.take(2)?;
                let n = u16::from_le_bytes([s[0], s[1]]) as u64;
                if n < 0xfd { return None; }
                n
            }
            0xfe => {
                let s = self.take(4)?;
                let n = u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64;
                if n < 0x1_0000 { return None; }
                n
            }
            0xff => {
                let s = self.take(8)?;
                let n = u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
                if n < 0x1_0000_0000 { return None; }
                n
            }
            n => n as u64,
        };
        if n > MAX_SIZE { None } else { Some(n) }
    }
    pub fn field(&mut self) -> Option<&'a [u8]> {
        let n = self.compact()?;
        self.take(n as usize)
    }
    pub fn output(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        self.take(8)?;
        self.field()?;
        Some(&self.b[start..self.pos])
    }
}

fn inputs<'a>(r: &mut Reader<'a>, n: u64) -> Option<Vec<TxIn<'a>>> {
    let mut v = Vec::new();
    for _ in 0..n {
        let outpoint = r.take(36)?;
        let script = r.field()?;
        let sequence = r.take(4)?;
        v.push(TxIn { outpoint, script, sequence, witness: Vec::new() });
    }
    Some(v)
}

fn outputs<'a>(r: &mut Reader<'a>) -> Option<Vec<&'a [u8]>> {
    let n = r.compact()?;
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(r.output()?);
    }
    Some(v)
}

/// Core's `UnserializeTransaction` with witnesses allowed, and nothing may follow.
pub fn parse(b: &[u8]) -> Option<Tx<'_>> {
    let mut r = Reader { b, pos: 0 };
    let version = r.take(4)?;
    let mut flags = 0u8;
    let n = r.compact()?;
    let mut ins = inputs(&mut r, n)?;
    let mut outs = Vec::new();
    if ins.is_empty() {
        // An empty input list, or the segwit marker.
        flags = r.byte()?;
        if flags != 0 {
            let n = r.compact()?;
            ins = inputs(&mut r, n)?;
            outs = outputs(&mut r)?;
        }
    } else {
        outs = outputs(&mut r)?;
    }
    if flags & 1 != 0 {
        flags ^= 1;
        for i in ins.iter_mut() {
            let k = r.compact()?;
            for _ in 0..k {
                i.witness.push(r.field()?);
            }
        }
        if ins.iter().all(|i| i.witness.is_empty()) {
            return None; // "Superfluous witness record"
        }
    }
    if flags != 0 {
        return None; // "Unknown transaction optional data"
    }
    let lock_time = r.take(4)?;
    if r.pos != b.len() {
        return None;
    }
    Some(Tx { version, inputs: ins, outputs: outs, lock_time })
}

pub fn put_compact(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn put_field(out: &mut Vec<u8>, b: &[u8]) {
    put_compact(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// Core's serialization; with witnesses when `witness` and some input has one.
pub fn serialize(tx: &Tx, witness: bool) -> Vec<u8> {
    let w = witness && tx.inputs.iter().any(|i| !i.witness.is_empty());
    let mut out = Vec::new();
    out.extend_from_slice(tx.version);
    if w {
        out.extend_from_slice(&[0, 1]);
    }
    put_compact(&mut out, tx.inputs.len() as u64);
    for i in &tx.inputs {
        out.extend_from_slice(i.outpoint);
        put_field(&mut out, i.script);
        out.extend_from_slice(i.sequence);
    }
    put_compact(&mut out, tx.outputs.len() as u64);
    for o in &tx.outputs {
        out.extend_from_slice(o);
    }
    if w {
        for i in &tx.inputs {
            put_compact(&mut out, i.witness.len() as u64);
            for item in &i.witness {
                put_field(&mut out, item);
            }
        }
    }
    out.extend_from_slice(tx.lock_time);
    out
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn sha256d(b: &[u8]) -> [u8; 32] {
    sha256(&sha256(b))
}

/// Core's GetScriptOp: the opcode at `pc`, advancing past it and its push data. On failure
/// `pc` stays where Core leaves it (after the opcode, or after the length bytes).
fn get_op(s: &[u8], pc: &mut usize) -> Option<u8> {
    if *pc >= s.len() {
        return None;
    }
    let op = s[*pc];
    *pc += 1;
    if op <= 0x4e {
        let n = if op < 0x4c {
            op as usize
        } else if op == 0x4c {
            if s.len() - *pc < 1 { return None; }
            let n = s[*pc] as usize;
            *pc += 1;
            n
        } else if op == 0x4d {
            if s.len() - *pc < 2 { return None; }
            let n = u16::from_le_bytes([s[*pc], s[*pc + 1]]) as usize;
            *pc += 2;
            n
        } else {
            if s.len() - *pc < 4 { return None; }
            let n = u32::from_le_bytes([s[*pc], s[*pc + 1], s[*pc + 2], s[*pc + 3]]) as usize;
            *pc += 4;
            n
        };
        if s.len() - *pc < n {
            return None;
        }
        *pc += n;
    }
    Some(op)
}

/// Core's CTransactionSignatureSerializer::SerializeScriptCode: the script without its
/// OP_CODESEPARATORs, prefixed by its length less their number. Like Core, bytes after a push
/// that runs past the end are not written (the length still counts them).
fn script_code(out: &mut Vec<u8>, s: &[u8]) {
    let mut it = 0;
    let mut seps = 0u64;
    while let Some(op) = get_op(s, &mut it) {
        if op == 0xab {
            seps += 1;
        }
    }
    put_compact(out, s.len() as u64 - seps);
    let mut it = 0;
    let mut begin = 0;
    while let Some(op) = get_op(s, &mut it) {
        if op == 0xab {
            out.extend_from_slice(&s[begin..it - 1]);
            begin = it;
        }
    }
    if begin != s.len() {
        out.extend_from_slice(&s[begin..it]);
    }
}

/// Core's SignatureHash for SigVersion::BASE. `index` must be an input; SIGHASH_SINGLE without a
/// matching output gives Core's "1" (0x01 then 31 zero bytes).
pub fn sighash_legacy(tx: &Tx, index: usize, script: &[u8], hash_type: u32) -> [u8; 32] {
    let anyone = hash_type & 0x80 != 0;
    let single = hash_type & 0x1f == 3;
    let none = hash_type & 0x1f == 2;
    if single && index >= tx.outputs.len() {
        let mut one = [0u8; 32];
        one[0] = 1;
        return one;
    }
    let mut out = Vec::new();
    out.extend_from_slice(tx.version);
    let n_in = if anyone { 1 } else { tx.inputs.len() };
    put_compact(&mut out, n_in as u64);
    for k in 0..n_in {
        let k = if anyone { index } else { k };
        let i = &tx.inputs[k];
        out.extend_from_slice(i.outpoint);
        if k != index {
            put_compact(&mut out, 0);
        } else {
            script_code(&mut out, script);
        }
        if k != index && (single || none) {
            out.extend_from_slice(&[0; 4]);
        } else {
            out.extend_from_slice(i.sequence);
        }
    }
    let n_out = if none { 0 } else if single { index + 1 } else { tx.outputs.len() };
    put_compact(&mut out, n_out as u64);
    for k in 0..n_out {
        if single && k != index {
            out.extend_from_slice(&[0xff; 8]);
            put_compact(&mut out, 0);
        } else {
            out.extend_from_slice(tx.outputs[k]);
        }
    }
    out.extend_from_slice(tx.lock_time);
    out.extend_from_slice(&hash_type.to_le_bytes());
    sha256d(&out)
}

/// BIP143 (Core's SignatureHash for SigVersion::WITNESS_V0). `index` must be an input.
pub fn sighash_segwit_v0(tx: &Tx, index: usize, script: &[u8], amount: u64, hash_type: u32) -> [u8; 32] {
    let anyone = hash_type & 0x80 != 0;
    let base = hash_type & 0x1f;
    let mut prevouts = [0u8; 32];
    let mut sequences = [0u8; 32];
    let mut outputs = [0u8; 32];
    if !anyone {
        let mut b = Vec::new();
        for i in &tx.inputs {
            b.extend_from_slice(i.outpoint);
        }
        prevouts = sha256d(&b);
    }
    if !anyone && base != 3 && base != 2 {
        let mut b = Vec::new();
        for i in &tx.inputs {
            b.extend_from_slice(i.sequence);
        }
        sequences = sha256d(&b);
    }
    if base != 3 && base != 2 {
        let mut b = Vec::new();
        for o in &tx.outputs {
            b.extend_from_slice(o);
        }
        outputs = sha256d(&b);
    } else if base == 3 && index < tx.outputs.len() {
        outputs = sha256d(tx.outputs[index]);
    }
    let i = &tx.inputs[index];
    let mut out = Vec::new();
    out.extend_from_slice(tx.version);
    out.extend_from_slice(&prevouts);
    out.extend_from_slice(&sequences);
    out.extend_from_slice(i.outpoint);
    put_field(&mut out, script);
    out.extend_from_slice(&amount.to_le_bytes());
    out.extend_from_slice(i.sequence);
    out.extend_from_slice(&outputs);
    out.extend_from_slice(tx.lock_time);
    out.extend_from_slice(&hash_type.to_le_bytes());
    sha256d(&out)
}

/// BIP341's SigMsg with epoch 0, hashed as TapSighash. `prevouts` are the spent outputs, one per
/// input. None for an undefined hash type, or SIGHASH_SINGLE without a matching output.
pub fn sighash_taproot(
    tx: &Tx,
    index: usize,
    prevouts: &[&[u8]],
    hash_type: u8,
    annex: Option<&[u8]>,
    leaf: Option<(&[u8], u32)>,
) -> Option<[u8; 32]> {
    if !matches!(hash_type, 0x00 | 0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83) {
        return None;
    }
    let anyone = hash_type & 0x80 != 0;
    let out_type = hash_type & 3;
    if out_type == 3 && index >= tx.outputs.len() {
        return None;
    }
    let mut m = Vec::new();
    m.push(0x00); // epoch
    m.push(hash_type);
    m.extend_from_slice(tx.version);
    m.extend_from_slice(tx.lock_time);
    if !anyone {
        let mut a = Vec::new();
        let mut b = Vec::new();
        let mut c = Vec::new();
        let mut d = Vec::new();
        for (i, p) in tx.inputs.iter().zip(prevouts) {
            a.extend_from_slice(i.outpoint);
            b.extend_from_slice(&p[..8]);
            c.extend_from_slice(&p[8..]);
            d.extend_from_slice(i.sequence);
        }
        for x in [&a, &b, &c, &d] {
            m.extend_from_slice(&sha256(x));
        }
    }
    if out_type != 2 && out_type != 3 {
        let mut b = Vec::new();
        for o in &tx.outputs {
            b.extend_from_slice(o);
        }
        m.extend_from_slice(&sha256(&b));
    }
    m.push(if leaf.is_some() { 2 } else { 0 } + if annex.is_some() { 1 } else { 0 });
    if anyone {
        let i = &tx.inputs[index];
        m.extend_from_slice(i.outpoint);
        m.extend_from_slice(prevouts[index]);
        m.extend_from_slice(i.sequence);
    } else {
        m.extend_from_slice(&(index as u32).to_le_bytes());
    }
    if let Some(a) = annex {
        let mut b = Vec::new();
        put_field(&mut b, a);
        m.extend_from_slice(&sha256(&b));
    }
    if out_type == 3 {
        m.extend_from_slice(&sha256(tx.outputs[index]));
    }
    if let Some((h, pos)) = leaf {
        m.extend_from_slice(h);
        m.push(0x00); // key_version
        m.extend_from_slice(&pos.to_le_bytes());
    }
    Some(crate::tagged(b"TapSighash", &m))
}
