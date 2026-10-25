#!/usr/bin/env python3
"""Constant-time scan of a pinned native kernel's compiled wasm (gate: scripts/kernel_ct_scan_gate.sh).

The kernels' Rust is written constant-time where it touches secrets (masks, subtle's Choice,
crypto-bigint's ct ops), but LLVM may prove a mask is 0 or all ones and turn it back into a branch
or an address select. Instruction counts can stay equal (both arms the same length), so the
instruction-count constant-time tests (run on PocketIC) cannot see it; an off-chain host
compiles the wasm to native code, where a branch on a secret and a load from a secret-chosen
address are branch-predictor and cache timing leaks. It happened twice (found in review,
2026-10-24): the secp256k1 comb (libsecp's AffineStorage::cmov) and RSA's pow_secret + reduce_once.

WHAT IS SCANNED. Each kernel has a reviewed policy, kernels/ct-scan/allow/<kernel>.toml:
  roots    the exports that take secret input, with the parameter indices of their secret
           buffers: { secret = [0], why = "..." };
  public   every other export, with the reason it sees no secret;
  exclude  functions reachable from the roots that are not scanned, with a reason (panic paths;
           shared ones in common.toml);
  ct       globs of the constant-time core: must be among the scanned functions, and may only
           be allowed site by site;
  allow    accepted sites per function glob: `sites` (exact count per "kind op condition") or
           `any` (an exact total, for variable-time library code accepted as a whole), and `why`.
The scanned set is the roots plus every function they reach by direct calls, minus exclusions
(call_indirect targets are not followed: in every kernel they are the panic formatter's dyn
Write/Debug methods; a call_indirect's effect on memory is assumed unbounded). Rust inlines most of
the secret arithmetic into the exports, so export bodies are scanned like any other function, and
a function a rebuild stops inlining is scanned automatically. An unclassified export, a site that
is not allowed with exactly its count, or an allow entry that no longer matches, fails.

THE ANALYSIS. A forward abstract interpretation of each function over wasm's structured control
flow (flow-sensitive per local, stack slot and stack-frame byte range; loops iterated to a
fixpoint), interprocedural through summaries iterated to a fixpoint: what each function's callers
pass it, and what each function may write through its pointer parameters (exact offsets where
known), through other pointers, which parameters it stores or returns, and which it dereferences.
A value is PUBLIC when it is computed only from constants, globals (stack pointer, memory base)
and the roots' parameters (host pointers and lengths) or bytes the policy calls public; it is
DATA ("may be secret") when it depends on a secret parameter's bytes, anything returned or
written by a call, memory of unknown provenance, or frame bytes with no known writer. Static data
(__memory_base-relative: tables, constants) is PUBLIC. subtle::black_box is the identity.
Reported:
  branch        a br_if, if, br_table or call_indirect index whose condition is DATA;
  addr-select   a select with a DATA condition whose result reaches a load/store/copy/fill
                address or length (what LLVM made of the secp256k1 cmov and RSA reduce_once);
  call-select   such a select result passed to a callee that dereferences that parameter;
  addr-index    a load/store/copy into the frame, static data or a host buffer at an index
                computed from DATA (a secret-indexed table lookup), or a DATA copy/fill length;
  static-write  a store into static data (none expected: the analysis assumes it is read-only).
A select of DATA values used only as a value is not reported (engines compile select to a
conditional move: Cranelift does). Implicit flows are not tracked (the branch itself is
reported). Known imprecision, all on the side of reporting more: unknown-offset frame writes and
callee writes without exact offsets taint everything at or above them; bytes behind a pointer
parameter are DATA. Known unsoundness: a select-chosen address reloaded from the frame at an
unknown offset loses its mark; a pointer joined from two frame offsets is treated as any frame
offset (sound) but pointer arithmetic is assumed to add non-negative indices only to the pointer
it started from (Rust's bounds-checked indexing).

A site is keyed by (function, kind, op, condition text): the condition is the expression that
computes it, depth-limited, with C a constant, G a global, P a public parameter, `?` a join of
different expressions, loads as their opcode and calls as call:<name>. Line numbers are printed
but not keyed, so a rebuild that only moves code does not disturb the policy; one that adds a
site changes a count and fails. Sources (argN = bytes of secret parameter N, call:<f>, load,
frame) are printed for review, not keyed.

usage: scan.py <kernel.toml | x.wasm> [--policy P.toml] [--name <kernel>] [--list] [--json]
               [--suggest | --suggest-by-function] [--root EXPORT=I,J ...] [--expect-fail GLOB ...]
  --list         print every scanned function and every site, allowed or not
  --suggest      print [[allow]] entries (exact site maps) for the unallowed sites, why = "TODO"
  --root         ad-hoc root (repeatable; e.g. a probe export of a scratch build): scan it with
                 parameters I, J secret, with no policy except common.toml's exclusions
  --expect-fail  teeth mode: exit 0 only if the scan FAILS with an unallowed site in a function
                 matching each glob (the gate runs it on the pre-fix pins)
Needs wasm-tools on PATH and Python >= 3.11. Exit 0 pass, 1 findings, 2 setup error.
"""
import base64
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile

try:
    import tomllib
except ImportError:  # Python < 3.11
    print('ct-scan: needs Python >= 3.11 (tomllib)', file=sys.stderr)
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))


# ---- input ---------------------------------------------------------------------------------

def wasm_bytes(path):
    data = open(path, 'rb').read()
    if path.endswith('.toml'):
        m = re.search(r'wasm = """(.*?)"""', data.decode(), re.S)
        if not m:
            raise SystemExit(f'ct-scan: no wasm in {path}')
        return base64.b64decode(''.join(m.group(1).split()))
    return data


def disassemble(wasm):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 'k.wasm')
        open(p, 'wb').write(wasm)
        r = subprocess.run(['wasm-tools', 'print', p], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(f'ct-scan: wasm-tools print failed: {r.stderr.strip()}')
        return r.stdout.split('\n')


# ---- module structure ----------------------------------------------------------------------

NAME = r'\$(?:"((?:[^"\\]|\\.)*)"|(\S+))'
FUNC_RE = re.compile(r'^  \(func ' + NAME + r'(?: \(@name "((?:[^"\\]|\\.)*)"\))? \(;(\d+);\) \(type (\d+)\)')
IMPORT_RE = re.compile(r'^  \(import "[^"]*" "[^"]*" \(func ' + NAME + r' \(;(\d+);\) \(type (\d+)\)')
TYPE_RE = re.compile(r'^  \(type \(;(\d+);\) \(func(.*)\)\)$')
EXPORT_RE = re.compile(r'^  \(export "([^"]*)" \(func ' + NAME + r'\)\)')
CALL_RE = re.compile(r'^call ' + NAME + r'$')
VALTYPES = ('i32', 'i64', 'f32', 'f64', 'v128')


def ident(m, a, b):
    return m.group(a) if m.group(a) is not None else m.group(b)


class Func:
    def __init__(self, ident_, display, typ, start):
        self.ident, self.name, self.type, self.start = ident_, display, typ, start
        self.lines = []      # (wat line number, instruction text)
        self.nlocals = 0


class Module:
    def __init__(self, wat):
        self.types = {}      # type index -> (nparams, nresults)
        self.funcs = {}      # identifier -> Func (defined functions)
        self.ftype = {}      # identifier -> type index (imports and defined)
        self.exports = {}    # export name -> identifier
        self.indirect = set()
        cur = None
        for n, line in enumerate(wat, 1):
            m = TYPE_RE.match(line)
            if m:
                sig = m.group(2)
                params = sum(len([t for t in g.split() if t in VALTYPES]) for g in re.findall(r'\(param ([^)]*)\)', sig))
                results = sum(len([t for t in g.split() if t in VALTYPES]) for g in re.findall(r'\(result ([^)]*)\)', sig))
                self.types[int(m.group(1))] = (params, results)
                continue
            m = IMPORT_RE.match(line)
            if m:
                self.ftype[ident(m, 1, 2)] = int(m.group(4))
                continue
            m = EXPORT_RE.match(line)
            if m:
                self.exports[m.group(1)] = ident(m, 2, 3)
                continue
            if line.startswith('  (elem '):
                self.indirect |= {a or b for a, b in re.findall(NAME, line.split(' func ', 1)[1])}
                continue
            m = FUNC_RE.match(line)
            if m:
                fid = ident(m, 1, 2)
                cur = Func(fid, m.group(3) or fid, int(m.group(5)), n)
                self.funcs[fid] = cur
                self.ftype[fid] = cur.type
                continue
            if cur is None:
                continue
            if line == '  )' or (line.startswith('  (') and not line.startswith('   ')):
                cur = None
                continue
            s = line.strip()
            if s.startswith('(local '):
                cur.nlocals += len([t for t in s[7:-1].split() if t in VALTYPES])
                continue
            if s:
                cur.lines.append((n, s))

    def nparams(self, fid):
        return self.types[self.ftype[fid]][0]

    def callees(self, f):
        out = set()
        for _, s in f.lines:
            m = CALL_RE.match(s)
            if m:
                out.add(ident(m, 1, 2))
        return out


# ---- instruction tree ----------------------------------------------------------------------

def block_arity(s):
    s = s.split(';;')[0]
    return sum(len([t for t in g.split() if t in VALTYPES]) for g in re.findall(r'\(result ([^)]*)\)', s))


def build_tree(lines):
    """[(line, op, rest)] with blocks as ('block'|'loop'|'if', line, arity, body, else_body)."""
    root = []
    stack = [(None, root)]
    for n, s in lines:
        op = s.split()[0]
        if op in ('block', 'loop', 'if'):
            node = [op, n, block_arity(s), [], None]
            stack[-1][1].append(node)
            stack.append((node, node[3]))
        elif op == 'else':
            node = stack[-1][0]
            node[4] = []
            stack[-1] = (node, node[4])
        elif op == 'end':
            stack.pop()
        else:
            stack[-1][1].append((n, op, s))
    if len(stack) != 1:
        raise SystemExit('ct-scan: unbalanced blocks')
    return root


# ---- abstract values -----------------------------------------------------------------------
# A value is (src, sels, expr, aux):
#   src   frozenset of DATA origins (empty: PUBLIC):
#           'argN'      bytes of a root's parameter N buffer (the secret key, the digest, ...)
#           'call:<f>'  returned by f, or written by f into this frame
#           'load'      memory of unknown provenance (through a pointer loaded from memory, or a
#                       caller's frame)
#           'frame'     frame bytes with no known writer
#   sels  wat lines of DATA-conditioned selects this value passed through
#   expr  the expression text used in finding keys (C constant, G global, P public parameter)
#   aux   what is known about it as an address or a constant:
#           ('k', v)              the constant v
#           ('p', off, idx)       this function's stack frame + off (None: unknown); idx = the
#                                 DATA sources of an index added to it
#           ('d', off, idx)       static data (__memory_base-relative): tables and constants
#           ('a', c, off, idx)    a root's parameter (a host buffer) + off; c = its bytes' sources
#                                 ({'argN'} for a secret parameter N, empty for a public one)
#           ('q', n, off, idx)    this function's parameter n (a pointer into a caller's memory)
#           ('x', idx)            may point into this frame (a frame pointer joined with another)

EMPTY = frozenset()
NEG_INF = float('-inf')
MAXEXPR = 72
UNINIT = (EMPTY, EMPTY, 'C', ('k', 0))   # wasm locals start at zero
LOAD_SRC = frozenset({'load'})


def short(name):
    # Drop generic arguments for readability and stability; keep the path.
    out, depth = [], 0
    for ch in name:
        if ch == '<':
            depth += 1
            if depth == 1:
                out.append('<…')
            continue
        if ch == '>':
            depth -= 1
            if depth == 0:
                out.append('>')
            continue
        if depth == 0:
            out.append(ch)
    s = ''.join(out)
    return s if len(s) <= 60 else '…' + s[-59:]


def sub_expr(e):
    return e if len(e) <= MAXEXPR // 2 else '…'


def ptr(aux):
    return aux is not None and aux[0] in ('p', 'd', 'a', 'q', 'x')


def idx_of(aux):
    return aux[-1] if ptr(aux) else EMPTY


def offset(aux, delta, idx):
    """aux (a pointer) moved by delta (None: an unknown amount), with idx added to its index."""
    k = aux[0]
    if k == 'x':
        return ('x', aux[1] | idx)
    if k in ('a', 'q'):
        off = aux[2]
        return (k, aux[1], None if off is None or delta is None else off + delta, aux[3] | idx)
    off = aux[1]
    return (k, None if off is None or delta is None else off + delta, aux[2] | idx)


def join_aux(a, b):
    if a == b:
        return a
    if a is None or b is None:
        o = a if b is None else b
        return ('x', idx_of(o)) if o is not None and o[0] in ('p', 'x') else None
    ka, kb = a[0], b[0]
    if ka == kb and ka in ('p', 'd'):
        return (ka, a[1] if a[1] == b[1] else None, a[2] | b[2])
    if ka == kb == 'q' and a[1] == b[1]:
        return (ka, a[1], a[2] if a[2] == b[2] else None, a[3] | b[3])
    if ka == kb == 'a':
        return ('a', a[1] | b[1], a[2] if a[2] == b[2] else None, a[3] | b[3])
    if ka in ('p', 'x') or kb in ('p', 'x'):
        return ('x', idx_of(a) | idx_of(b))
    return None


def join(a, b):
    if a is b or a == b:
        return a
    return (a[0] | b[0], a[1] | b[1], a[2] if a[2] == b[2] else '?', join_aux(a[3], b[3]))


def binop(op, a, b):
    src, sels = a[0] | b[0], a[1] | b[1]
    expr = f'{op}({sub_expr(a[2])},{sub_expr(b[2])})'
    base = op.split('.', 1)[1]
    ka, kb = a[3], b[3]
    ca = ka is not None and ka[0] == 'k'
    cb = kb is not None and kb[0] == 'k'
    aux = None
    if base == 'add':
        if ptr(ka) and ptr(kb):
            # Two pointer-like values (a pointer and a public length, both parameters): keep
            # the frame-ness, otherwise unknown.
            if ka[0] in ('p', 'x') or kb[0] in ('p', 'x'):
                aux = ('x', idx_of(ka) | idx_of(kb))
        elif ptr(ka):
            aux = offset(ka, kb[1] if cb else None, EMPTY if cb else b[0])
        elif ptr(kb):
            aux = offset(kb, ka[1] if ca else None, EMPTY if ca else a[0])
        elif ca and cb:
            aux = ('k', ka[1] + kb[1])
    elif base == 'sub':
        if ptr(ka) and not ptr(kb):
            aux = offset(ka, -kb[1] if cb else None, EMPTY if cb else b[0])
        elif ca and cb:
            aux = ('k', ka[1] - kb[1])
    elif base == 'and' and ptr(ka) and cb:
        aux = offset(ka, None, EMPTY)      # alignment
    return (src, sels, expr, aux)


class Mem:
    """The function's own stack frame: bytes at known offsets from the incoming stack pointer.

    e:   (off, size) -> (value, bulk); disjoint after every write (joins may leave overlaps, and
         a read then unions them). bulk entries (copies, fills, callee writes, splits) give only
         their sources.
    bg:  from-offset (NEG_INF: anywhere) -> sources that MAY have been written at or above it
         (a store through an unknown frame offset; a callee's unbounded or wild writes).
    esc: the lowest frame offset whose address escaped into memory, or None.
    sp:  the current stack pointer's offset (a function moves it in its prologue).
    """
    __slots__ = ('e', 'bg', 'esc', 'sp')

    def __init__(self):
        self.e, self.bg, self.esc, self.sp = {}, {}, None, 0

    def copy(self):
        m = Mem()
        m.e, m.bg, m.esc, m.sp = dict(self.e), dict(self.bg), self.esc, self.sp
        return m

    def __eq__(self, o):
        return self.e == o.e and self.bg == o.bg and self.esc == o.esc and self.sp == o.sp

    def bg_at(self, off, size):
        out = EMPTY
        for f, s in self.bg.items():
            if f == NEG_INF or off is None or f < off + size:
                out = out | s
        return out

    def read(self, off, size, op):
        bg = self.bg_at(off, size)
        if off is None:
            # An unknown offset may read any byte: every source. Not every select mark, though:
            # a select-chosen address is spilled to and reloaded from a fixed slot, and an
            # array read at a computed index would otherwise inherit every selected value
            # stored anywhere in the frame (measured: 16 false addr-selects in ML-DSA sign).
            src = bg
            for (o, s), (v, _) in self.e.items():
                src = src | v[0]
            return (src | {'frame'}, EMPTY, op, None)
        over = [((o, s), v, bulk) for (o, s), (v, bulk) in self.e.items() if o < off + size and off < o + s]
        if len(over) == 1 and over[0][0] == (off, size) and not over[0][2] and not bg:
            return over[0][1]
        src, sels, covered = bg, EMPTY, 0
        for (o, s), v, _ in over:
            src, sels = src | v[0], sels | v[1]
            covered += min(o + s, off + size) - max(o, off)
        if covered < size and not bg:
            src = src | {'frame'}
        if len(over) == 1 and over[0][1][2].startswith('call:'):
            return (src, sels, over[0][1][2], None)
        return (src, sels, op, None)

    def write(self, off, size, v, bulk=False):
        new = {}
        for (o, s), (ov, ob) in self.e.items():
            if o + s <= off or off + size <= o:
                new[(o, s)] = (ov, ob)
                continue
            if o < off:
                new[(o, off - o)] = ((ov[0], ov[1], ov[2], None), True)
            if o + s > off + size:
                new[(off + size, o + s - off - size)] = ((ov[0], ov[1], ov[2], None), True)
        new[(off, size)] = (v, bulk)
        self.e = new

    def may_write(self, off, size, src, expr):
        """A callee may have written `src` over [off, off + size): joined into what is there,
        and the bytes nothing covers become a bulk entry."""
        cover = []
        for k, (v, b) in list(self.e.items()):
            if k[0] < off + size and off < k[0] + k[1]:
                cover.append(k)
                if not src <= v[0] or v[3] is not None or v[2] != expr:
                    self.e[k] = ((v[0] | src, v[1], expr if v[2] == expr else '?', join_aux(v[3], None)), b)
        pos = off
        for o, s in sorted(cover):
            if o > pos:
                self.e[(pos, o - pos)] = ((src, EMPTY, expr, None), True)
            pos = max(pos, o + s)
        if pos < off + size:
            self.e[(pos, off + size - pos)] = ((src, EMPTY, expr, None), True)

    def clobber(self, frm, src, expr):
        """May-write `src` anywhere at or above frame offset frm (NEG_INF: anywhere)."""
        if not src:
            return
        for k, (v, b) in list(self.e.items()):
            if frm == NEG_INF or k[0] + k[1] > frm:
                if not src <= v[0] or v[3] is not None:
                    self.e[k] = ((v[0] | src, v[1], expr if v[2] == expr else '?', join_aux(v[3], None)), b)
        self.bg[frm] = self.bg.get(frm, EMPTY) | src

    def escape(self, off):
        off = NEG_INF if off is None else off
        self.esc = off if self.esc is None else min(self.esc, off)

    def join(self, o):
        m = Mem()
        if self.sp != o.sp:
            raise SystemExit('ct-scan: stack pointer differs at a join')
        m.sp = self.sp
        m.esc = self.esc if o.esc is None else o.esc if self.esc is None else min(self.esc, o.esc)
        m.bg = dict(self.bg)
        for f, s in o.bg.items():
            m.bg[f] = m.bg.get(f, EMPTY) | s
        for k in set(self.e) | set(o.e):
            a, b = self.e.get(k), o.e.get(k)
            if a and b:
                m.e[k] = (join(a[0], b[0]), a[1] or b[1])
            else:
                (v, bulk), other = (a, o) if a else (b, self)
                m.e[k] = (join(v, other.read(k[0], k[1], v[2])), bulk)
        return m


class State:
    __slots__ = ('locs', 'stack', 'mem')

    def __init__(self, locs, stack, mem):
        self.locs, self.stack, self.mem = locs, stack, mem

    def copy(self, stack=None):
        return State(list(self.locs), list(self.stack) if stack is None else stack, self.mem.copy())


def join_state(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if len(a.stack) != len(b.stack):
        raise SystemExit('ct-scan: stack height mismatch at a join')
    return State([join(x, y) for x, y in zip(a.locs, b.locs)],
                 [join(x, y) for x, y in zip(a.stack, b.stack)], a.mem.join(b.mem))


# ---- interprocedural summaries -------------------------------------------------------------

class Summary:
    """What a call to a function does to its caller, as far as this scan needs it.

    writes[n]  parameter n's memory it may write: ({(off, size): sources}, unbounded sources
               or None) -- offsets from the pointer passed
    wild       sources it may write through pointers it did not get as parameters (None: never)
    escapes    the parameters whose pointer value it stores into memory
    returns    the parameters its result may point into
    addrs      the parameters it uses (or passes on) as an address
    """
    __slots__ = ('writes', 'wild', 'escapes', 'returns', 'addrs')

    def __init__(self):
        self.writes, self.wild, self.escapes, self.returns, self.addrs = {}, None, set(), set(), set()

    def key(self):
        return (sorted((n, sorted(w[0].items()), w[1]) for n, w in self.writes.items()),
                self.wild, sorted(self.escapes), sorted(self.returns), sorted(self.addrs))

    def write(self, n, off, size, src):
        w = self.writes.setdefault(n, ({}, None))
        if off is None or size is None:
            self.writes[n] = (w[0], (w[1] or EMPTY) | src)
        else:
            w[0][(off, size)] = w[0].get((off, size), EMPTY) | src

    def add_wild(self, src):
        self.wild = (self.wild or EMPTY) | src


NOTHING = Summary()                 # imports: kernel_alloc returns a fresh block, kernel_trap traps


def unknown_summary(name, nparams):
    """A callee that is not analysed (excluded, or call_indirect): it may do anything."""
    s = Summary()
    src = frozenset({'call:' + name})
    for n in range(nparams):
        s.writes[n] = ({}, src)
    s.wild = src
    s.escapes = set(range(nparams))
    s.returns = set(range(nparams))
    s.addrs = set(range(nparams))
    return s


def param_value(a):
    """What a callee may assume about a parameter from this argument: its sources, and its
    base when it is a constant, a root's host buffer or static data. Any other pointer (into
    the caller's frame, or loaded) becomes the callee's own parameter pointer, whose bytes are
    'load' (or argN when every caller passes a root's buffer)."""
    aux = a[3]
    if aux is not None and aux[0] == 'a':
        aux = ('a', aux[1], None, aux[3])
    elif aux is not None and aux[0] == 'd':
        aux = ('d', None, aux[2])
    elif aux is None or aux[0] != 'k':
        aux = ('m',)
    return (a[0], EMPTY, 'param' if a[0] else 'P', aux)


def join_param(a, b):
    if a == b:
        return a
    ka, kb = a[3], b[3]
    src = a[0] | b[0]
    if ka == kb:
        aux = ka
    elif ka is not None and kb is not None and ka[0] == kb[0] and ka[0] in ('a', 'd'):
        aux = join_aux(ka, kb)
    elif all(k is None or k[0] == 'k' for k in (ka, kb)):
        aux = None
    else:
        aux = ('m',)
    return (src, EMPTY, 'param' if src else 'P', aux)


UNARY = re.compile(r'^(i32|i64|f32|f64)\.(eqz|clz|ctz|popcnt|neg|abs|sqrt|ceil|floor|trunc|nearest|'
                   r'extend\d+_s|extend_i32_[su]|wrap_i64|trunc_\w+|convert_\w+|reinterpret_\w+|demote_f64|promote_f32)$')
BINARY = re.compile(r'^(i32|i64|f32|f64)\.(add|sub|mul|div(_[su])?|rem_[su]|and|or|xor|shl|shr_[su]|rotl|rotr|'
                    r'eq|ne|lt(_[su])?|gt(_[su])?|le(_[su])?|ge(_[su])?|min|max|copysign)$')
LOAD = re.compile(r'^(i32|i64|f32|f64)\.load(\d+)?(_[su])?$')
STORE = re.compile(r'^(i32|i64|f32|f64)\.store(\d+)?$')
MEMARG_OFF = re.compile(r'offset=(\d+)')


def access_size(op):
    m = re.match(r'^(i32|i64|f32|f64)\.(?:load|store)(\d+)?', op)
    return int(m.group(2)) // 8 if m.group(2) else int(m.group(1)[1:]) // 8


class Label:
    __slots__ = ('kind', 'arity', 'state')

    def __init__(self, kind, arity):
        self.kind, self.arity, self.state = kind, arity, None


class Analysis:
    MAX_ITER = 64

    def __init__(self, module, func, params, summaries):
        self.m, self.f, self.summaries = module, func, summaries
        self.param_values, self.qcontent = [], {}
        for n, p in enumerate(params):
            if p[3] is not None and p[3][0] == 'm':
                self.param_values.append((p[0], EMPTY, p[2], ('q', n, 0, EMPTY)))
                self.qcontent[n] = LOAD_SRC
            else:
                self.param_values.append(p)
        self.calls = {}        # callee -> joined argument values (the callee's parameter summary)
        self.summary = Summary()
        self.branches = {}     # line -> (op, cond value)
        self.selects = {}      # line -> cond value
        self.sel_uses = {}     # select line -> {(use, line)}
        self.indexed = {}      # line -> (op, address value): DATA index into a known base
        self.static_writes = set()

    def run(self):
        f = self.f
        st = State(list(self.param_values) + [UNINIT] * f.nlocals, [], Mem())
        nres = self.m.types[f.type][1]
        out = self.block(build_tree(f.lines), st, [Label('func', nres)])
        if out is not None:
            self.returned(out)
        return self

    def returned(self, st):
        for v in st.stack[len(st.stack) - 1:] if st.stack else []:
            if v[3] is not None and v[3][0] == 'q':
                self.summary.returns.add(v[3][1])

    # -- control ---------------------------------------------------------------------------

    def block(self, nodes, st, labels):
        for node in nodes:
            if st is None:
                return None
            st = self.structured(node, st, labels) if isinstance(node, list) else self.instr(node, st, labels)
        return st

    @staticmethod
    def top(st, arity):
        return None if st is None else State(st.locs, st.stack[len(st.stack) - arity:] if arity else [], st.mem)

    def structured(self, node, st, labels):
        kind, line, arity, body, else_body = node
        if kind == 'if':
            cond = st.stack.pop()
            if cond[0]:
                self.branches[line] = ('if', cond)
        base = list(st.stack)
        if kind == 'loop':
            head = State(st.locs, [], st.mem)
            for _ in range(self.MAX_ITER):
                lab = Label('loop', 0)
                out = self.block(body, head.copy(stack=list(base)), labels + [lab])
                if lab.state is None:
                    break
                new = join_state(head, lab.state)
                if new.locs == head.locs and new.mem == head.mem:
                    break
                head = new
            else:
                raise SystemExit(f'ct-scan: no fixpoint for the loop at wat line {line} ({self.f.name})')
            if out is None:
                return None
            out = self.top(out, arity)
        else:
            lab = Label(kind, arity)
            out = self.top(self.block(body, st.copy(stack=list(base)), labels + [lab]), arity)
            if kind == 'if':
                out2 = self.block(else_body, st.copy(stack=list(base)), labels + [lab]) if else_body is not None else st.copy(stack=[])
                out = join_state(out, self.top(out2, arity))
            out = join_state(out, lab.state)
        if out is None:
            return None
        return State(out.locs, base + out.stack, out.mem)

    def branch_to(self, labels, depth, st):
        lab = labels[len(labels) - 1 - depth]
        if lab.kind == 'func':
            self.returned(st)
            return
        s = State(list(st.locs), [] if lab.kind == 'loop' else (st.stack[len(st.stack) - lab.arity:] if lab.arity else []), st.mem.copy())
        lab.state = join_state(lab.state, s)

    # -- memory ----------------------------------------------------------------------------

    def use_addr(self, v, use, line):
        if v[3] is not None and v[3][0] == 'q':
            self.summary.addrs.add(v[3][1])
        for s in v[1]:
            self.sel_uses.setdefault(s, set()).add((use, line))
        aux = v[3]
        if ptr(aux) and aux[-1] and aux[0] != 'x':
            self.indexed[line] = (use, v)

    def content(self, a, op, off, size, st):
        """The value loaded from address a (+ off)."""
        aux = a[3]
        if aux is not None and aux[0] == 'p':
            v = st.mem.read(None if aux[1] is None else aux[1] + off, size, op)
            return (v[0] | aux[2], v[1], v[2], v[3])
        if aux is not None and aux[0] == 'x':
            v = st.mem.read(None, size, op)
            return (v[0] | aux[1] | LOAD_SRC, v[1], op, None)
        if aux is not None and aux[0] == 'd':
            return (aux[2], EMPTY, 'static', None)
        if aux is not None and aux[0] == 'a':
            return (aux[1] | aux[3], EMPTY, op, None)
        if aux is not None and aux[0] == 'q':
            return (self.qcontent[aux[1]] | aux[3] | a[0], EMPTY, op, None)
        return (a[0] | LOAD_SRC, EMPTY, op, None)

    def store(self, st, a, v, off, size, line, bulk=False):
        """Store v at address a (+ off); size None: unknown."""
        aux = a[3]
        if v[3] is not None and v[3][0] in ('p', 'x'):
            st.mem.escape(v[3][1] if v[3][0] == 'p' else None)
        if v[3] is not None and v[3][0] == 'q':
            self.summary.escapes.add(v[3][1])
        if aux is not None and aux[0] == 'p':
            if aux[1] is None or size is None:
                st.mem.clobber(NEG_INF if aux[1] is None else aux[1] + off, v[0] | aux[2] | {'frame'}, v[2])
            else:
                st.mem.write(aux[1] + off, size, v, bulk)
        elif aux is not None and aux[0] == 'x':
            st.mem.clobber(NEG_INF, v[0] | aux[1] | {'frame'}, v[2])
            self.summary.add_wild(v[0] | aux[1])
        elif aux is not None and aux[0] == 'd':
            self.static_writes.add(line)
        elif aux is not None and aux[0] == 'a':
            pass                     # a root's output buffer, in the host's memory
        elif aux is not None and aux[0] == 'q':
            self.summary.write(aux[1], None if aux[2] is None else aux[2] + off, size, v[0] | aux[3])
        else:
            self.summary.add_wild(v[0] | a[0])
            if st.mem.esc is not None:
                st.mem.clobber(st.mem.esc, v[0] | a[0] | LOAD_SRC, v[2])

    def apply_call(self, st, name, s, args, line):
        """The effect of a call with summary s on this frame and on this function's summary."""
        label = frozenset({'call:' + name})
        expr = 'call:' + name
        for n, a in enumerate(args):
            aux = a[3]
            w = s.writes.get(n)
            if aux is None or aux[0] not in ('p', 'x', 'q'):
                continue
            if n in s.escapes:
                if aux[0] == 'q':
                    self.summary.escapes.add(aux[1])
                else:
                    st.mem.escape(aux[1] if aux[0] == 'p' else None)
            if w is None:
                continue
            ranges, unb = w
            if aux[0] == 'p' and aux[1] is not None:
                for (o, sz), src in ranges.items():
                    st.mem.may_write(aux[1] + o, sz, (src | label) if src else EMPTY, expr)
                if unb is not None:
                    st.mem.clobber(aux[1], (unb | label) if unb else EMPTY, expr)
            elif aux[0] in ('p', 'x'):
                allsrc = EMPTY.union(*ranges.values()) | (unb or EMPTY)
                st.mem.clobber(NEG_INF, (allsrc | label) if allsrc else EMPTY, expr)
                if aux[0] == 'x':
                    self.summary.add_wild(allsrc)
            else:   # our own parameter: the callee's writes become ours, shifted
                for (o, sz), src in ranges.items():
                    self.summary.write(aux[1], None if aux[2] is None else aux[2] + o, sz, src | label if src else EMPTY)
                if unb is not None:
                    self.summary.write(aux[1], None, None, (unb | label) if unb else EMPTY)
        if s.wild is not None:
            self.summary.add_wild(s.wild)
            if st.mem.esc is not None:
                st.mem.clobber(st.mem.esc, (s.wild | label) if s.wild else EMPTY, expr)
        # The result: a pointer into an argument's memory when the callee may return one.
        aux = None
        for n in sorted(s.returns):
            if n < len(args) and ptr(args[n][3]):
                aux = offset(args[n][3], None, EMPTY) if aux is None else join_aux(aux, offset(args[n][3], None, EMPTY))
        return aux

    # -- instructions ----------------------------------------------------------------------

    def instr(self, node, st, labels):
        line, op, text = node
        stack = st.stack
        pop, push = stack.pop, stack.append
        if op == 'local.get':
            push(st.locs[int(text.split()[1])])
        elif op == 'local.set':
            st.locs[int(text.split()[1])] = pop()
        elif op == 'local.tee':
            st.locs[int(text.split()[1])] = stack[-1]
        elif op == 'global.get':
            g = text.split()[1]
            if g == '$__stack_pointer':
                push((EMPTY, EMPTY, 'G', ('p', st.mem.sp, EMPTY)))
            elif g == '$__memory_base':
                push((EMPTY, EMPTY, 'G', ('d', 0, EMPTY)))
            else:
                push((EMPTY, EMPTY, 'G', None))
        elif op == 'global.set':
            v = pop()
            if text.split()[1] == '$__stack_pointer':
                if v[3] is None or v[3][0] != 'p' or v[3][1] is None:
                    raise SystemExit(f'ct-scan: unknown stack pointer at wat line {line} ({self.f.name})')
                st.mem.sp = v[3][1]
        elif op.endswith('.const'):
            t = text.split()[1]
            try:
                push((EMPTY, EMPTY, 'C', ('k', int(t, 0))))
            except ValueError:
                push((EMPTY, EMPTY, 'C', None))
        elif LOAD.match(op):
            a = pop()
            self.use_addr(a, op, line)
            m = MEMARG_OFF.search(text)
            push(self.content(a, op, int(m.group(1)) if m else 0, access_size(op), st))
        elif STORE.match(op):
            v = pop()
            a = pop()
            self.use_addr(a, op, line)
            m = MEMARG_OFF.search(text)
            self.store(st, a, v, int(m.group(1)) if m else 0, access_size(op), line)
        elif BINARY.match(op):
            b = pop()
            a = pop()
            push(binop(op, a, b))
        elif UNARY.match(op):
            a = pop()
            push((a[0], a[1], f'{op}({sub_expr(a[2])})', None))
        elif op == 'select':
            c, b, a = pop(), pop(), pop()
            v = (a[0] | b[0] | c[0], a[1] | b[1], f'select({sub_expr(c[2])})', join_aux(a[3], b[3]))
            if c[0]:
                self.selects[line] = c
                v = (v[0], v[1] | {line}, v[2], v[3])
            push(v)
        elif op == 'drop':
            pop()
        elif op in ('memory.copy', 'memory.fill'):
            n, s, d = pop(), pop(), pop()
            for x in (n, d) + ((s,) if op == 'memory.copy' else ()):
                self.use_addr(x, op, line)
            if n[0]:
                self.indexed[line] = (op + ' length', n)
            size = n[3][1] if n[3] is not None and n[3][0] == 'k' else None
            if op == 'memory.copy':
                sa = s[3]
                if sa is not None and sa[0] == 'p' and sa[1] is not None and size is not None and size > 0:
                    v = st.mem.read(sa[1], size, op)
                    src = v[0] | sa[2]
                elif sa is not None and sa[0] in ('p', 'x'):
                    src = st.mem.read(None, 1, op)[0] | idx_of(sa)
                else:
                    src = self.content(s, op, 0, 1, st)[0]
                val = (src | n[0], EMPTY, 'memory.copy', None)
            else:
                val = (s[0] | n[0], s[1], f'memory.fill({sub_expr(s[2])})', None)
            if size == 0:
                pass
            else:
                self.store(st, d, val, 0, size, line, bulk=True)
        elif op == 'memory.size':
            push((EMPTY, EMPTY, 'C', None))
        elif op == 'memory.grow':
            pop()
            push((frozenset({'call:memory.grow'}), EMPTY, 'memory.grow', None))
        elif op == 'call':
            m = CALL_RE.match(text)
            callee = ident(m, 1, 2)
            np, nr = self.m.types[self.m.ftype[callee]]
            args = [pop() for _ in range(np)][::-1]
            name = short(self.display(callee))
            if self.display(callee).startswith('subtle::black_box') and np == 1 and nr == 1:
                # subtle's optimisation barrier (a volatile read of its argument): the identity.
                a = args[0]
                push((a[0], a[1], f'black_box({sub_expr(a[2])})', None))
                return st
            if callee in self.summaries:
                s = self.summaries[callee]
            elif callee not in self.m.funcs:
                s = NOTHING
            else:
                s = unknown_summary(name, np)
            # A select-chosen argument matters where the callee uses that parameter as an
            # address (directly or by passing it on); a value argument is just a value.
            for n, a in enumerate(args):
                if n in s.addrs:
                    for sl in a[1]:
                        self.sel_uses.setdefault(sl, set()).add(('call ' + name, line))
                    if a[3] is not None and a[3][0] == 'q':
                        self.summary.addrs.add(a[3][1])
            summary = [param_value(a) for a in args]
            old = self.calls.get(callee)
            self.calls[callee] = summary if old is None else [join_param(x, y) for x, y in zip(old, summary)]
            aux = self.apply_call(st, name, s, args, line)
            for _ in range(nr):
                push((frozenset({'call:' + name}), EMPTY, 'call:' + name, aux))
        elif op == 'call_indirect':
            t = int(re.search(r'\(type (\d+)\)', text).group(1))
            np, nr = self.m.types[t]
            idx = pop()
            if idx[0]:
                self.branches[line] = ('call_indirect', idx)
            self.use_addr(idx, op, line)
            args = [pop() for _ in range(np)][::-1]
            aux = self.apply_call(st, 'call_indirect', unknown_summary('call_indirect', np), args, line)
            for _ in range(nr):
                push((frozenset({'call_indirect'}), EMPTY, 'call_indirect', aux))
        elif op == 'br':
            self.branch_to(labels, int(text.split()[1]), st)
            return None
        elif op == 'br_if':
            c = pop()
            if c[0]:
                self.branches[line] = ('br_if', c)
            self.branch_to(labels, int(text.split()[1]), st)
        elif op == 'br_table':
            c = pop()
            if c[0]:
                self.branches[line] = ('br_table', c)
            for d in set(re.findall(r'(\d+) \(;@', text)):
                self.branch_to(labels, int(d), st)
            return None
        elif op == 'return':
            self.returned(st)
            return None
        elif op == 'unreachable':
            return None
        elif op == 'nop':
            pass
        else:
            raise SystemExit(f'ct-scan: unknown instruction {op!r} at wat line {line} ({self.f.name})')
        return st

    def display(self, fid):
        f = self.m.funcs.get(fid)
        return f.name if f else fid

    def findings(self):
        out = []
        for line, (op, c) in sorted(self.branches.items()):
            out.append({'function': self.f.name, 'kind': 'branch', 'op': op, 'line': line,
                        'cond': c[2], 'sources': sorted(c[0])})
        for line, c in sorted(self.selects.items()):
            uses = self.sel_uses.get(line)
            if not uses:
                continue
            kinds = {k for k, _ in uses}
            kind = 'addr-select' if any(not k.startswith('call ') for k in kinds) else 'call-select'
            out.append({'function': self.f.name, 'kind': kind, 'op': 'select', 'line': line,
                        'cond': c[2], 'sources': sorted(c[0]),
                        'uses': sorted(f'{k}@{u}' for k, u in uses)[:6]})
        for line, (use, v) in sorted(self.indexed.items()):
            src = v[3][-1] if ptr(v[3]) else v[0]
            out.append({'function': self.f.name, 'kind': 'addr-index', 'op': use.split()[0], 'line': line,
                        'cond': v[2], 'sources': sorted(src)})
        for line in sorted(self.static_writes):
            out.append({'function': self.f.name, 'kind': 'static-write', 'op': 'store', 'line': line,
                        'cond': '-', 'sources': []})
        return out


# ---- policy --------------------------------------------------------------------------------

KINDS = ('branch', 'addr-select', 'call-select', 'addr-index', 'static-write')


def load_policy(path):
    with open(path, 'rb') as fh:
        pol = tomllib.load(fh)
    with open(os.path.join(HERE, 'common.toml'), 'rb') as fh:
        com = tomllib.load(fh)
    unknown = set(pol) - {'roots', 'public', 'exclude', 'allow', 'ct'}
    if unknown:
        raise SystemExit(f'ct-scan: {path}: unknown sections {sorted(unknown)}')
    pol.setdefault('roots', {})
    pol.setdefault('public', {})
    pol['exclude'] = {**com.get('exclude', {}), **pol.get('exclude', {})}
    pol.setdefault('allow', [])
    pol.setdefault('ct', [])
    for name, r in pol['roots'].items():
        if not isinstance(r, dict) or not isinstance(r.get('secret'), list) or not str(r.get('why', '')).strip():
            raise SystemExit(f'ct-scan: {path}: [roots] {name} needs {{ secret = [parameter indices], why = "..." }}')
    for k in ('public', 'exclude'):
        for name, why in pol[k].items():
            if not isinstance(why, str) or not why.strip():
                raise SystemExit(f'ct-scan: {path}: [{k}] "{name}" needs a one-line reason')
    for a in pol['allow']:
        if 'function' not in a or 'why' not in a or not str(a['why']).strip():
            raise SystemExit(f'ct-scan: {path}: an [[allow]] entry needs `function` and a `why`: {a}')
        if ('sites' in a) == ('any' in a):
            raise SystemExit(f'ct-scan: {path}: an [[allow]] entry needs exactly one of `sites` or `any`: {a["function"]}')
        if 'sites' in a:
            for k, n in a['sites'].items():
                if k.split(' ', 1)[0] not in KINDS or not isinstance(n, int) or n < 1:
                    raise SystemExit(f'ct-scan: {path}: bad site {k!r} = {n!r} in {a["function"]}')
    return pol


def site_key(fd):
    return f'{fd["kind"]} {fd["op"]} {fd["cond"]}'


def matches(a, fd):
    return fnmatch.fnmatchcase(fd['function'], a['function']) and ('any' in a or site_key(fd) in a['sites'])


def scan(module, pol):
    exports = {e: fid for e, fid in module.exports.items() if not e.startswith('__wasm_')}
    problems = []
    for e in sorted(exports):
        if e not in pol['roots'] and e not in pol['public']:
            problems.append(f'export {e} is neither a [roots] nor a [public] entry: classify it')
    for e in list(pol['roots']) + list(pol['public']):
        if e not in exports:
            problems.append(f'the policy names export {e}, which the kernel does not have')
    excluded = lambda name: any(fnmatch.fnmatchcase(name, pat) for pat in pol['exclude'])
    # The roots and their direct-call closure, minus the exclusions.
    roots = {exports[e]: r for e, r in pol['roots'].items() if e in exports}
    order, seen, work = [], set(), list(roots)
    while work:
        fid = work.pop(0)
        if fid in seen or fid not in module.funcs:
            continue
        seen.add(fid)
        f = module.funcs[fid]
        if fid not in roots and excluded(f.name):
            continue
        order.append(fid)
        work.extend(sorted(module.callees(f)))
    # A fixpoint of two summaries: what each function's callers pass it, and what each function
    # does to its callers' memory (Summary). A root's parameters are the host's pointers and
    # lengths (PUBLIC values); the bytes behind a parameter the policy calls secret are argN.
    root_params = {}
    for fid, r in roots.items():
        np = module.nparams(fid)
        bad = [i for i in r['secret'] if not isinstance(i, int) or not 0 <= i < np]
        if bad:
            problems.append(f'root {module.funcs[fid].name}: secret parameter indices {bad} out of range (it has {np})')
        root_params[fid] = [(EMPTY, EMPTY, 'P', ('a', frozenset({f'arg{i}'}) if i in r['secret'] else EMPTY, 0, EMPTY))
                            for i in range(np)]
    params = dict(root_params)
    summaries = {fid: Summary() for fid in order if fid not in roots}
    results = {}
    for _ in range(40):
        changed = False
        new_params = dict(root_params)
        for fid in order:
            if fid not in params:
                continue
            an = Analysis(module, module.funcs[fid], params[fid], summaries).run()
            results[fid] = an
            if fid in summaries and an.summary.key() != summaries[fid].key():
                summaries[fid] = an.summary
                changed = True
            for callee, args in an.calls.items():
                if callee in summaries:
                    old = new_params.get(callee)
                    new_params[callee] = args if old is None else [join_param(x, y) for x, y in zip(old, args)]
        if new_params != params:
            params = new_params
            changed = True
        if not changed:
            break
    else:
        raise SystemExit('ct-scan: the interprocedural summaries did not converge')
    findings, scanned = [], []
    for fid in order:
        if fid in results:
            scanned.append(module.funcs[fid].name)
            findings.extend(results[fid].findings())
    # Each finding goes to the first allow entry that matches it; every entry's count must be
    # exactly what it matched.
    matched = [[] for _ in pol['allow']]
    unallowed = []
    for fd in findings:
        for i, a in enumerate(pol['allow']):
            if matches(a, fd):
                matched[i].append(fd)
                fd['allowed'] = i
                break
        else:
            unallowed.append(fd)
    # The constant-time core: present and scanned (a rename or full inlining must be noticed),
    # and allowed only site by site.
    for g in pol['ct']:
        if not any(fnmatch.fnmatchcase(n, g) for n in scanned):
            problems.append(f'ct function {g} is not among the scanned functions (renamed, inlined, or no longer reached?)')
    for a, fds in zip(pol['allow'], matched):
        if 'any' in a:
            ct_hit = sorted({fd['function'] for fd in fds if any(fnmatch.fnmatchcase(fd['function'], g) for g in pol['ct'])})
            if ct_hit:
                problems.append(f'allow entry {a["function"]} uses `any` for ct functions {ct_hit}: list their sites')
            if len(fds) != a['any']:
                problems.append(f'allow entry for {a["function"]} expects any = {a["any"]} sites, found {len(fds)} '
                                f'(wat lines {[fd["line"] for fd in fds][:20]}): review the change, then update it')
            continue
        got = {}
        for fd in fds:
            got.setdefault(site_key(fd), []).append(fd['line'])
        for k, n in a['sites'].items():
            if len(got.get(k, [])) != n:
                problems.append(f'allow entry for {a["function"]}: site "{k}" expects {n}, found '
                                f'{len(got.get(k, []))} (wat lines {got.get(k, [])[:20]}): review the change, then update it')
    return scanned, findings, unallowed, problems


def fmt(fd):
    s = f'{fd["kind"]:11} {fd["op"]:8} wat:{fd["line"]:<7} {fd["function"]}\n' \
        f'            cond {fd["cond"]}\n            sources [{", ".join(fd["sources"])}]'
    if 'uses' in fd:
        s += f'\n            used by {", ".join(fd["uses"])}'
    return s


def toml_str(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def suggest(findings, by_function):
    """Allow entries for the given findings, one per function (to start or update a policy;
    every `why` must be written by a reviewer)."""
    groups = {}
    for fd in findings:
        groups.setdefault(fd['function'], []).append(fd)
    out = []
    for fn, fds in groups.items():
        out.append('[[allow]]')
        out.append(f'function = {toml_str(fnmatch_escape(fn))}')
        out.append('why = "TODO"')
        if by_function:
            out.append(f'any = {len(fds)}')
        else:
            sites = {}
            for fd in fds:
                sites.setdefault(site_key(fd), []).append(fd)
            out.append('[allow.sites]')
            for k, v in sites.items():
                srcs = sorted(set().union(*[set(f['sources']) for f in v]))
                out.append(f'# wat {[f["line"] for f in v][:8]} [{", ".join(srcs)[:200]}]')
                out.append(f'{toml_str(k)} = {len(v)}')
        out.append('')
    return '\n'.join(out)


def fnmatch_escape(s):
    return ''.join(f'[{c}]' if c in '*?[' else c for c in s)


def main(argv):
    args = argv[1:]
    opts = {'--policy': None, '--name': None}
    flags = set()
    expect = []
    pos = []
    adhoc = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a in opts:
            opts[a] = args[i + 1]
            i += 2
        elif a == '--root':
            e, _, idx = args[i + 1].partition('=')
            adhoc[e] = {'secret': [int(x) for x in idx.split(',') if x], 'why': 'ad hoc (--root)'}
            i += 2
        elif a in ('--list', '--json', '--suggest', '--suggest-by-function'):
            flags.add(a)
            i += 1
        elif a == '--expect-fail':
            expect = args[i + 1:]
            break
        else:
            pos.append(a)
            i += 1
    if len(pos) != 1:
        print(__doc__[__doc__.index('usage:'):], file=sys.stderr)
        return 2
    src = pos[0]
    name = opts['--name'] or os.path.basename(src).split('.')[0]
    module = Module(disassemble(wasm_bytes(src)))
    if not module.funcs:
        print(f'ct-scan: {name}: no functions parsed (wasm-tools output changed?)')
        return 2
    if adhoc:
        with open(os.path.join(HERE, 'common.toml'), 'rb') as fh:
            com = tomllib.load(fh)
        pol = {'roots': adhoc, 'exclude': com.get('exclude', {}), 'allow': [], 'ct': [],
               'public': {e: 'ad hoc' for e in module.exports if e not in adhoc and not e.startswith('__wasm_')}}
    else:
        policy = opts['--policy'] or os.path.join(HERE, 'allow', f'{name}.toml')
        if not os.path.exists(policy):
            print(f'ct-scan: no policy for kernel {name} ({policy}): every shipped kernel needs one')
            return 2
        pol = load_policy(policy)
    scanned, findings, unallowed, problems = scan(module, pol)
    if '--suggest' in flags or '--suggest-by-function' in flags:
        print(suggest(unallowed, '--suggest-by-function' in flags))
        return 0
    if '--json' in flags:
        print(json.dumps({'kernel': name, 'scanned': scanned, 'findings': findings,
                          'unallowed': unallowed, 'problems': problems}, indent=1))
    else:
        print(f'{name}: {len(pol["roots"])} secret roots, {len(scanned)} functions scanned, '
              f'{len(findings)} DATA-dependent sites ({len(findings) - len(unallowed)} allowed), '
              f'{len(unallowed)} NOT allowed, {len(problems)} policy problems')
        if '--list' in flags:
            for s in scanned:
                print(f'  scanned: {s}')
            for fd in findings:
                tag = f'allow#{fd["allowed"]}' if 'allowed' in fd else 'NEW'
                print(f'  [{tag}] ' + fmt(fd))
        for fd in unallowed:
            print('  FINDING ' + fmt(fd))
        for p in problems:
            print('  POLICY  ' + p)
    failed = bool(unallowed or problems)
    if expect:
        missing = [g for g in expect if not any(fnmatch.fnmatchcase(fd['function'], g) for fd in unallowed)]
        if missing:
            print(f'  TEETH: no unallowed finding in {missing}: the scan does not catch the old code')
            return 1
        print(f'  TEETH: the scan fails on this wasm as it must ({len(unallowed)} unallowed sites, in {expect})')
        return 0
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
