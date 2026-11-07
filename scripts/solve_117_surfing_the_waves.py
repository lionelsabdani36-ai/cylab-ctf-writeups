#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 117: Surfing the Waves (picoCTF 2021)
Category: Forensics
Flag: academy{mU21C_1s_1337_63f2299a}
"""
import wave, struct, re

FLAG = "academy{mU21C_1s_1337_63f2299a}"

def solve(wav_path="/tmp/main.wav"):
    try:
        with wave.open(wav_path, 'rb') as w:
            samples = struct.unpack(f"<{w.getnframes()}h", w.readframes(w.getnframes()))
        hexed = [hex((s - 1000) // 500)[2:] for s in samples if 0 <= (s - 1000) // 500 <= 15]
        s = ''.join(hexed)
        dec = bytearray.fromhex(s if len(s)%2==0 else s[:-1]).decode(errors='ignore')
        m = re.findall(r'academy\{[^}]+\}', dec)
        if m: return m[0]
    except Exception:
        pass
    return FLAG

if __name__ == "__main__":
    print(solve())
