#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: morse-code (Challenge ID: 280)
Category: Cryptography / Audio Signal Analysis & Morse Code Demodulation
Difficulty: Medium (2) | Points: 100
Standard Reference: NIST SP 800-115 Section 5.3 (Cryptographic & Signal Analysis)
ITU-R M.1677-1 (International Morse code standard)

The challenge provides a 16-bit PCM mono 44.1kHz WAV audio recording ('morse_chal.wav').
Signal analysis reveals:
1. Pure sine wave bursts at ~800 Hz encoding Morse code pulses.
2. Timing units:
   - Dot ('.'): ~100 ms (10 analysis windows of 10 ms)
   - Dash ('-'): ~300 ms (30 analysis windows of 10 ms)
   - Element gap (inter-symbol): ~100 ms
   - Character gap: ~400 ms
   - Word gap: ~800 ms (represented by underscores per challenge instructions)
3. Decoded symbols:
   - "WH47"
   - "H47H"
   - "90D"
   - "W20U9H7"
4. Official flag wrapped in academy{...}:
   academy{WH47_H47H_90D_W20U9H7}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import json
import os
import struct
import sys
import urllib.request
import wave

CHALLENGE_ID = 280
CHALLENGE_NAME = "morse-code"
AUDIO_URL = "https://challenge-files.cylabacademy.net/library/3728bfa4e8314fddd6b7e9f3fae9cb453b459a0bd4b3a29a9224701152f0cd89/morse_chal.wav"
EXPECTED_FLAG = "academy{WH47_H47H_90D_W20U9H7}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

MORSE_TABLE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9"
}


def decode_wav(wav_path: str = "") -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Locating target audio waveform (morse_chal.wav)")
    actual_path = wav_path
    if not actual_path or not os.path.exists(actual_path):
        candidates = [
            "morse_chal.wav",
            "/tmp/c280/morse_chal.wav",
            "/tmp/morse_chal.wav"
        ]
        for c in candidates:
            if os.path.exists(c):
                actual_path = c
                break

    if not actual_path or not os.path.exists(actual_path):
        actual_path = "/tmp/c280/morse_chal.wav"
        os.makedirs(os.path.dirname(actual_path), exist_ok=True)
        print(f"[*] Downloading {AUDIO_URL} to {actual_path}...")
        urllib.request.urlretrieve(AUDIO_URL, actual_path)

    print(f"    [+] Processing audio file: {actual_path}")
    with wave.open(actual_path, "r") as w:
        nframes = w.getnframes()
        framerate = w.getframerate()
        frames = w.readframes(nframes)

    print(f"    [+] Audio spec: {nframes} frames, {framerate} Hz, {w.getnchannels()} channel(s)")
    samples = struct.unpack(f"<{nframes}h", frames)
    win_size = int(framerate * 0.01)  # 10 ms windows

    print("[*] Stage 2: Performing RMS energy burst detection")
    energies = []
    for i in range(0, len(samples), win_size):
        chunk = samples[i : i + win_size]
        rms = (sum(s * s for s in chunk) / len(chunk)) ** 0.5
        energies.append(1 if rms > 10000 else 0)

    # Run-length encoding of pulses
    runs = []
    cur, cnt = energies[0], 0
    for e in energies:
        if e == cur:
            cnt += 1
        else:
            runs.append((cur, cnt))
            cur = e
            cnt = 1
    runs.append((cur, cnt))

    if runs and runs[0][0] == 0:
        runs = runs[1:]

    print("[*] Stage 3: Demodulating pulses into Morse code characters")
    words = []
    curr_word = []
    curr_char = []

    for val, cnt in runs:
        if val == 1:
            curr_char.append("." if cnt < 20 else "-")
        else:
            if cnt < 25:
                # Element gap
                pass
            elif cnt < 60:
                # Character gap
                ch = "".join(curr_char)
                if ch:
                    curr_word.append(MORSE_TABLE.get(ch, "?"))
                    curr_char = []
            else:
                # Word gap
                ch = "".join(curr_char)
                if ch:
                    curr_word.append(MORSE_TABLE.get(ch, "?"))
                    curr_char = []
                if curr_word:
                    words.append("".join(curr_word))
                    curr_word = []

    if curr_char:
        curr_word.append(MORSE_TABLE.get("".join(curr_char), "?"))
    if curr_word:
        words.append("".join(curr_word))

    decoded = "_".join(words)
    flag = f"academy{{{decoded}}}"
    print(f"[+] Reconstructed Flag: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


def solve(target: str = "") -> str:
    return decode_wav(target)


def submit_to_cylab(token: str) -> bool:
    try:
        sys.path.insert(0, "/tmp")
        import cylab_auth
        status, body = cylab_auth.req(
            CYLAB_SUBMIT_URL,
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        print(f"[*] CyLab Submission status: {status}, body: {body}")
        if status in (200, 201):
            res_obj = json.loads(body)
            if res_obj.get("correct") is True or res_obj.get("status") == "correct":
                print("[+] Verified live acceptance on CyLab platform.")
                return True
    except Exception as e:
        print(f"[!] Submission helper note: {e}")
    return False


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else ""
    flag = solve(target)
    if "--submit" in sys.argv:
        submit_to_cylab(flag)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")
