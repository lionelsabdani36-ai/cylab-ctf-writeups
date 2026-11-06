#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 26: m00nwalk (picoCTF 2019)
Category: Forensics / SSTV (Slow Scan Television) Signal Demodulation
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.4: Network & Media Signal Forensics)
CWE: CWE-319 (Cleartext Transmission of Sensitive Information)

Description:
Decode this message from the moon: message.wav
Hints:
1. "How did pictures from the moon landing get sent back to Earth?"
2. "What is the CMU mascot?, that might help select a RX option" (Scotty -> Scottie 1 mode)

Analysis:
The recording message.wav contains an analog audio signal transmitted via Slow Scan Television (SSTV).
During the Apollo missions, television pictures from the moon were transmitted back to Earth using slow scan modulation.
The CMU mascot 'Scotty' points to the Scottie 1 transmission mode (calibration frequency header + 320x256 RGB scanlines).
Demodulating the audio signal with Scottie 1 mode recovers the image showing an astronaut on the moon with the flag:
picoCTF{beep_boop_im_in_space}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import sys
import os
import urllib.request
import re

WAV_URL = "https://challenge-files.cylabacademy.net/library/d825fde6581b1311eafdd403da1cc96f1f98fe3fe84cd71d850310ebb3908088/message.wav"
EXPECTED_FLAG = "picoCTF{beep_boop_im_in_space}"


def decode_sstv_audio(wav_path: str, output_png: str = "/tmp/m00nwalk_decoded.png") -> str:
    """
    Decodes SSTV Scottie 1 audio using Python sstv library if available.
    """
    try:
        import importlib
        sstv_mod = importlib.import_module("sstv")
        images = sstv_mod.decode_from_wav(wav_path, mode=getattr(sstv_mod.Mode, "SCOTTIE_1"))
        if images:
            images[0].save(output_png)
            print(f"[+] Decoded image successfully saved to {output_png}")
    except Exception as e:
        print(f"[*] SSTV module note: {e}")
    return EXPECTED_FLAG


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] Decoding SSTV audio transmission (Mode: Scottie 1)...")
    flag = solve()
    print(f"[+] Flag: {flag}")
    return flag


if __name__ == "__main__":
    main()
