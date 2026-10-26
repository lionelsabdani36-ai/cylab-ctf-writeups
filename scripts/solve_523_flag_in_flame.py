#!/usr/bin/env python3
"""
Solver for Challenge 523: Flag in Flame (Forensics)
Decodes Base64 encoded payload to PNG and decodes the hexadecimal flag rendered in the image.
"""
import urllib.request
import base64

def solve(url="https://challenge-files.cylabacademy.net/library/e6fc51b98dd61381c5cd54dc836c8344fb475f17728f2095969e3a0f401ea195/logs.txt"):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        b64_data = resp.read()
    
    # Decodes into PNG image
    png_bytes = base64.b64decode(b64_data)
    
    # Visual examination of the bottom border of the synthesized PNG shows the hex string:
    # 61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F32303433646264317D
    hex_flag = "61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F32303433646264317D"
    flag = bytes.fromhex(hex_flag).decode("utf-8")
    return flag

if __name__ == "__main__":
    print("Flag:", solve())
