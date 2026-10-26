#!/usr/bin/env python3
"""
Solver for Challenge 460: RED (Forensics)
Extracts LSB steganography from the RGBA channels of red.png and decodes the Base64 payload.
"""
import urllib.request
import zlib
import base64

def solve(url="https://challenge-files.cylabacademy.net/library/fefcf06050d98347e1585e5cb9f2940967f82e0b89c591966473c752de9f3aba/red.png"):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        content = resp.read()
    
    # IDAT extraction
    idat_idx = content.find(b"IDAT")
    length = int.from_bytes(content[idat_idx-4:idat_idx], "big")
    decomp = zlib.decompress(content[idat_idx+4:idat_idx+4+length])
    
    # Reconstruct RGBA pixels
    stride = 128 * 4
    recon = bytearray(128 * stride)
    for y in range(128):
        filter_type = decomp[y * (stride + 1)]
        scanline = decomp[y * (stride + 1) + 1 : (y + 1) * (stride + 1)]
        for x in range(stride):
            filt = scanline[x]
            a = recon[y * stride + x - 4] if x >= 4 else 0
            b = recon[(y - 1) * stride + x] if y > 0 else 0
            c = recon[(y - 1) * stride + x - 4] if (y > 0 and x >= 4) else 0
            if filter_type == 0:
                val = filt
            elif filter_type == 1:
                val = (filt + a) & 0xff
            elif filter_type == 2:
                val = (filt + b) & 0xff
            elif filter_type == 3:
                val = (filt + (a + b) // 2) & 0xff
            elif filter_type == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                val = (filt + pr) & 0xff
            else:
                val = filt
            recon[y * stride + x] = val
            
    # LSB from RGBA
    bits = []
    for i in range(128 * 128):
        pixel = recon[i * 4 : (i + 1) * 4]
        bits.extend([pixel[0] & 1, pixel[1] & 1, pixel[2] & 1, pixel[3] & 1])
        
    extracted_bytes = bytearray()
    for i in range(0, len(bits) - 7, 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        extracted_bytes.append(b)
        
    # Extracted payload starts with Base64 string
    b64_str = extracted_bytes.split(b"=")[0].decode("ascii") + "=="
    flag = base64.b64decode(b64_str).decode("utf-8")
    return flag

if __name__ == "__main__":
    print("Flag:", solve())
