"""Solver for challenge 130 MacroHard WeakEdge (picoCTF 2021, Forensics).

Forensics_is_fun.pptm is a ZIP (OOXML). Decoy layers: VBA macro
('sorry_but_this_is_not_it'), a hidden slide ('Not the flag'), and a
thumbnail reading 'Forensics is fun'. The real flag hides in the non-standard
entry ppt/slideMasters/hidden: space-obfuscated base64 -> decode with '=='
padding -> 'flag: academy{...}'.

Usage: solve_130_macrohard_weakedge.py <file.pptm>
"""
import base64
import re
import sys
import zipfile


def solve(path: str) -> str:
    z = zipfile.ZipFile(path)
    for name in z.namelist():
        if name.endswith('hidden'):
            raw = z.read(name).decode(errors='replace')
            b64 = re.sub(r'\s+', '', raw)
            flag = base64.b64decode(b64 + '==').decode()
            m = re.search(r'academy\{[^}]+\}', flag)
            assert m, 'flag not found'
            return m.group(0)
    raise ValueError('hidden entry not found')


if __name__ == '__main__':
    print(solve(sys.argv[1]))
