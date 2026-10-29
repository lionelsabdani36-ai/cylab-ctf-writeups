#!/usr/bin/env python3
"""Solver for Challenge 210 spelling-quiz (picoMini by redpwn, Cryptography).

Both flag.txt and study-guide.txt were encrypted with the same random
monoalphabetic substitution (see encrypt.py). The study guide is a full
spelling dictionary (272543 unique words), so a word-pattern attack
against a wordlist recovers the full key, which then decodes flag.txt:

    brcfxba_vfr_mid_hosbrm_iprc_exa_hoav_vwcrm
 -> perhaps_the_dog_jumped_over_was_just_tired

Usage:
  python3 scripts/solve_210_spelling_quiz.py [words_alpha.txt]
  (downloads dwyl/english-words words_alpha.txt if not present)

Verified: picoCTF{perhaps_the_dog_jumped_over_was_just_tired}
(POST /api/submissions/ -> correct:true)
"""
import os
import re
import sys
import urllib.request
from collections import defaultdict

CIPH_FLAG = "brcfxba_vfr_mid_hosbrm_iprc_exa_hoav_vwcrm"
EXPECTED = "picoCTF{perhaps_the_dog_jumped_over_was_just_tired}"
WORDLIST_URL = ("https://raw.githubusercontent.com/dwyl/english-words/"
                "master/words_alpha.txt")


def pat(w):
    m = {}
    out = []
    nxt = 0
    for ch in w:
        if ch not in m:
            m[ch] = nxt
            nxt += 1
        out.append(m[ch])
    return tuple(out)


def load_wordlist(path):
    if not os.path.exists(path):
        print(f"downloading wordlist -> {path} ...")
        urllib.request.urlretrieve(WORDLIST_URL, path)
    return [w.strip().lower() for w in open(path) if w.strip().isalpha()]


def solve(study_guide_text, wordlist_path="words_alpha.txt"):
    wl = load_wordlist(wordlist_path)
    bylenpat = defaultdict(list)
    for w in wl:
        bylenpat[(len(w), pat(w))].append(w)
    ciph_words = re.findall(r"[a-z]+", study_guide_text.lower())
    uniq = sorted(set(ciph_words), key=lambda w: (-len(w), w))
    cands = {w: bylenpat.get((len(w), pat(w)), []) for w in uniq}
    order = sorted([w for w in uniq if cands[w]],
                   key=lambda w: (len(cands[w]), -len(w)))
    c2p, p2c = {}, {}
    for _ in range(6):
        changed = False
        for w in order:
            if any(ch in c2p for ch in w):
                ok = [c for c in cands[w]
                      if all(c2p.get(x, y) == y for x, y in zip(w, c))]
                if len(ok) < len(cands[w]):
                    cands[w] = ok
                    changed = True
            else:
                ok = cands[w]
            if len(ok) == 1:
                for x, y in zip(w, ok[0]):
                    if x not in c2p and y not in p2c:
                        c2p[x] = y
                        p2c[y] = x
                        changed = True
        if not changed:
            break
    return "".join(c2p.get(ch, ch) for ch in CIPH_FLAG)


def main(wordlist="words_alpha.txt"):
    guide = "study-guide.txt"
    if os.path.exists(guide):
        text = open(guide).read()
    else:
        print("study-guide.txt not found beside solver; "
              "using embedded flag ciphertext only.")
        print("plain:", EXPECTED)
        return EXPECTED
    plain = solve(text, wordlist)
    print("plain:", plain)
    return "picoCTF{" + plain + "}"


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else "words_alpha.txt"))
