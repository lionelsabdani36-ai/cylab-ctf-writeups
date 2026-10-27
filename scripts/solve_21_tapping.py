#!/usr/bin/env python3
"""
Solver for Challenge 21: Tapping (Cryptography)
Decodes Morse code stream received over netcat into flag format.
"""

def solve(raw_morse: str = ".- -.-. .- -.. . -- -.-- { -- ----- .-. ... ...-- -.-. ----- -.. ...-- .---- ... ..-. ..- -. .---- --... ---.. -.. .- --... ----. ---.. }") -> str:
    morse_dict = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z',
        '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
        '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
        '{': '{', '}': '}'
    }
    tokens = raw_morse.strip().split()
    decoded = "".join(morse_dict.get(t, '') for t in tokens)
    return decoded.lower()

if __name__ == "__main__":
    print("Flag:", solve())
