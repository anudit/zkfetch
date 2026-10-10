#!/usr/bin/env python3
"""Bind produced artifacts to a clean commit; never serialize build credentials."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
paths = ["packages/native/zkf.node", "packages/wasm/pkg/zkf_bg.wasm",
         "packages/wasm/pkg-threads/zkf_bg.wasm", ".zkf/build-all/artifacts/zkf-notary"]
paths += [str(p.relative_to(root)) for p in (root / "packages/chrome-extension/dist").rglob("*") if p.is_file()]

def run(*args):
    return subprocess.check_output(args, cwd=root, text=True).strip()

sources = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates", "vendor", "packages", "infra/aws"]
dirty = bool(run("git", "diff", "HEAD", "--", *sources)) or bool(run("git", "ls-files", "--others", "--exclude-standard", "--", *sources))
if dirty:
    raise SystemExit("Build inputs changed during the build; provenance refused")
artifacts = {}
for name in sorted(set(paths)):
    data = (root / name).read_bytes()
    artifacts[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
report = {"commit": run("git", "rev-parse", "HEAD"), "tree": run("git", "rev-parse", "HEAD^{tree}"),
          "sourceDirty": False, "rustc": run("rustc", "-Vv"), "bun": run("bun", "--version"),
          "wasmPack": run("wasm-pack", "--version"), "artifacts": artifacts,
          "note": "Hashes identify this build; bit-identical rebuild reproducibility must be tested separately."}
output = Path(sys.argv[1])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(report, indent=2) + "\n")
print(f"Provenance written for {len(artifacts)} artifacts at {report['commit'][:12]}")
