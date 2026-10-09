import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writePrivateFile } from "./output";

test("private session writes replace symlinks and restrict permissions under umask 022", () => {
  const dir = mkdtempSync(join(tmpdir(), "zkfetch-output-"));
  const old = process.umask(0o022);
  try {
    const target = join(dir, "target");
    const path = join(dir, "session");
    writeFileSync(target, "unchanged");
    symlinkSync(target, path);
    writePrivateFile(path, "secret");
    expect(readFileSync(target, "utf8")).toBe("unchanged");
    expect(readFileSync(path, "utf8")).toBe("secret");
    expect(statSync(path).mode & 0o777).toBe(0o600);
    writePrivateFile(path, "replacement");
    expect(readFileSync(path, "utf8")).toBe("replacement");
    expect(statSync(path).mode & 0o777).toBe(0o600);
  } finally {
    process.umask(old);
    rmSync(dir, { recursive: true, force: true });
  }
});
