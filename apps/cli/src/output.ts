import { closeSync, fsyncSync, mkdtempSync, openSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

/** Replace the directory entry, never open an existing destination or symlink. */
export function writePrivateFile(path: string, data: string) {
  const staging = mkdtempSync(join(dirname(path), ".zkfetch-"));
  const temporary = join(staging, "session");
  try {
    const fd = openSync(temporary, "wx", 0o600);
    try {
      writeFileSync(fd, data);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temporary, path);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}
