import { chmod, copyFile } from "node:fs/promises";
import { join } from "node:path";
import { bin, root, run } from "@builds/layouts.ts";

// CERBERUS_SKIP_CARGO lets a packager that builds the Rust binary itself
// assemble dist/bin.
export async function installBinary(): Promise<string | null> {
  if (process.env.CERBERUS_SKIP_CARGO) return null;
  run(["cargo", "build", "--release", "-p", "cerberus"]);
  const executable = process.platform === "win32" ? "cerberus.exe" : "cerberus";
  const destination = join(bin, executable);
  await copyFile(join(root, "target", "release", executable), destination);
  if (process.platform !== "win32") await chmod(destination, 0o755);
  return destination;
}
