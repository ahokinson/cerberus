import { mkdir, rm } from "node:fs/promises";
import { bin, dist } from "@builds/layouts.ts";
import { installBinary } from "@builds/packaging.ts";

await rm(dist, { recursive: true, force: true });
await mkdir(bin, { recursive: true });

const executable = await installBinary();

console.log(`cerberus release layout built at ${dist}`);
if (executable) console.log(`  ${executable}`);
