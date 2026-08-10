import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { keccak256, toHex } from "viem";

const termsPath = fileURLToPath(new URL("../TERMS.md", import.meta.url));
const bytes = readFileSync(termsPath);
process.stdout.write(`${keccak256(toHex(bytes))}\n`);
