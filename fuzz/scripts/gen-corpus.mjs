#!/usr/bin/env node
// Generate the seed corpus for the fuzz targets.
//
// Seeds are deliberately minimal-but-valid wire payloads so libFuzzer starts
// from inputs the parsers accept (already past the header byte and into the
// interesting branches) instead of rediscovering the format from scratch.
//
// This is a ONE-TIME setup step: the generated seeds are committed to git and
// used directly by CI. It is NOT run in CI.
//
// Layout produced (all paths relative to fuzz/):
//   corpus/hybrid_init_parse/{enc,bundle}_{classic,hybrid}.bin
//   corpus/envelope_parse/envelope_valid.hex
//
// Usage (from the repo root or from fuzz/):
//   node fuzz/scripts/gen-corpus.mjs
//
// Zero dependencies. Safe to re-run (overwrites seeds, never touches findings).

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const fuzzDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const corpusDir = join(fuzzDir, "corpus");

function put(target, name, bytes) {
  const dir = join(corpusDir, target);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, name), bytes);
  console.log(`${target}/${name}  ${bytes.length} bytes`);
}

// hybrid_init_parse — HybridEncapsulation / HybridPublicBundle wire bytes.
// Header byte 0x01 = classic, 0x02 = hybrid (see src-tauri/src/pq/hybrid.rs).
put("hybrid_init_parse", "enc_classic.bin",
  Buffer.concat([Buffer.from([0x01]), Buffer.alloc(32)]));
put("hybrid_init_parse", "enc_hybrid.bin",
  Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32), Buffer.alloc(1088)]));
put("hybrid_init_parse", "bundle_classic.bin",
  Buffer.concat([Buffer.from([0x01]), Buffer.alloc(32)]));
put("hybrid_init_parse", "bundle_hybrid.bin",
  Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32), Buffer.alloc(1184)]));

// envelope_parse — SM2 wire envelope C1(128 hex) || C3(64 hex) || C2(n), ASCII hex.
// C1 = x||y, 128 hex chars, *no* 0x04 prefix (see src-tauri/src/sm2.rs:816).
put("envelope_parse", "envelope_valid.hex",
  Buffer.from("00".repeat(64) + "00".repeat(32) + "ab".repeat(16), "ascii"));
