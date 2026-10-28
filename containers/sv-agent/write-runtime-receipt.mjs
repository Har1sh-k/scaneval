// Writes /opt/scaneval/runtime.json during the image build, from what is actually installed.
//
// Every identity in the receipt is read from the built filesystem rather than copied from a
// build argument: the harness commit from its checkout, the harness and Pi versions from the
// installed package.json files, the Node version from the running binary. The build arguments
// are only the expectations each one is checked against, so a wrong base digest, a moved Pi
// dependency or a different harness checkout fails the build instead of producing a receipt
// that describes some other runtime. The output carries no timestamp, path from the build
// host or environment value, so identical inputs give an identical file.
//
// Run by the Dockerfile through a build-time bind mount; it is not itself part of the image.
//   node write-runtime-receipt.mjs

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = "/opt/scaneval";
const HARNESS = join(ROOT, "harness");
const PI_PACKAGE = "@earendil-works/pi-coding-agent";
const REQUIRED = ["llm_harness_driver.mts", "pi_oci_runner.mts", "pi_open_context.mts"];

function expected(name) {
  const value = process.env[name];
  if (!value) throw new Error(`build argument ${name} is required`);
  return value;
}

function check(label, actual, want) {
  if (actual !== want) throw new Error(`${label}: built ${JSON.stringify(actual)}, expected ${JSON.stringify(want)}`);
  return actual;
}

const sha256 = (path) => "sha256:" + createHash("sha256").update(readFileSync(path)).digest("hex");
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));

function tree(dir) {
  // Sorted name -> digest map of the regular files directly in dir.
  const out = {};
  for (const name of readdirSync(dir).sort()) {
    if (statSync(join(dir, name)).isFile()) out[name] = sha256(join(dir, name));
  }
  return out;
}

function dpkgVersion(name) {
  return execFileSync("dpkg-query", ["-W", "-f=${Version}", name], { encoding: "utf8" }).trim();
}

const harnessCommit = check(
  "harness commit",
  execFileSync("git", ["-C", HARNESS, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
  expected("HARNESS_COMMIT"),
);
const harnessPackage = readJson(join(HARNESS, "package.json"));
const harnessTsx = readJson(join(HARNESS, "node_modules", "tsx", "package.json"));
const pi = readJson(join(ROOT, "node_modules", PI_PACKAGE, "package.json"));
const piLock = readJson(join(ROOT, "package-lock.json")).packages[`node_modules/${PI_PACKAGE}`];
check("Pi version", pi.version, expected("EXPECT_PI_VERSION"));
check("Pi lockfile version", piLock.version, pi.version);
check("Node version", process.version, expected("EXPECT_NODE_VERSION"));
for (const name of REQUIRED) {
  if (!existsSync(join(ROOT, name))) throw new Error(`adapter file ${name} is missing from the build context`);
}

const adapters = {};
for (const name of readdirSync(ROOT).sort()) {
  if (/\.m(ts|js)$/.test(name)) adapters[name] = sha256(join(ROOT, name));
}

const receipt = {
  schema_version: 1,
  harness: {
    commit: harnessCommit,
    package_version: harnessPackage.version,
    package_name: harnessPackage.name,
    repository: expected("HARNESS_REPOSITORY"),
    lockfile_sha256: sha256(join(HARNESS, "package-lock.json")),
    tsx_version: harnessTsx.version,
  },
  pi: {
    package: PI_PACKAGE,
    version: pi.version,
    integrity: piLock.integrity,
    lockfile_sha256: sha256(join(ROOT, "package-lock.json")),
  },
  node: {
    version: process.version,
    base_image: `${expected("NODE_IMAGE")}@${expected("NODE_DIGEST")}`,
  },
  observer: {
    package_version: readJson(join(ROOT, "observer", "package.json")).version,
    files: tree(join(ROOT, "observer")),
  },
  adapters,
  os_packages: Object.fromEntries(
    ["ca-certificates", "fd-find", "git", "ripgrep"].map((name) => [name, dpkgVersion(name)]),
  ),
};

writeFileSync(join(ROOT, "runtime.json"), JSON.stringify(receipt, null, 2) + "\n");
process.stdout.write(JSON.stringify(receipt, null, 2) + "\n");
