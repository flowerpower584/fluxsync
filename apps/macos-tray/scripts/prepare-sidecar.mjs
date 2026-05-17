import { execSync } from "node:child_process";
import { mkdirSync, copyFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

const trayDir = resolve(import.meta.dirname, "..");
const repoRoot = resolve(trayDir, "..", "..");
const manifest = join(repoRoot, "Cargo.toml");

const triple = execSync("rustc -vV", { encoding: "utf8" })
  .split("\n")
  .find((l) => l.startsWith("host:"))
  .slice("host:".length)
  .trim();
const exe = triple.includes("windows") ? ".exe" : "";

console.log(`[prepare-sidecar] building fluxsyncd for ${triple}`);
execSync(`cargo build --release -p fluxsyncd --manifest-path "${manifest}"`, {
  stdio: "inherit",
});

const src = join(repoRoot, "target", "release", `fluxsyncd${exe}`);
if (!existsSync(src)) {
  console.error(`[prepare-sidecar] build output missing: ${src}`);
  process.exit(1);
}

const destDir = join(trayDir, "src-tauri", "binaries");
const dest = join(destDir, `fluxsyncd-${triple}${exe}`);
mkdirSync(destDir, { recursive: true });
copyFileSync(src, dest);
console.log(`[prepare-sidecar] sidecar ready: ${dest}`);
