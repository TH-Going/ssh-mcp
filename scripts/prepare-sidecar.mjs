import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

export function sweepAndEvictLockedExe(dir, exeNames) {
  if (!fs.existsSync(dir)) return;
  // Clean up previously renamed `.old-*` binaries that are no longer locked
  for (const name of fs.readdirSync(dir)) {
    if (name.includes(".locked-") && name.endsWith(".old")) {
      try {
        fs.unlinkSync(path.join(dir, name));
      } catch {
        // Still running, ignore
      }
    }
  }

  for (const exe of exeNames) {
    const full = path.join(dir, exe);
    if (!fs.existsSync(full)) continue;
    try {
      // Test if writable/removable; if locked on Windows, rename in-place (allowed by NTFS for running images!)
      const fd = fs.openSync(full, "r+");
      fs.closeSync(fd);
    } catch {
      const backup = path.join(dir, `${exe}.locked-${Date.now()}.old`);
      try {
        fs.renameSync(full, backup);
        console.log(`[prepare-sidecar] Renamed running binary ${exe} -> ${path.basename(backup)}`);
      } catch (err) {
        console.warn(`[prepare-sidecar] Could not rename locked ${exe}: ${err}`);
      }
    }
  }
}

function resolveTargetTriple() {
  if (process.env.TAURI_ENV_TARGET_TRIPLE) {
    return process.env.TAURI_ENV_TARGET_TRIPLE.trim();
  }
  const rustcOut = execSync("rustc -vV", { cwd: rootDir, encoding: "utf8" });
  const match = /^host:\s*(\S+)/m.exec(rustcOut);
  if (!match) {
    throw new Error("无法从 rustc -vV 解析 host target triple");
  }
  return match[1];
}

const triple = resolveTargetTriple();
const isWin = triple.includes("windows");
const binExt = isWin ? ".exe" : "";

const releaseDir = path.join(rootDir, "target", "release");
if (isWin) {
  sweepAndEvictLockedExe(releaseDir, ["ssh-mcp-stdio.exe", "ssh-mcp.exe"]);
}

console.log(`[prepare-sidecar] Compiling ssh-mcp-stdio (--release) for ${triple}...`);
execSync("cargo build -p ssh-mcp-stdio --release", {
  cwd: rootDir,
  stdio: "inherit",
});

const srcBin = path.join(releaseDir, `ssh-mcp-stdio${binExt}`);
if (!fs.existsSync(srcBin)) {
  throw new Error(`未找到编译产物: ${srcBin}`);
}

const destDir = path.join(rootDir, "src-tauri", "binaries");
fs.mkdirSync(destDir, { recursive: true });

const destBin = path.join(destDir, `ssh-mcp-stdio-${triple}${binExt}`);
fs.copyFileSync(srcBin, destBin);
console.log(`[prepare-sidecar] Sidecar ready -> ${destBin}`);
