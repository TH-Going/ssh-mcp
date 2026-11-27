import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const localKeyPath = path.join(rootDir, ".tauri-keys", "ssh-mcp.key");

const env = { ...process.env };
if (!env.TAURI_SIGNING_PRIVATE_KEY && fs.existsSync(localKeyPath)) {
  env.TAURI_SIGNING_PRIVATE_KEY = fs.readFileSync(localKeyPath, "utf8").trim();
  if (env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD === undefined) {
    env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "";
  }
  console.log("[build-installer] Loaded local updater signing key from .tauri-keys/ssh-mcp.key");
}

const extraArgs = process.argv.slice(2).join(" ");
const cmd = `pnpm tauri build${extraArgs ? ` ${extraArgs}` : ""}`;
console.log(`[build-installer] Running: ${cmd}`);
execSync(cmd, {
  cwd: rootDir,
  stdio: "inherit",
  env,
});
