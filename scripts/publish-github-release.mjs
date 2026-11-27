import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

const tauriConf = JSON.parse(
  fs.readFileSync(path.join(rootDir, "src-tauri", "tauri.conf.json"), "utf8"),
);
const version = tauriConf.version;
const repo = process.env.GITHUB_REPOSITORY || "TH-Going/ssh-mcp";
const refType = process.env.GITHUB_REF_TYPE || "";
const refName = process.env.GITHUB_REF_NAME || "";
const tag = refType === "tag" && refName ? refName : version;

const nsisDir = path.join(rootDir, "target", "release", "bundle", "nsis");
if (!fs.existsSync(nsisDir)) {
  throw new Error(`NSIS bundle directory not found: ${nsisDir}`);
}

const entries = fs.readdirSync(nsisDir);
const exeName = entries.find((f) => f.endsWith("-setup.exe"));
if (!exeName) {
  throw new Error(`No *-setup.exe found in ${nsisDir}`);
}
const sigName = `${exeName}.sig`;
const exePath = path.join(nsisDir, exeName);
const sigPath = path.join(nsisDir, sigName);
if (!fs.existsSync(sigPath)) {
  throw new Error(
    `Missing updater signature file: ${sigPath} (ensure TAURI_SIGNING_PRIVATE_KEY is configured in GitHub Secrets)`,
  );
}

const outDir = path.join(rootDir, "target", "release-upload");
fs.mkdirSync(outDir, { recursive: true });

// Use ASCII asset filename so GitHub Release API never strips Chinese characters from productName
const cleanExeName = `ssh-mcp_${version}_x64-setup.exe`;
const cleanSigName = `${cleanExeName}.sig`;
const cleanExePath = path.join(outDir, cleanExeName);
const cleanSigPath = path.join(outDir, cleanSigName);
const latestJsonPath = path.join(outDir, "latest.json");

fs.copyFileSync(exePath, cleanExePath);
fs.copyFileSync(sigPath, cleanSigPath);

const signature = fs.readFileSync(sigPath, "utf8").trim();
if (!signature) {
  throw new Error("Signature file is empty");
}

const downloadUrl = `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/${cleanExeName}`;
const latestManifest = {
  version,
  notes: `服务器控制台 v${version}`,
  pub_date: new Date().toISOString(),
  platforms: {
    "windows-x86_64-nsis": {
      signature,
      url: downloadUrl,
    },
    "windows-x86_64": {
      signature,
      url: downloadUrl,
    },
  },
};

fs.writeFileSync(
  latestJsonPath,
  JSON.stringify(latestManifest, null, 2) + "\n",
  "utf8",
);
console.log(
  "[publish-release] Generated latest.json:\n" +
    fs.readFileSync(latestJsonPath, "utf8"),
);

const ghEnv = { ...process.env };
let releaseExists = false;
try {
  execFileSync("gh", ["release", "view", tag, "--repo", repo], {
    stdio: "ignore",
    env: ghEnv,
  });
  releaseExists = true;
} catch {
  releaseExists = false;
}

const releaseTitle = `服务器控制台 v${version}`;
const releaseNotes = [
  `### 下载与安装`,
  `- 全新安装请下载下方 **\`${cleanExeName}\`**（默认简体中文安装界面，无需管理员权限）。`,
  `- 已安装客户端可在 **「设置 -> 版本更新」** 中自动检查并一键升级。`,
].join("\n");

if (!releaseExists) {
  execFileSync(
    "gh",
    [
      "release",
      "create",
      tag,
      cleanExePath,
      cleanSigPath,
      latestJsonPath,
      "--repo",
      repo,
      "--title",
      releaseTitle,
      "--notes",
      releaseNotes,
    ],
    { stdio: "inherit", env: ghEnv },
  );
} else {
  execFileSync(
    "gh",
    [
      "release",
      "edit",
      tag,
      "--repo",
      repo,
      "--title",
      releaseTitle,
      "--notes",
      releaseNotes,
      "--draft=false",
      "--prerelease=false",
    ],
    { stdio: "inherit", env: ghEnv },
  );
  execFileSync(
    "gh",
    [
      "release",
      "upload",
      tag,
      cleanExePath,
      cleanSigPath,
      latestJsonPath,
      "--clobber",
      "--repo",
      repo,
    ],
    { stdio: "inherit", env: ghEnv },
  );

  // Remove mangled asset names (`_1.0.0_x64-setup.exe`) stripped by GitHub previously
  for (const legacyAsset of [
    `_${version}_x64-setup.exe`,
    `_${version}_x64-setup.exe.sig`,
  ]) {
    try {
      execFileSync(
        "gh",
        ["release", "delete-asset", tag, legacyAsset, "--yes", "--repo", repo],
        { stdio: "ignore", env: ghEnv },
      );
    } catch {
      // Ignore if absent
    }
  }
}
