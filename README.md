# 服务器控制台 (`ssh-mcp`) · Windows 10/11 Rust 桌面版

基于 **Rust + Tauri v2 + WebView2** 构建的受控 Linux 服务器运维控制台与本地 MCP 服务端（面向 Windows 10/11 x64，默认版本 `1.0.0`）。

## 核心特性

- **简体中文安装器与平滑自动更新**：
  - 提供默认**简体中文界面**的 NSIS 当前用户安装包（`currentUser` 免 UAC 弹窗，自动随包部署 `ssh-mcp.exe` 与 `ssh-mcp-stdio.exe`，覆盖升级或卸载默认保留 `%LOCALAPPDATA%\sshMcp` 加密数据）；
  - 「设置 -> 版本更新」内置基于 **GitHub Releases** 的公钥验签自动版本更新（后台静默下载，就绪后一键平滑重启升级）。
- **单屏可拖拽双栏控制台**：极简服务器卡片网格、实时 `CPU / 内存 / 磁盘` 占用进度条、卡片级一键切换 `需审批 / 全自动` 控制模式、待审批队列与分页任务管理。
- **智能只读免审批与高危硬拦截**：
  - 在 `需审批` 模式下，所有**专用只读 MCP 工具**及通过词法与参数白名单校验的**只读 `shell_execute` 查询命令**（支持常用排查命令、安全管道 `|` / `&&` 及 `sudo` 只读查询）自动免审批直接执行；
  - `file_upload`、`file_download`、`service_control`、Docker 清理删除及任何含写入/删除/重定向/命令替换语义的操作强制人工审批；
  - 即使处于 `全自动` 模式，包含 Volume 数据卷删除的 Docker 清理计划依然强制独立人工审批。
- **内置 Skills 自动热更新闭环**：控制台启动、版本升级及 AI 客户端连接时，自动校验指纹并将内置 7 个 `ssh-mcp-*` Skills 热更新至本机各 AI 客户端目录（含防降级保护与跨版本调用 `_skillsAutoUpdated` 会话重载通知）。
- **纯 Rust 异步 SSH / SFTP / PTY 引擎**：基于 `russh` + `russh-sftp`，零外部 OpenSSL 动态库依赖；支持**托管私钥**、**密码**、**本机密钥路径**及 **Windows 10/11 原生 OpenSSH Agent (`\\.\pipe\openssh-ssh-agent`)**；内置 `xterm.js` 全功能交互式终端。
- **严格主机密钥防劫持（Manual TOFU）与 Windows 原生凭据保护**：首次连接强制展示 `SHA256` 指纹确认，密钥变更触发红色拦截告警；采用 Win32 DPAPI + AES-256-GCM 加密存储凭据，支持 Argon2id 口令加密备份导出与冲突预览恢复。
- **系统托盘常驻与原生通知**：单实例运行，点击关闭默认最小化至系统托盘；新增待审批请求、失败告警或新版本下载就绪时自动推送 Windows 原生通知。

## 目录结构

- `crates/ssh-mcp-core`：纯 Rust 核心业务库（DPAPI/ACL/自启、SQLite WAL、智能只读与高危风险策略、SSH/SFTP/PTY、Docker 两阶段安全清理、Skills 热更新套件与 21 个 MCP 工具）
- `crates/ssh-mcp-stdio`：轻量 MCP `stdio` 桥接程序 (`ssh-mcp-stdio.exe`，作为 Sidecar 随安装包一同分发)
- `src-tauri`：Tauri v2 Windows 桌面宿主与自动更新服务 (`ssh-mcp.exe`)
- `src`：React + TypeScript + Ant Design 5 + `@xterm/xterm` 单屏界面
- `skills/`：AI 客户端专用 Skills 套件（编译期内嵌并自动热同步至本机 AI 目录）

## 开发、测试与中文安装包构建

```powershell
# 1. 前端类型检查与静态资源打包
pnpm typecheck
pnpm build

# 2. 运行 Rust 核心、只读策略与安全测试套件
cargo test --workspace

# 3. 一键构建简体中文 NSIS 安装包与自动更新签名产物 (.exe + .sig)
pnpm build:installer
```

安装包输出路径：`target\release\bundle\nsis\服务器控制台_1.0.0_x64-setup.exe`

## GitHub Releases 自动更新发版配置

仓库已内置 `.github/workflows/release.yml`：
1. 在 GitHub 仓库 `Settings -> Secrets and variables -> Actions` 中新建 Secret：
   - `TAURI_SIGNING_PRIVATE_KEY`：填入本地 `.tauri-keys/ssh-mcp.key` 文件全文内容；
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`：若无私钥密码可留空或不创建。
2. 修改版本号后推送标签（例如 `git tag -a 1.0.1 -m "Release 1.0.1" && git push origin 1.0.1`），GitHub Actions 将自动编译中文安装包、生成签名的 `latest.json` 并发布至 GitHub Releases，客户端即可在「设置 -> 版本更新」中自动检测并升级。
