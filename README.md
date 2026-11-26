# 服务器控制台 (`ssh-mcp`) · Windows 10/11 Rust 桌面版

基于 **Rust + Tauri v2 + WebView2** 构建的受控 Linux 服务器运维控制台与本地 MCP 服务端（仅面向 Windows 10/11 x64）。

## 核心特性

- **单屏可拖拽双栏控制台**：1:1 复刻极简服务器卡片网格、实时 `CPU / 内存 / 磁盘` 占用进度条、卡片级一键切换 `需审批 / 全自动` 控制模式、待审批队列与分页任务管理。
- **纯 Rust 异步 SSH / SFTP / PTY 引擎**：基于 `russh` + `russh-sftp`，零外部 OpenSSL 动态库依赖；支持**托管私钥**、**密码**、**本机密钥路径**及 **Windows 10/11 原生 OpenSSH Agent (`\\.\pipe\openssh-ssh-agent`)**；内置 `xterm.js` 全功能交互式终端（支持全屏缩放，内存态会话关闭即销毁）。
- **严格主机密钥防劫持（Manual TOFU）**：首次连接强制展示 `SHA256` 指纹确认并串联测速上线；若远程主机密钥发生变更，自动触发高危红色拦截告警。
- **Windows 原生凭据保护**：直接通过 Win32 DPAPI (`CryptProtectData`) 绑定当前 Windows 账户保护主密钥，结合 AES-256-GCM（绑定 `server:<id>` AAD）加密存储凭据于 `%LOCALAPPDATA%\sshMcp\`（启动自动收紧 NTFS 目录 ACL）；支持 Argon2id + AES-256-GCM 口令加密导出与冲突预览恢复。
- **零 Node 依赖双模 MCP 服务（21 个受控工具）**：
  - 内置 `http://127.0.0.1:8787/mcp` Streamable HTTP 服务（防浏览器跨站 `Origin` 调用）；
  - 随附纯控制台轻量桥接器 `ssh-mcp-stdio.exe`，可直接配置到 Claude Desktop、Cursor、Codex、Antigravity 等任意 MCP 客户端；
  - 即使服务器处于`全自动`模式，包含 Volume 数据卷删除的 Docker 清理计划依然强制独立人工审批。
- **Windows 系统托盘常驻与原生通知**：单实例运行，点击关闭默认最小化至系统托盘；新增待审批请求或开启「失败告警」发生离线/任务失败时自动推送 Windows 10/11 原生通知。

## 目录结构

- `crates/ssh-mcp-core`：纯 Rust 核心业务库（DPAPI/ACL/自启、SQLite WAL、风险策略、SSH/SFTP/PTY、Docker 两阶段安全清理、任务调度与 21 个 MCP 工具）
- `crates/ssh-mcp-stdio`：零依赖 MCP `stdio` 桥接程序 (`ssh-mcp-stdio.exe`)
- `src-tauri`：Tauri v2 Windows 桌面宿主 (`ssh-mcp.exe`)
- `src`：React + TypeScript + Ant Design 5 + `@xterm/xterm` 单屏界面
- `skills/`：适配新版桌面控制台的 AI 客户端专用 Skills 套件：
  - `ssh-mcp-ops`（全场景综合受控运维主 Skill + `references/workflows.md`）
  - `ssh-mcp-start`（单机默认会话上下文绑定）
  - `ssh-mcp-health`（只读连通性与负载/内存/磁盘/进程健康巡检）
  - `ssh-mcp-service`（`systemd` 服务与 `journald` 日志排障及受控启停）
  - `ssh-mcp-docker`（Docker 容器、实时资源与空间结构化只读巡检）
  - `ssh-mcp-docker-cleanup`（Docker `预览 -> 确认 -> 二次摘要校验删除 -> 健康复查` 安全清理）
  - `ssh-mcp-job-followup`（既有持久任务等待、审批跟踪与 UTF-8 分页日志读取）

## 开发与构建命令

```powershell
# 1. 前端类型检查与静态打包
pnpm typecheck
pnpm build

# 2. 运行 Rust 核心与安全测试套件
cargo test --workspace

# 3. 编译桌面主程序 (ssh-mcp.exe) 与 Stdio 桥接器 (ssh-mcp-stdio.exe)
cargo build --workspace --release
```
