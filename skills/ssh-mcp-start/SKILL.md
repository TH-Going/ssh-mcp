---
name: ssh-mcp-start
description: 使用 ssh-mcp 为当前对话选择并绑定一台已配置服务器，声明后续运维操作默认针对该 serverId。用于用户说“接下来操作某台服务器”或进入单机运维上下文。
---

# 绑定当前对话目标服务器

通过 `ssh-mcp` 建立当前对话的默认单机上下文，本身不发起任何远程 SSH 命令。

1. 调用 `servers_list` 读取桌面控制台已配置的服务器，按用户给出的名称、`host`、环境或 `serverId` 匹配确认。
2. 仅绑定单台服务器：若未指定目标或匹配到多台候选，列出各候选的名称、`host:port`、环境与在线状态请用户选择。
3. 目标唯一确定后，输出「当前服务器上下文已建立」，列出 `serverId`、名称、`host:port`、环境、`controlMode`、`connectionStatus`（含实时指标概览，若有）与 `hostKeyStatus`。
4. 后续对话中若用户未切换目标，默认沿用该 `serverId`；绑定上下文仅锁定目标机器，后续任何写入、服务启停、`sudo` 或 Shell 命令仍须由当次请求明确提出并遵循服务器审批策略。
