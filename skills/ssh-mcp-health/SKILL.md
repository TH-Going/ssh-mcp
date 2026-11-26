---
name: ssh-mcp-health
description: 使用 ssh-mcp 对 Linux 服务器执行只读健康巡检，检查 SSH 连通性、主机密钥状态、系统负载、内存、磁盘与高占用进程。用于日常巡检、连通性测试或资源负载排查。
---

# 服务器只读健康巡检

通过 `ssh-mcp` 只读工具完成服务器连通性与资源健康检查。

1. 若当前对话已通过 `$ssh-mcp-start` 绑定目标服务器且未变更则沿用该 `serverId`，否则先调用 `servers_list` 解析目标（同时读取已缓存的 `metrics` 与 `lastLatencyMs`）。
2. 检查连通性或主机指纹调用 `server_check`；读取完整主机负载、运行时间、内存与分区占用调用 `system_summary`；排查高负载根因时追加调用 `processes_list`（设置合理 `limit`）。
3. 取得任务 `id` 与 `revision` 后调用 `job_wait` 等待终态；若遇 `host_key_required` 或 `host_key_changed`，提示用户在桌面控制台核对并确认主机密钥指纹。
4. 使用 `job_output_read`（按 `nextCursor` 分页）读取输出，逐台服务器汇总连通延迟、负载、内存、磁盘、TOP 进程与异常信息。全部目标到达终态并完成核对后结束。
