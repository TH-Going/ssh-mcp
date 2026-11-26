---
name: ssh-mcp-service
description: 使用 ssh-mcp 查询 systemd 服务状态与 journald 日志，并在用户明确要求时执行受控的启动、停止、重启或重载操作。用于服务排障与 systemd 运维。
---

# systemd 服务排障与受控操作

通过 `ssh-mcp` 专用服务与日志工具处理 systemd 运维，使用结构化参数代替手写 `shell_execute`。

1. 沿用当前对话已绑定的 `serverId`，或调用 `servers_list` 精确解析目标服务器。
2. 盘点服务使用 `services_list`（配合 `state` 与 `limit`），单服务状态使用 `service_status`，日志检索使用 `logs_query`（利用 `unit`、`since`、`query`、`lines` 缩小范围）。
3. 排障过程保持只读；当用户明确指示启停、重启或重载某个具体服务时，调用 `service_control` 并传入准确的 `service`、`action`、必要的 `sudo` 以及简明的业务原因 `reason`。
4. 对返回的任务调用 `job_wait` 跟踪同一 `jobId`；若进入 `waiting_approval`，告知用户审批单原因与风险等级，待用户在桌面控制台「待审批」栏批准后继续等待原任务。
5. 使用 `job_output_read` 读取关键输出，逐台服务器汇报服务当前状态、关键错误日志、退出码与执行结果。全部目标到达终态并核对完毕后完成。
