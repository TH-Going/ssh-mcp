---
name: ssh-mcp-ops
description: 通过 ssh-mcp 管理已在 Windows 桌面控制台中配置的 Linux 服务器：查询服务器与实时指标、系统摘要、进程、systemd 服务、journald 日志与 Docker 状态，执行受控 Shell、服务启停、SFTP 文件传输与两阶段 Docker 安全清理，以及等待或跟踪持久任务。
---

# ssh-mcp 受控服务器运维

全部远程查询与变更统一通过本机 `ssh-mcp` MCP 工具执行。当会话缺少 `ssh-mcp` 工具或返回本地连接错误时，直接提示用户启动 `ssh-mcp.exe` 并在「设置」中开启「MCP 服务」开关。服务器增删、SSH 凭据与主机密钥指纹确认由用户在桌面控制台完成。

## 标准流程

1. **解析目标**：调用 `servers_list` 获取服务器清单、在线状态、主机密钥信任状态与实时 `metrics`（CPU/内存/磁盘）及延迟。按名称、主机、环境与上下文唯一锁定 `serverIds`；存在歧义且影响作用范围时先向用户确认，始终传入明确的服务器集合。
2. **选用最窄专用工具**：连通性用 `server_check`，主机概况用 `system_summary`，进程用 `processes_list`，服务与日志用 `services_list` / `service_status` / `service_control` / `logs_query`，容器与空间用 `docker_*` 系列工具；仅当专用工具无法表达用户明确意图时使用 `shell_execute`。
3. **填写变更原因（`reason`）**：调用 `service_control`、`shell_execute`、`file_upload`、`file_download` 或 `docker_cleanup_execute` 时，始终传入简明准确的 `reason`（说明本次变更目的），供桌面控制台「待审批」列表与 Windows 系统通知直接展示。
4. **单次长等持久任务**：普通远程工具返回 `Job` 快照（含 `id` 与 `revision`），立即调用 `job_wait({ jobId, afterRevision: revision })` 等待终态或进入待审批；Docker 专用工具内部已自动长等一次。若 `timedOut: true`，继续对同一 `jobId` 调用 `job_wait`。
5. **响应人工审批暂停**：当任务状态为 `waiting_approval` 时，向用户报告目标服务器、`approvalId`、`riskLevel`、`matchedPolicy` 与 `approvalReason`，请用户在桌面控制台「待审批」栏批准或拒绝；用户处理后继续对同一 `jobId` 调用 `job_wait`。
6. **分页读取输出**：对 `outputBytes > 0` 的目标调用 `job_output_read`（首块 `offset: 0`，后续传递 `nextCursor` 直至为 `null`），结合 `structuredResult`、`exitCode` 与 `error` 逐台服务器核对并汇总结果。

处理工具映射、多目标生命周期、分页游标或 Docker 清理参数时，查阅 [references/workflows.md](references/workflows.md)。

## 安全红线

- **只读与写操作分离**：巡检与排障请求仅使用只读工具（`servers_list`、`server_check`、`system_summary`、`processes_list`、`services_list`、`service_status`、`logs_query`、`docker_containers_list`、`docker_container_stats`、`docker_disk_usage`、`docker_cleanup_preview`、`jobs_list`、`job_get`、`job_wait`、`job_output_read`）；仅在当前请求明确授权变更动作与目标时调用变更工具。
- **全自动模式审慎核参**：对 `controlMode: "direct"`（全自动）服务器提交写操作将直接执行，调用前必须核准目标服务器、命令与路径参数；文件传输默认保持 `overwrite: false`，仅在用户明确要求覆盖时设为 `true`。
- **Docker 清理硬保护**：清理固定走 `docker_cleanup_preview` → 用户确认计划明细 → `docker_cleanup_execute({ cleanupPlanId, reason })`，严禁使用 `shell_execute` 运行 `docker system prune` 或直接删除 `/var/lib/docker`；数据卷清理必须单独预览并显式开启 `includeVolumes: true`（无论何种控制模式均强制触发桌面端人工审批）。

## 完成标准

全部目标均到达终态（`succeeded`、`partial_failure`、`failed` 或 `cancelled`），每台目标服务器的状态、退出码、错误信息及可用输出均已核对并按服务器清晰汇报（部分失败须逐台区分成功与失败目标）。`waiting_approval` 为等待桌面端人工决策的挂起态，确认用户处理前保持原 `jobId` 待命。
