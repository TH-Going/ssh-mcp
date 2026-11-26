---
name: ssh-mcp-docker
description: 使用 ssh-mcp 结构化查询 Docker 容器列表、实时 CPU/内存/IO 资源统计与磁盘空间占用。用于容器盘点、性能诊断与空间分析。
---

# Docker 只读巡检与空间分析

通过 `ssh-mcp` 的只读 Docker 工具直接获取结构化结果。

1. 沿用当前对话已绑定的 `serverId`，或调用 `servers_list` 解析目标服务器。
2. 容器盘点调用 `docker_containers_list`（按需选 `running`、`stopped` 或 `all`）；实时资源诊断调用 `docker_container_stats`；空间与可回收量分析调用 `docker_disk_usage`。
3. 若返回时任务仍处于排队或运行态，对同一 `jobId` 与最新 `revision` 调用 `job_wait` 直至终态。
4. 直接基于每个目标的 `structuredResult` 汇总容器状态、健康检查、端口映射、资源占用或四类对象（images / containers / volumes / buildCache）的总量与可回收空间；仅当工具报错时通过 `job_output_read` 读取原始错误输出。全部目标到达终态并核对后完成。
