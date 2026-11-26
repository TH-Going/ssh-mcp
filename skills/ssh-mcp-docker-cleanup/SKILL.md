---
name: ssh-mcp-docker-cleanup
description: 使用 ssh-mcp 两阶段安全预览并执行 Docker 停止容器、无用镜像、构建缓存或未使用数据卷清理。用于释放 Docker 磁盘空间、按时长保留缓存或按仓库保留最新镜像标签。
---

# Docker 两阶段安全清理

严格执行 `docker_cleanup_preview → 用户确认计划 → docker_cleanup_execute → 自动复查` 闭环，全程使用专用清理工具保护运行容器、被引用镜像与在用数据卷。

1. 沿用已绑定的 `serverId` 或调用 `servers_list` 解析目标；每份清理计划绑定单台服务器，多台服务器逐台预览与确认。
2. 调用 `docker_cleanup_preview`，按用户要求设置：
   - 保留最近 N 小时构建缓存：`resourceTypes: ["buildCache"]`、`olderThanHours: N`、`buildCacheKeepUsedWithinHours: N`；
   - 指定仓库保留最新 K 个版本：`resourceTypes: ["images"]`、同时提供 `imageRepository` 与 `keepLatestTags`；
   - 清理未使用数据卷：单独使用 `resourceTypes: ["volumes"]` 且显式设置 `includeVolumes: true`（无论服务器何种模式均会强制进入桌面控制台人工审批）。
3. 向用户完整呈现预览返回的 `targets`、`protectedResources`、`estimatedReclaimableBytes`、`estimateConfidence`、`riskWarnings` 与过期时间；若用户仅要求预览则到此结束。
4. 获得用户对该计划的明确执行确认后，调用 `docker_cleanup_execute({ cleanupPlanId, reason })`。若返回计划过期或 `CLEANUP_PLAN_STALE`（预览后远端对象发生变化），重新运行 `docker_cleanup_preview` 并请用户再次确认。
5. 若进入 `waiting_approval`，提示用户在桌面控制台「待审批」栏批准后，继续对同一 `jobId` 调用 `job_wait`。
6. 执行完成后核对并汇报 `before`、`after`、`freedBytes`、`deleted`、`failed` 与 `verification`（确认运行中容器未受影响、健康状态正常、保留镜像标签完整）。
