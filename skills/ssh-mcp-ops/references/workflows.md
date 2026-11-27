# ssh-mcp 工具与工作流参考

以当前会话注册的 `ssh-mcp` 工具 JSON Schema 为准；本文档规定工具选型、任务状态机、输出游标分页与 Docker 安全清理规范。

## 工具选型表

| 运维意图 | MCP 工具 | 关键约束 |
| --- | --- | --- |
| 查询服务器清单、在线态与实时指标 | `servers_list` | 所有新操作先调用它解析准确的 `serverIds` |
| 检查 SSH 握手与主机密钥指纹状态 | `server_check` | 只读检查；首次连接或密钥变更需用户在桌面控制台确认指纹 |
| 读取主机名、运行时间、负载、内存与磁盘 | `system_summary` | 常规健康巡检首选 |
| 按 CPU 使用率列出进程 | `processes_list` | 按需设置 `limit`（默认 50） |
| 按状态列出 systemd 服务 | `services_list` | 使用 `state`（`running` / `failed` / `active` / `inactive`）过滤 |
| 查看单个 systemd 服务状态 | `service_status` | 传入准确的 `service` 单元名 |
| 启停、重启或重载 systemd 服务 | `service_control` | 写操作；准确传入 `action`、`sudo` 与业务原因 `reason` |
| 查询 journald 日志 | `logs_query` | 组合 `unit`、`since`、`query`、`lines` 精确收敛日志范围 |
| 结构化列出 Docker 容器 | `docker_containers_list` | 返回状态、健康度、端口、创建时间与体积（自带长等待） |
| 结构化读取容器实时资源 | `docker_container_stats` | 返回 CPU%、内存、网络/块 I/O 与 PID 数（自带长等待） |
| 结构化分析 Docker 磁盘空间 | `docker_disk_usage` | 返回镜像、容器、数据卷与构建缓存的总量及可回收空间 |
| 预览 Docker 安全清理计划 | `docker_cleanup_preview` | 只读；单次绑定 1 台 `serverId`，返回 15 分钟有效的 `cleanupPlanId` |
| 执行 Docker 清理计划 | `docker_cleanup_execute` | 仅接收 `cleanupPlanId` 与 `reason`；删除前二次校验对象摘要 |
| 执行专用工具无法覆盖的命令 | `shell_execute` | 需审批模式下纯只读查询（含安全管道与 `sudo`）免审批；变更命令须传入忠实于用户意图的 `command`、`sudo` 与 `reason` |
| 本机文件原子上传至远端 | `file_upload` | 写操作；创建任务时锁定本机快照哈希，传入 `reason` |
| 远端文件原子下载至本机 | `file_download` | 写操作；默认 `overwrite: false`，传入 `reason` |
| 查看最近持久任务 | `jobs_list` | 用于找回既有任务 |
| 读取单个任务快照 | `job_get` | 立即返回当前任务及各目标状态与 `revision` |
| 长轮询等待任务进展 | `job_wait` | 阻塞等待终态、`waiting_approval` 或版本变化，绝不重放远端命令 |
| UTF-8 安全字节分页读取输出 | `job_output_read` | 按 `jobId`、`targetId` 与 `cursor` 读取日志 |
| 取消排队/待审批/运行中任务 | `job_cancel` | 仅按用户明确指示调用；运行中进程采用 `SIGTERM` 尽力取消 |

## 任务状态流转

提交任务后记录 `id`（即 `jobId`）与 `revision`，调用 `job_wait({ jobId, afterRevision: revision })`：

- `queued` / `running`：任务执行中；若等待超时（`timedOut: true`），携带最新返回的 `revision` 继续对同一 `jobId` 调用 `job_wait`。
- `waiting_approval`：存在目标等待用户在 Windows 桌面控制台「待审批」面板处理。向用户说明目标服务器、`approvalReason`、`matchedPolicy` 与 `riskLevel`；待用户批准后继续对原 `jobId` 调用 `job_wait`。
- `succeeded`：全部目标退出码为 0，按需调用 `job_output_read` 提取输出摘要。
- `partial_failure` / `failed`：逐台检查 `targets` 中的 `status`、`exitCode`、`error` 与可用输出，明确区分成功与失败节点。
- `cancelled`：任务已取消（含人工拒绝审批或审批超时 15 分钟自动取消）。

## 输出分页规范

对 `outputBytes > 0` 的目标读取完整日志：

1. 首次调用 `job_output_read({ jobId, targetId, offset: 0 })`。
2. 当返回的 `nextCursor` 非 `null` 时，下一页传入 `{ jobId, targetId, offset: 0, cursor: nextCursor }`（服务端已保证 UTF-8 多字节字符不在页边界截断）。
3. 拼接各页 `content` 直至 `nextCursor === null`。输出包含 `[stdout]`、`[stderr]` 或 `[error]` 分段标记，且服务端已自动脱敏敏感密码为 `[REDACTED]`。

## Docker 两阶段安全清理示例

1. 调用 `docker_cleanup_preview` 获取 `cleanupPlanId`、`targets`、`protectedResources`、`estimatedReclaimableBytes` 与 `riskWarnings`。
2. 向用户展示将被删除的精确列表与保护项，获得明确确认后调用 `docker_cleanup_execute({ cleanupPlanId, reason })`。
3. 服务端在执行前重新盘点远端库存并比对 `targetDigest`（若期间对象变化则返回 `CLEANUP_PLAN_STALE` 中止删除），删除镜像前逐个校验 `sha256` Image ID，执行后自动复查运行容器健康度与保留标签完整性。

保留最近 2 小时使用过的构建缓存：
```json
{
  "serverId": "<server-uuid>",
  "resourceTypes": ["buildCache"],
  "olderThanHours": 168,
  "buildCacheKeepUsedWithinHours": 2
}
```

指定镜像仓库保留最新 3 个版本：
```json
{
  "serverId": "<server-uuid>",
  "resourceTypes": ["images"],
  "olderThanHours": 24,
  "imageRepository": "registry.example.com/team/app",
  "keepLatestTags": 3
}
```

独立清理未使用数据卷（强制进入桌面端人工审批）：
```json
{
  "serverId": "<server-uuid>",
  "resourceTypes": ["volumes"],
  "olderThanHours": 168,
  "includeVolumes": true
}
```
