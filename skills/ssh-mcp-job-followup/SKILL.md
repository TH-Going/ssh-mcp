---
name: ssh-mcp-job-followup
description: 使用 ssh-mcp 查询、继续等待或取消既有持久任务，查看待审批状态并分页读取完整任务输出。用于用户提供 jobId、询问刚才任务的进展或批准后继续获取结果。
---

# 既有持久任务跟踪与输出读取

仅观察、等待或按指示取消既有任务，绝不重复提交原始远程操作。

1. 已知 `jobId` 时调用 `job_get` 读取最新快照与 `revision`；未知 `jobId` 时调用 `jobs_list` 检索近期任务，若存在多个候选请用户确认。
2. 若任务处于 `queued` 或 `running`，调用 `job_wait({ jobId, afterRevision: revision })` 持续等待同一 `jobId`。
3. 若任务处于 `waiting_approval`，逐台汇报目标服务器、`approvalId`、`riskLevel`、`matchedPolicy` 与 `approvalReason`，等待用户在桌面控制台批准或拒绝后继续调用 `job_wait`。
4. 对 `outputBytes > 0` 的目标调用 `job_output_read`：首次传 `offset: 0`，后续循环传递 `nextCursor` 直至为 `null`。
5. 仅在用户明确要求终止任务时调用 `job_cancel`，并说明运行中远程进程为 `SIGTERM` 尽力取消语义。全部目标到达终态并核对状态、退出码、结构化结果与输出后完成。
