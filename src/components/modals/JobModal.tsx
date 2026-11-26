import React, { useEffect, useState } from "react";
import { Button, Modal, Spin, message } from "antd";
import { CopyOutlined, DownloadOutlined } from "@ant-design/icons";
import { save as saveFileDialog } from "@tauri-apps/plugin-dialog";
import type { Job, JobStatus, JobTarget } from "../../types/models";
import { api, formatBytes, formatJobTime } from "../../api/client";

export const JOB_STATUS_META: Record<
  JobStatus,
  { label: string; cls: string }
> = {
  queued: { label: "排队中", cls: "warn" },
  waiting_approval: { label: "等待审批", cls: "warn" },
  running: { label: "执行中", cls: "warn" },
  succeeded: { label: "成功", cls: "" },
  partial_failure: { label: "部分失败", cls: "warn" },
  failed: { label: "失败", cls: "off" },
  cancelled: { label: "已取消", cls: "" },
};

export function JobStatusBadge({ status }: { status: JobStatus }) {
  const meta = JOB_STATUS_META[status] || JOB_STATUS_META.failed;
  return (
    <span className={`st ${meta.cls}`}>
      <i className="dot" style={{ background: "currentColor" }} />
      {meta.label}
    </span>
  );
}

interface Props {
  job: Job | null;
  onClose: () => void;
}

export const JobModal: React.FC<Props> = ({ job, onClose }) => {
  const [selectedTargetId, setSelectedTargetId] = useState<string>("");
  const [outputText, setOutputText] = useState<string>("");
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadingOut, setLoadingOut] = useState(false);
  const [showStructured, setShowStructured] = useState(false);

  const activeTarget: JobTarget | undefined = job
    ? job.targets.find((t) => t.id === selectedTargetId) || job.targets[0]
    : undefined;

  useEffect(() => {
    if (!job) {
      setSelectedTargetId("");
      setOutputText("");
      setNextCursor(null);
      setShowStructured(false);
      return;
    }
    if (
      !selectedTargetId ||
      !job.targets.some((t) => t.id === selectedTargetId)
    ) {
      setSelectedTargetId(job.targets[0]?.id || "");
    }
  }, [job, selectedTargetId]);

  useEffect(() => {
    if (!job || !activeTarget) return;
    if (activeTarget.outputBytes === 0) {
      setOutputText("");
      setNextCursor(null);
      return;
    }
    let cancelled = false;
    setLoadingOut(true);
    api
      .jobReadOutput(job.id, activeTarget.id, 0, 65536)
      .then((res) => {
        if (!cancelled) {
          setOutputText(res.content);
          setNextCursor(res.nextCursor);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setOutputText(`[无法读取输出日志: ${String(err)}]`);
          setNextCursor(null);
        }
      })
      .finally(() => {
        if (!cancelled) setLoadingOut(false);
      });

    return () => {
      cancelled = true;
    };
  }, [
    job?.id,
    job?.revision,
    activeTarget?.id,
    activeTarget?.outputBytes,
    activeTarget?.status,
  ]);

  const loadMore = async () => {
    if (!job || !activeTarget || !nextCursor) return;
    setLoadingOut(true);
    try {
      const res = await api.jobReadOutput(
        job.id,
        activeTarget.id,
        0,
        65536,
        nextCursor,
      );
      setOutputText((prev) => prev + res.content);
      setNextCursor(res.nextCursor);
    } catch (e) {
      message.error(String(e));
    } finally {
      setLoadingOut(false);
    }
  };

  const handleCopy = async () => {
    if (!job || !activeTarget) return;
    try {
      const text =
        activeTarget.outputBytes > 0
          ? await api.jobReadFullOutput(job.id, activeTarget.id)
          : outputText || activeTarget.error || "";
      await navigator.clipboard.writeText(text);
      message.success("输出内容已复制");
    } catch (e) {
      message.error(String(e));
    }
  };

  const handleDownload = async () => {
    if (!job || !activeTarget) return;
    try {
      const dest = await saveFileDialog({
        title: "保存任务输出日志",
        defaultPath: `${job.tool}-${activeTarget.serverName}-${job.id.slice(0, 8)}.log`,
        filters: [{ name: "Log Files", extensions: ["log", "txt"] }],
      });
      if (dest) {
        await api.jobSaveOutputFile(job.id, activeTarget.id, dest);
        message.success("日志文件已保存");
      }
    } catch (e) {
      message.error(String(e));
    }
  };

  const targetSummary = job
    ? job.targets.length === 1
      ? job.targets[0]!.serverName
      : `${job.targets.length} 台服务器`
    : "";

  return (
    <Modal
      className="ncp-modal"
      open={!!job}
      onCancel={onClose}
      width={640}
      centered
      footer={null}
      title={
        job ? (
          <div style={{ paddingRight: 28 }}>
            <span style={{ fontSize: 14, fontWeight: 600 }}>
              {job.toolLabel}
            </span>
            <span
              style={{
                marginLeft: 8,
                fontSize: 11,
                color: "#98a0ab",
                fontFamily: "var(--mono)",
              }}
            >
              {job.id.slice(0, 8)} · {formatJobTime(job.createdAt)}
            </span>
          </div>
        ) : (
          ""
        )
      }
    >
      {job && activeTarget && (
        <>
          <div style={{ display: "flex", gap: 32, flexWrap: "wrap" }}>
            <div>
              <div className="k">状态</div>
              <div className="v">
                <JobStatusBadge status={job.status} />
              </div>
            </div>
            <div>
              <div className="k">目标</div>
              <div className="v">{targetSummary}</div>
            </div>
            <div>
              <div className="k">发起人</div>
              <div className="v">{job.requester}</div>
            </div>
            {activeTarget.exitCode !== null && (
              <div>
                <div className="k">退出码</div>
                <div className="v mono">{activeTarget.exitCode}</div>
              </div>
            )}
          </div>

          {job.reason && (
            <div style={{ marginTop: 10, fontSize: 12, color: "var(--t2)" }}>
              原因：{job.reason}
            </div>
          )}

          {job.targets.length > 1 && (
            <div className="target-pills">
              {job.targets.map((t) => {
                const dotColor =
                  t.status === "succeeded"
                    ? "#12b76a"
                    : t.status === "failed"
                      ? "#c8372d"
                      : "#f79009";
                return (
                  <button
                    key={t.id}
                    type="button"
                    className={`target-pill${t.id === activeTarget.id ? " active" : ""}`}
                    onClick={() => setSelectedTargetId(t.id)}
                  >
                    <i className="dot" style={{ background: dotColor }} />
                    {t.serverName}
                  </button>
                );
              })}
            </div>
          )}

          {activeTarget.executedCommand && (
            <div className="cmdline" style={{ marginTop: 12 }}>
              <code>$ {activeTarget.executedCommand}</code>
            </div>
          )}

          {activeTarget.error && (
            <div className="err-line" style={{ marginTop: 10 }}>
              {activeTarget.error}
            </div>
          )}

          <div style={{ marginTop: 14 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: 8,
              }}
            >
              <span className="k">执行输出</span>
              {activeTarget.structuredResult !== null && (
                <Button
                  type="link"
                  size="small"
                  style={{ height: 20, padding: 0, fontSize: 11.5 }}
                  onClick={() => setShowStructured((v) => !v)}
                >
                  {showStructured ? "查看标准输出" : "查看结构化 JSON"}
                </Button>
              )}
            </div>

            {loadingOut && !outputText ? (
              <div style={{ padding: "28px 0", textAlign: "center" }}>
                <Spin size="small" />
              </div>
            ) : showStructured && activeTarget.structuredResult !== null ? (
              <pre className="out">
                {JSON.stringify(activeTarget.structuredResult, null, 2)}
              </pre>
            ) : (
              <pre className="out">
                {outputText ||
                  (activeTarget.status === "waiting_approval"
                    ? "等待人工批准后开始执行..."
                    : activeTarget.status === "running" ||
                        activeTarget.status === "queued"
                      ? "正在远程执行中..."
                      : "（无输出内容）")}
              </pre>
            )}

            {nextCursor && !showStructured && (
              <div style={{ marginTop: 8, textAlign: "center" }}>
                <Button size="small" loading={loadingOut} onClick={loadMore}>
                  加载后续输出
                </Button>
              </div>
            )}
          </div>

          <div className="modal-foot">
            <span style={{ fontSize: 11, color: "var(--t4)" }}>
              输出 {formatBytes(activeTarget.outputBytes)}
            </span>
            <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <Button
                type="text"
                size="small"
                icon={<CopyOutlined />}
                onClick={handleCopy}
              >
                复制
              </Button>
              <Button
                type="text"
                size="small"
                icon={<DownloadOutlined />}
                disabled={activeTarget.outputBytes === 0}
                onClick={handleDownload}
              >
                下载
              </Button>
            </div>
          </div>
        </>
      )}
    </Modal>
  );
};
