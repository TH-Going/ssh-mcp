import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  Checkbox,
  Empty,
  Input,
  Pagination,
  Popconfirm,
  Switch,
  Tooltip,
  message,
} from "antd";
import {
  CheckOutlined,
  CodeOutlined,
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  SearchOutlined,
  SettingOutlined,
  StopOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import { listen } from "@tauri-apps/api/event";
import type {
  AppSettings,
  Approval,
  Job,
  Server,
  SettingsUpdateRequest,
} from "./types/models";
import {
  api,
  formatJobTime,
  formatRelativeTime,
  formatRemainingExpiry,
} from "./api/client";
import {
  ServerDetailModal,
  ServerStatusBadge,
} from "./components/modals/ServerDetailModal";
import { ServerFormModal } from "./components/modals/ServerFormModal";
import { TerminalModal } from "./components/modals/TerminalModal";
import { ApprovalModal } from "./components/modals/ApprovalModal";
import { JobModal, JobStatusBadge } from "./components/modals/JobModal";
import { SettingsModal } from "./components/modals/SettingsModal";

const SPLIT_MIN = 320;
const SPLIT_MAX = 720;
const SPLIT_DEFAULT = 420;
const LEFT_MIN = 520;
const JOB_PAGE_SIZE = 20;
const STORAGE_SPLIT_KEY = "sshMcp.rightWidth";

const isActiveJob = (job: Job) =>
  job.status === "queued" ||
  job.status === "waiting_approval" ||
  job.status === "running";

export const App: React.FC = () => {
  const colsRef = useRef<HTMLDivElement | null>(null);
  const [rightWidth, setRightWidth] = useState<number>(() => {
    const saved = Number(localStorage.getItem(STORAGE_SPLIT_KEY));
    return Number.isFinite(saved) && saved >= SPLIT_MIN && saved <= SPLIT_MAX
      ? saved
      : SPLIT_DEFAULT;
  });
  const [dragging, setDragging] = useState(false);

  const [servers, setServers] = useState<Server[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [lastRefresh, setLastRefresh] = useState<string>("");

  const [query, setQuery] = useState("");
  const [jobPage, setJobPage] = useState(1);
  const [selectedJobIds, setSelectedJobIds] = useState<string[]>([]);

  // Active modals
  const [activeServerId, setActiveServerId] = useState<string | null>(null);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [terminalServer, setTerminalServer] = useState<Server | null>(null);
  const [activeApprovalId, setActiveApprovalId] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [formOpen, setFormOpen] = useState(false);
  const [formServer, setFormServer] = useState<Server | null>(null);

  // Action loading states
  const [checkingId, setCheckingId] = useState<string | null>(null);
  const [checkedId, setCheckedId] = useState<string | null>(null);
  const [confirmingKey, setConfirmingKey] = useState(false);
  const [decidingState, setDecidingState] = useState<{
    id: string;
    decision: "approve" | "reject";
  } | null>(null);

  const loadSnapshot = useCallback(async () => {
    try {
      const snap = await api.dashboardSnapshot();
      setServers(snap.servers);
      setApprovals(snap.approvals);
      setJobs(snap.jobs);
      setSettings(snap.settings);
      setLastRefresh(
        new Date().toLocaleTimeString("zh-CN", { hour12: false }),
      );
    } catch (e) {
      console.error("Failed to fetch dashboard snapshot:", e);
    }
  }, []);

  useEffect(() => {
    void loadSnapshot();
  }, [loadSnapshot]);

  // Instant backend push listener
  useEffect(() => {
    let unlistenState: (() => void) | null = null;
    let unlistenAppr: (() => void) | null = null;
    let unlistenOpenAppr: (() => void) | null = null;

    void listen("console:state-changed", () => {
      void loadSnapshot();
    }).then((fn) => {
      unlistenState = fn;
    });

    void listen<Approval>("console:approval-created", () => {
      void loadSnapshot();
    }).then((fn) => {
      unlistenAppr = fn;
    });

    void listen<{ approvalId: string }>("console:open-approval", (event) => {
      void loadSnapshot().then(() => {
        if (event.payload?.approvalId) {
          setActiveApprovalId(event.payload.approvalId);
        }
      });
    }).then((fn) => {
      unlistenOpenAppr = fn;
    });

    return () => {
      unlistenState?.();
      unlistenAppr?.();
      unlistenOpenAppr?.();
    };
  }, [loadSnapshot]);

  // Configurable UI auto-refresh interval
  const refreshInterval = settings?.refreshIntervalSeconds ?? 5;
  useEffect(() => {
    if (!refreshInterval) return undefined;
    const timer = window.setInterval(() => {
      void loadSnapshot();
    }, refreshInterval * 1000);
    return () => window.clearInterval(timer);
  }, [refreshInterval, loadSnapshot]);

  const clampWidth = (width: number) => {
    const total = colsRef.current
      ? colsRef.current.clientWidth
      : window.innerWidth;
    const max = Math.max(SPLIT_MIN, Math.min(SPLIT_MAX, total - LEFT_MIN));
    return Math.min(Math.max(width, SPLIT_MIN), max);
  };

  const startResize = (event: React.MouseEvent<HTMLDivElement>) => {
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = rightWidth;
    setDragging(true);

    const onMove = (e: MouseEvent) => {
      const next = clampWidth(startWidth - (e.clientX - startX));
      setRightWidth(next);
      localStorage.setItem(STORAGE_SPLIT_KEY, String(Math.round(next)));
    };
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      setDragging(false);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  };

  const filteredServers = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return servers;
    return servers.filter((s) =>
      [s.name, s.host, s.environment, s.username].some((v) =>
        v.toLowerCase().includes(q),
      ),
    );
  }, [query, servers]);

  const onlineCount = servers.filter(
    (s) => s.connectionStatus === "online",
  ).length;
  const offlineCount = servers.filter(
    (s) => s.connectionStatus === "offline",
  ).length;
  const pendingHostKeyCount = servers.filter(
    (s) =>
      s.connectionStatus === "host_key_required" ||
      s.connectionStatus === "host_key_changed" ||
      s.connectionStatus === "unknown",
  ).length;

  const jobPageCount = Math.max(1, Math.ceil(jobs.length / JOB_PAGE_SIZE));
  const currentJobPage = Math.min(jobPage, jobPageCount);
  const visibleJobs = jobs.slice(
    (currentJobPage - 1) * JOB_PAGE_SIZE,
    currentJobPage * JOB_PAGE_SIZE,
  );
  const selectableOnPage = visibleJobs
    .filter((j) => !isActiveJob(j))
    .map((j) => j.id);
  const allSelected =
    selectableOnPage.length > 0 &&
    selectableOnPage.every((id) => selectedJobIds.includes(id));
  const someSelected =
    !allSelected && selectableOnPage.some((id) => selectedJobIds.includes(id));

  const toggleAllJobs = (checked: boolean) => {
    setSelectedJobIds((list) =>
      checked
        ? Array.from(new Set([...list, ...selectableOnPage]))
        : list.filter((id) => !selectableOnPage.includes(id)),
    );
  };

  const toggleOneJob = (id: string, checked: boolean) => {
    setSelectedJobIds((list) =>
      checked ? Array.from(new Set([...list, id])) : list.filter((x) => x !== id),
    );
  };

  const toggleServerMode = async (target: Server, checked: boolean) => {
    try {
      const nextMode = checked ? "approval" : "direct";
      const updated = await api.serverPatch(target.id, {
        expectedRevision: target.revision,
        controlMode: nextMode,
      });
      setServers((list) =>
        list.map((s) => (s.id === updated.id ? updated : s)),
      );
      message.success(
        `${target.name} 已切换为${checked ? "需审批" : "全自动"}`,
      );
    } catch (e) {
      message.error(String(e));
    }
  };

  const handleCheckServer = async (target: Server) => {
    if (checkingId) return;
    setCheckingId(target.id);
    try {
      const res = await api.serverProbe(target.id);
      setServers((list) =>
        list.map((s) => (s.id === res.server.id ? res.server : s)),
      );
      setCheckedId(target.id);
      message.success(
        `${target.name} 连接正常${res.latencyMs !== null ? ` · ${res.latencyMs}ms` : ""}`,
      );
      window.setTimeout(() => setCheckedId(null), 1600);
    } catch (e) {
      const errText = String(e);
      await loadSnapshot();
      if (errText.startsWith("HOST_KEY_REQUIRED:")) {
        message.warning(`${target.name} 首次连接，请确认主机密钥指纹`);
        setActiveServerId(target.id);
      } else if (errText.startsWith("HOST_KEY_CHANGED:")) {
        message.error(`${target.name} 主机密钥发生变更！已阻断连接`);
        setActiveServerId(target.id);
      } else {
        message.error(`${target.name}: ${errText}`);
      }
    } finally {
      setCheckingId(null);
    }
  };

  const handleConfirmHostKey = async (target: Server, fingerprint: string) => {
    setConfirmingKey(true);
    try {
      const res = await api.serverConfirmHostKeyAndConnect(
        target.id,
        fingerprint,
        target.revision,
      );
      setServers((list) =>
        list.map((s) => (s.id === res.server.id ? res.server : s)),
      );
      message.success(
        `${target.name} 指纹已确认并上线${res.latencyMs !== null ? ` · ${res.latencyMs}ms` : ""}`,
      );
    } catch (e) {
      await loadSnapshot();
      message.error(String(e));
    } finally {
      setConfirmingKey(false);
    }
  };

  const handleDeleteServer = async (target: Server) => {
    try {
      await api.serverDelete(target.id);
      setActiveServerId(null);
      await loadSnapshot();
      message.success(`服务器 ${target.name} 已删除`);
    } catch (e) {
      message.error(String(e));
    }
  };

  const handleDecideApproval = async (
    item: Approval,
    decision: "approve" | "reject",
  ) => {
    if (decidingState) return;
    setDecidingState({ id: item.id, decision });
    try {
      await api.approvalDecide(item.id, decision, item.requestDigest);
      setActiveApprovalId(null);
      await loadSnapshot();
      if (decision === "approve") {
        message.success("已批准，任务开始执行");
      } else {
        message.info("已拒绝该请求");
      }
    } catch (e) {
      message.error(String(e));
    } finally {
      setDecidingState(null);
    }
  };

  const handleCancelJob = async (target: Job) => {
    try {
      await api.jobCancel(target.id);
      await loadSnapshot();
      message.info("取消请求已提交");
    } catch (e) {
      message.error(String(e));
    }
  };

  const handleRemoveJob = async (target: Job) => {
    try {
      await api.jobDelete(target.id);
      setSelectedJobIds((ids) => ids.filter((id) => id !== target.id));
      await loadSnapshot();
      message.success("任务记录已删除");
    } catch (e) {
      message.error(String(e));
    }
  };

  const handleDeleteSelectedJobs = async () => {
    try {
      const toDelete = [...selectedJobIds];
      await Promise.all(toDelete.map((id) => api.jobDelete(id)));
      setSelectedJobIds([]);
      await loadSnapshot();
      message.success(`已删除 ${toDelete.length} 条记录`);
    } catch (e) {
      message.error(String(e));
    }
  };

  const handleClearFinishedJobs = async () => {
    try {
      const count = await api.jobsClearFinished();
      setSelectedJobIds([]);
      await loadSnapshot();
      message.success(`已清理 ${count} 条记录`);
    } catch (e) {
      message.error(String(e));
    }
  };

  const handleUpdateSettings = async (patch: SettingsUpdateRequest) => {
    try {
      const next = await api.settingsUpdate(patch);
      setSettings(next);
      if (patch.refreshIntervalSeconds !== undefined) {
        message.success(
          patch.refreshIntervalSeconds === 0
            ? "已关闭自动刷新"
            : `自动刷新已设为每 ${patch.refreshIntervalSeconds} 秒`,
        );
      } else if (patch.autostartEnabled !== undefined) {
        message.success(
          patch.autostartEnabled
            ? "已开启开机自启，登录系统后将自动驻留托盘"
            : "已关闭开机自启",
        );
      } else {
        message.success("设置已更新");
      }
    } catch (e) {
      message.error(String(e));
    }
  };

  const activeServer =
    servers.find((s) => s.id === activeServerId) || null;
  const activeJob = jobs.find((j) => j.id === activeJobId) || null;
  const activeApproval =
    approvals.find((a) => a.id === activeApprovalId) || null;

  return (
    <div className="app">
      <header className="top">
        <div className="top-status">
          <span className="stat">
            <i className="dot" style={{ background: "#12b76a" }} />
            <b>{onlineCount}</b> 在线
          </span>
          <span className="stat">
            <i className="dot" style={{ background: "#c8372d" }} />
            <b>{offlineCount}</b> 离线
          </span>
          <span className="stat">
            <i className="dot" style={{ background: "#f79009" }} />
            <b>{pendingHostKeyCount}</b> 待确认
          </span>
          <span className="stat">
            <i className="dot" style={{ background: "#1677ff" }} />
            <b>{approvals.length}</b> 待审批
          </span>
        </div>
        <div
          style={{
            marginLeft: "auto",
            display: "flex",
            alignItems: "center",
            gap: 6,
          }}
        >
          <Tooltip title="设置">
            <Button
              type="text"
              icon={<SettingOutlined />}
              onClick={() => setSettingsOpen(true)}
            />
          </Tooltip>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setFormServer(null);
              setFormOpen(true);
            }}
            className="add-full"
          >
            添加服务器
          </Button>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setFormServer(null);
              setFormOpen(true);
            }}
            className="add-icon"
          />
        </div>
      </header>

      <main className="main">
        <div
          className="cols"
          ref={colsRef}
          style={{
            gridTemplateColumns: `minmax(0, 1fr) 9px ${rightWidth}px`,
          }}
        >
          <section className="col-left">
            <div className="sec-head">
              <div className="sec-title">
                服务器 <span className="sec-count">{servers.length}</span>
              </div>
              <Input
                variant="filled"
                allowClear
                prefix={<SearchOutlined style={{ color: "#aab0ba" }} />}
                placeholder="搜索"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                style={{ width: 168 }}
              />
            </div>

            <div className="srv-grid">
              {filteredServers.map((s) => {
                const metricRows: Array<[string, number]> | null =
                  s.connectionStatus === "online" && s.metrics
                    ? [
                        ["CPU", Math.round(s.metrics.cpuPercent)],
                        ["内存", Math.round(s.metrics.memoryPercent)],
                        ["磁盘", Math.round(s.metrics.diskPercent)],
                      ]
                    : null;

                return (
                  <div
                    className="srv-card"
                    key={s.id}
                    onClick={() => setActiveServerId(s.id)}
                  >
                    <div className="srv-card-top">
                      <div className="srv-name-wrap">
                        <span className="srv-name">{s.name}</span>
                        <span className="srv-env">{s.environment}</span>
                      </div>
                      <ServerStatusBadge status={s.connectionStatus} />
                    </div>

                    <div className="srv-host-row">
                      <span className="srv-host">
                        {s.host}:{s.port}
                      </span>
                      <span className="srv-time">
                        {formatRelativeTime(s.lastCheckedAt)}
                      </span>
                    </div>

                    {metricRows ? (
                      <div className="metrics">
                        {metricRows.map(([k, v]) => (
                          <div className="metric" key={k}>
                            <span className="metric-k">{k}</span>
                            <span className="metric-bar">
                              <i
                                style={{
                                  width: `${Math.min(100, Math.max(0, v))}%`,
                                  background: v >= 85 ? "#e5484d" : "#1677ff",
                                }}
                              />
                            </span>
                            <span className="metric-v">{v}%</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="metrics-empty">
                        {s.connectionStatus === "host_key_required" ||
                        s.connectionStatus === "unknown"
                          ? "确认主机指纹并连接后采集指标"
                          : s.connectionStatus === "host_key_changed"
                            ? "主机密钥已变更，连接已拦截"
                            : s.connectionStatus === "online"
                              ? "已连接，等待采样指标..."
                              : "离线，暂无指标"}
                      </div>
                    )}

                    <div
                      className="srv-actions"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <Tooltip title="开启后，该服务器的变更或高风险操作需要人工审批">
                        <span
                          className={`srv-mode${s.controlMode === "approval" ? " on" : ""}`}
                        >
                          需审批
                          <Switch
                            size="small"
                            checked={s.controlMode === "approval"}
                            onChange={(v) => toggleServerMode(s, v)}
                          />
                        </span>
                      </Tooltip>

                      <div className="srv-btns">
                        <Tooltip
                          title={
                            s.connectionStatus === "host_key_required"
                              ? "检查连接（获取并核对主机指纹）"
                              : "检查连接"
                          }
                        >
                          <Button
                            type="text"
                            size="small"
                            loading={checkingId === s.id}
                            icon={
                              checkedId === s.id ? (
                                <CheckOutlined style={{ color: "#12b76a" }} />
                              ) : (
                                <ThunderboltOutlined />
                              )
                            }
                            onClick={() => handleCheckServer(s)}
                          />
                        </Tooltip>
                        <Tooltip
                          title={
                            s.connectionStatus === "online"
                              ? "打开终端"
                              : "在线状态方可打开终端"
                          }
                        >
                          <Button
                            type="text"
                            size="small"
                            icon={<CodeOutlined />}
                            disabled={s.connectionStatus !== "online"}
                            onClick={() => setTerminalServer(s)}
                          />
                        </Tooltip>
                        <Tooltip title="编辑服务器">
                          <Button
                            type="text"
                            size="small"
                            icon={<EditOutlined />}
                            onClick={() => {
                              setFormServer(s);
                              setFormOpen(true);
                            }}
                          />
                        </Tooltip>
                      </div>
                    </div>
                  </div>
                );
              })}

              {filteredServers.length === 0 && (
                <div style={{ gridColumn: "1 / -1", padding: "48px 0" }}>
                  <Empty
                    image={Empty.PRESENTED_IMAGE_SIMPLE}
                    description={
                      servers.length === 0
                        ? "尚未添加服务器，点击右上角「添加服务器」开始管理"
                        : "没有匹配的服务器"
                    }
                  />
                </div>
              )}
            </div>
          </section>

          <div
            className={`splitter${dragging ? " dragging" : ""}`}
            role="separator"
            aria-orientation="vertical"
            aria-label="调整左右栏宽度"
            aria-valuenow={Math.round(rightWidth)}
            aria-valuemin={SPLIT_MIN}
            aria-valuemax={SPLIT_MAX}
            title="拖拽调整左右栏宽度，双击恢复默认"
            tabIndex={0}
            onMouseDown={startResize}
            onDoubleClick={() => {
              setRightWidth(SPLIT_DEFAULT);
              localStorage.setItem(STORAGE_SPLIT_KEY, String(SPLIT_DEFAULT));
            }}
            onKeyDown={(e) => {
              if (e.key === "ArrowLeft") {
                e.preventDefault();
                setRightWidth((w) => clampWidth(w + 16));
              }
              if (e.key === "ArrowRight") {
                e.preventDefault();
                setRightWidth((w) => clampWidth(w - 16));
              }
            }}
          >
            {dragging && (
              <span className="splitter-badge">{Math.round(rightWidth)} px</span>
            )}
          </div>

          <aside className="col-right">
            <div className="appr">
              <div className="sec-head">
                <div className="sec-title">
                  待审批 <span className="sec-count">{approvals.length}</span>
                </div>
              </div>
              {approvals.length === 0 ? (
                <div style={{ padding: "24px 0" }}>
                  <Empty
                    image={Empty.PRESENTED_IMAGE_SIMPLE}
                    description="没有待审批请求"
                  />
                </div>
              ) : (
                <div className="appr-scroll">
                  {approvals.map((a) => (
                    <div
                      className="appr-item"
                      key={a.id}
                      onClick={() => setActiveApprovalId(a.id)}
                    >
                      <div className="appr-top">
                        <span className="appr-name">{a.serverName}</span>
                        <span
                          className={`risk${a.risk === "high" ? "" : " mid"}`}
                          style={{ marginLeft: "auto" }}
                        >
                          <i
                            className="dot"
                            style={{ background: "currentColor" }}
                          />
                          {a.risk === "high" ? "高风险" : "中风险"}
                        </span>
                      </div>
                      <div className="appr-cmd">{a.commandPreview}</div>
                      <div className="appr-foot">
                        <span className="appr-meta">
                          {a.toolLabel} · {formatRemainingExpiry(a.expiresAt)}
                        </span>
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 6,
                            flexShrink: 0,
                          }}
                        >
                          <Button
                            size="small"
                            loading={
                              decidingState?.id === a.id &&
                              decidingState.decision === "reject"
                            }
                            disabled={
                              decidingState !== null &&
                              !(
                                decidingState.id === a.id &&
                                decidingState.decision === "reject"
                              )
                            }
                            onClick={(e) => {
                              e.stopPropagation();
                              void handleDecideApproval(a, "reject");
                            }}
                          >
                            拒绝
                          </Button>
                          <Button
                            size="small"
                            type="primary"
                            loading={
                              decidingState?.id === a.id &&
                              decidingState.decision === "approve"
                            }
                            disabled={
                              decidingState !== null &&
                              !(
                                decidingState.id === a.id &&
                                decidingState.decision === "approve"
                              )
                            }
                            onClick={(e) => {
                              e.stopPropagation();
                              void handleDecideApproval(a, "approve");
                            }}
                          >
                            批准
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="tasks">
              <div className="sec-head">
                <div className="sec-title">
                  <Checkbox
                    checked={allSelected}
                    indeterminate={someSelected}
                    disabled={selectableOnPage.length === 0}
                    onChange={(e) => toggleAllJobs(e.target.checked)}
                  />
                  最近任务 <span className="sec-count">{jobs.length}</span>
                </div>

                {selectedJobIds.length > 0 ? (
                  <div
                    style={{ display: "flex", alignItems: "center", gap: 6 }}
                  >
                    <span style={{ fontSize: 11, color: "var(--t3)" }}>
                      已选 {selectedJobIds.length}
                    </span>
                    <Popconfirm
                      title={`删除所选 ${selectedJobIds.length} 条记录？`}
                      description="任务记录与输出将一并删除。"
                      okText="删除"
                      okButtonProps={{ danger: true }}
                      cancelText="取消"
                      onConfirm={handleDeleteSelectedJobs}
                    >
                      <Button
                        type="text"
                        size="small"
                        danger
                        style={{ fontSize: 11.5, paddingInline: 4 }}
                      >
                        删除所选
                      </Button>
                    </Popconfirm>
                  </div>
                ) : jobs.some((j) => !isActiveJob(j)) ? (
                  <Popconfirm
                    title="清理已结束的任务？"
                    description="仅删除已结束的记录，等待审批或执行中的任务不会受影响。"
                    okText="清理"
                    cancelText="取消"
                    onConfirm={handleClearFinishedJobs}
                  >
                    <Button
                      type="text"
                      size="small"
                      style={{
                        color: "var(--t3)",
                        fontSize: 11.5,
                        paddingInline: 4,
                      }}
                    >
                      清理已结束
                    </Button>
                  </Popconfirm>
                ) : null}
              </div>

              <div className="task-scroll">
                {visibleJobs.map((j) => {
                  const targetLabel =
                    j.targets.length === 1
                      ? j.targets[0]!.serverName
                      : `${j.targets.length} 台服务器`;
                  return (
                    <div
                      className={`task-row${selectedJobIds.includes(j.id) ? " selected" : ""}`}
                      key={j.id}
                      onClick={() => setActiveJobId(j.id)}
                    >
                      <span
                        className="task-check"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Checkbox
                          checked={selectedJobIds.includes(j.id)}
                          disabled={isActiveJob(j)}
                          onChange={(e) => toggleOneJob(j.id, e.target.checked)}
                        />
                      </span>
                      <div className="task-main">
                        <div className="task-tool">{j.toolLabel}</div>
                        <div className="task-sub">{targetLabel}</div>
                      </div>
                      <JobStatusBadge status={j.status} />
                      <span className="task-time">
                        {formatJobTime(j.createdAt)}
                      </span>
                      <span
                        className="task-act"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {isActiveJob(j) ? (
                          <Tooltip title="取消任务">
                            <Button
                              type="text"
                              size="small"
                              icon={<StopOutlined />}
                              onClick={() => handleCancelJob(j)}
                            />
                          </Tooltip>
                        ) : (
                          <Popconfirm
                            title="删除这条任务记录？"
                            description="任务记录与输出将一并删除。"
                            okText="删除"
                            okButtonProps={{ danger: true }}
                            cancelText="取消"
                            onConfirm={() => handleRemoveJob(j)}
                          >
                            <Button
                              type="text"
                              size="small"
                              icon={<DeleteOutlined />}
                            />
                          </Popconfirm>
                        )}
                      </span>
                    </div>
                  );
                })}

                {jobs.length === 0 && (
                  <div
                    style={{
                      padding: "28px 0",
                      fontSize: 11.5,
                      color: "var(--t4)",
                      textAlign: "center",
                    }}
                  >
                    没有任务记录
                  </div>
                )}
              </div>

              {(selectedJobIds.length > 0 || jobs.length > JOB_PAGE_SIZE) && (
                <div className="list-foot">
                  <span>
                    {selectedJobIds.length > 0
                      ? `已选 ${selectedJobIds.length} 项`
                      : ""}
                  </span>
                  {jobs.length > JOB_PAGE_SIZE && (
                    <Pagination
                      size="small"
                      simple
                      current={currentJobPage}
                      pageSize={JOB_PAGE_SIZE}
                      total={jobs.length}
                      onChange={(next) => setJobPage(next)}
                    />
                  )}
                </div>
              )}
            </div>
          </aside>
        </div>
      </main>

      <ServerDetailModal
        server={activeServer}
        checking={checkingId === activeServer?.id}
        confirmingKey={confirmingKey}
        onClose={() => setActiveServerId(null)}
        onEdit={(s) => {
          setActiveServerId(null);
          setFormServer(s);
          setFormOpen(true);
        }}
        onDelete={handleDeleteServer}
        onCheck={handleCheckServer}
        onTerminal={(s) => {
          setActiveServerId(null);
          setTerminalServer(s);
        }}
        onConfirmKey={handleConfirmHostKey}
      />

      <JobModal job={activeJob} onClose={() => setActiveJobId(null)} />

      <TerminalModal
        server={terminalServer}
        onClose={() => setTerminalServer(null)}
      />

      <ApprovalModal
        approval={activeApproval}
        submitting={decidingState !== null}
        onClose={() => setActiveApprovalId(null)}
        onDecide={handleDecideApproval}
      />

      <SettingsModal
        open={settingsOpen}
        settings={settings}
        lastRefresh={lastRefresh}
        onClose={() => setSettingsOpen(false)}
        onUpdateSettings={handleUpdateSettings}
        onBackupImported={loadSnapshot}
      />

      <ServerFormModal
        open={formOpen}
        server={formServer}
        onClose={() => setFormOpen(false)}
        onSaved={(saved, isNew) => {
          void loadSnapshot();
          if (isNew) {
            setActiveServerId(saved.id);
          }
        }}
      />
    </div>
  );
};
