import React, { useEffect, useState } from "react";
import {
  Button,
  Input,
  InputNumber,
  Modal,
  Select,
  Switch,
  message,
} from "antd";
import {
  CloudSyncOutlined,
  CopyOutlined,
  DownloadOutlined,
  RightOutlined,
  SyncOutlined,
  UploadOutlined,
} from "@ant-design/icons";
import { listen } from "@tauri-apps/api/event";
import {
  open as openFileDialog,
  save as saveFileDialog,
} from "@tauri-apps/plugin-dialog";
import type {
  AppSettings,
  BackupApplyDecision,
  BackupImportAction,
  BackupPreflight,
  SettingsUpdateRequest,
  UpdateStatusSnapshot,
} from "../../types/models";
import { api, formatBytes, formatRelativeTime } from "../../api/client";

interface Props {
  open: boolean;
  settings: AppSettings | null;
  lastRefresh: string;
  onClose: () => void;
  onUpdateSettings: (patch: SettingsUpdateRequest) => Promise<void>;
  onBackupImported: () => void;
}

export const SettingsModal: React.FC<Props> = ({
  open,
  settings,
  lastRefresh,
  onClose,
  onUpdateSettings,
  onBackupImported,
}) => {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [syncingSkills, setSyncingSkills] = useState(false);
  const [updateStatus, setUpdateStatus] = useState<UpdateStatusSnapshot | null>(
    null,
  );
  const [installingUpdate, setInstallingUpdate] = useState(false);

  // Export backup dialog state
  const [exportOpen, setExportOpen] = useState(false);
  const [exportPass, setExportPass] = useState("");
  const [exporting, setExporting] = useState(false);

  // Import backup dialog state
  const [importOpen, setImportOpen] = useState(false);
  const [importPath, setImportPath] = useState("");
  const [importPass, setImportPass] = useState("");
  const [preflight, setPreflight] = useState<BackupPreflight | null>(null);
  const [decisions, setDecisions] = useState<Record<string, BackupImportAction>>({});
  const [importing, setImporting] = useState(false);

  useEffect(() => {
    if (!open) return;
    void api
      .updaterGetStatus()
      .then(setUpdateStatus)
      .catch(() => {});
  }, [open]);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    void listen<UpdateStatusSnapshot>("console:updater-changed", (event) => {
      if (event.payload) {
        setUpdateStatus(event.payload);
      }
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  const copyLine = async (val: string, label: string) => {
    await navigator.clipboard.writeText(val);
    message.success(`${label}已复制`);
  };

  const buildAiBootstrapPrompt = (s: AppSettings) => {
    const exeMatch = /^"([^"]+)"/.exec(s.mcpStdioCommand);
    const stdioExe = exeMatch ? exeMatch[1] : "ssh-mcp-stdio.exe";
    return [
      `请帮我接入本机服务器控制台 MCP 服务（名称设为 ssh-mcp）并自动安装配套 Skills：`,
      `1. 执行命令自动安装配套的 7 个受控运维 Skills：`,
      `   "${stdioExe}" --install-skills`,
      `2. 配置 MCP 服务 ssh-mcp（任选其一，连接握手及后续应用升级时均会自动同步最新 Skills）：`,
      `   - Stdio 命令：${s.mcpStdioCommand}`,
      `   - 或 Streamable HTTP：${s.mcpHttpEndpoint}`,
    ].join("\n");
  };

  const handleSyncSkillsNow = async () => {
    setSyncingSkills(true);
    try {
      const res = await api.skillsSyncNow();
      message.success(
        res.updated
          ? `已更新 ${res.filesWritten} 个文件（共 ${res.skillCount} 个 Skills）至 ${res.syncedTargets.length} 个本机 AI 目录`
          : `本机 ${res.syncedTargets.length} 个 AI 目录中的 ${res.skillCount} 个 Skills 均已是最新（v${res.appVersion}）`,
      );
    } catch (e) {
      message.error(String(e));
    } finally {
      setSyncingSkills(false);
    }
  };

  const handleCheckUpdateNow = async () => {
    try {
      const snap = await api.updaterCheckNow();
      setUpdateStatus(snap);
      if (snap.phase === "up_to_date") {
        message.success(`当前已是最新版本 v${snap.currentVersion}`);
      } else if (snap.phase === "ready" && snap.latestVersion) {
        message.success(`新版本 v${snap.latestVersion} 已下载就绪，可点击立即重启更新`);
      } else if (snap.phase === "available" && snap.latestVersion) {
        message.info(`发现新版本 v${snap.latestVersion}`);
      } else if (snap.phase === "error" && snap.error) {
        message.warning(snap.error);
      }
    } catch (e) {
      message.error(String(e));
    }
  };

  const handleInstallUpdateNow = async () => {
    setInstallingUpdate(true);
    try {
      await api.updaterInstallNow();
    } catch (e) {
      setInstallingUpdate(false);
      message.error(String(e));
    }
  };

  const renderUpdateDescription = () => {
    if (!updateStatus) {
      return "开启后自动检查并后台下载新版本，就绪后提示重启完成升级";
    }
    const { phase, latestVersion, downloadedBytes, totalBytes, error, lastCheckedAt } =
      updateStatus;

    if (phase === "checking") {
      return "正在连接 GitHub Releases 检查最新版本...";
    }
    if (phase === "downloading") {
      if (totalBytes && totalBytes > 0) {
        const pct = Math.min(100, Math.round((downloadedBytes / totalBytes) * 100));
        return `正在后台下载 v${latestVersion ?? ""} 更新包 · ${pct}% (${formatBytes(downloadedBytes)} / ${formatBytes(totalBytes)})`;
      }
      return `正在后台下载 v${latestVersion ?? ""} 更新包 · 已下载 ${formatBytes(downloadedBytes)}`;
    }
    if (phase === "ready") {
      return `新版本 v${latestVersion ?? ""} 已下载就绪，点击右侧按钮立即重启完成升级`;
    }
    if (phase === "installing") {
      return "正在关闭服务并启动安装程序，请稍候...";
    }
    if (phase === "available") {
      return `发现新版本 v${latestVersion ?? ""}，点击右侧按钮下载并重启升级`;
    }
    if (phase === "up_to_date") {
      return `当前已是最新版本${lastCheckedAt ? ` · 检查于${formatRelativeTime(lastCheckedAt)}` : ""}`;
    }
    if (phase === "error" && error) {
      return error;
    }
    return `开启后自动后台下载新版本，就绪后提示重启安装${lastCheckedAt ? ` · 上次检查${formatRelativeTime(lastCheckedAt)}` : ""}`;
  };

  const handleStartExport = async () => {
    if (exportPass.length < 8) {
      message.warning("加密口令长度至少 8 位");
      return;
    }
    setExporting(true);
    try {
      const dest = await saveFileDialog({
        title: "导出加密备份文件",
        defaultPath: `ssh-mcp-backup-${new Date().toISOString().slice(0, 10)}.ssc-backup`,
        filters: [{ name: "Encrypted Backup", extensions: ["ssc-backup", "json"] }],
      });
      if (dest) {
        await api.backupExportToFile(dest, exportPass);
        message.success("加密备份导出成功");
        setExportOpen(false);
        setExportPass("");
      }
    } catch (e) {
      message.error(String(e));
    } finally {
      setExporting(false);
    }
  };

  const handleOpenImport = async () => {
    try {
      const selected = await openFileDialog({
        multiple: false,
        title: "选择加密备份文件",
        filters: [{ name: "Encrypted Backup", extensions: ["ssc-backup", "json"] }],
      });
      if (typeof selected === "string" && selected) {
        setImportPath(selected);
        setImportPass("");
        setPreflight(null);
        setDecisions({});
        setImportOpen(true);
      }
    } catch (e) {
      message.error(String(e));
    }
  };

  const handlePreflight = async () => {
    if (!importPass) {
      message.warning("请输入备份解密口令");
      return;
    }
    setImporting(true);
    try {
      const res = await api.backupPreflightFromFile(importPath, importPass);
      setPreflight(res);
      const initDec: Record<string, BackupImportAction> = {};
      for (const item of res.servers) {
        initDec[item.sourceId] = item.conflict ? "overwrite" : "create_new";
      }
      setDecisions(initDec);
    } catch (e) {
      message.error(String(e));
    } finally {
      setImporting(false);
    }
  };

  const handleApplyImport = async () => {
    if (!preflight) return;
    setImporting(true);
    try {
      const payload: BackupApplyDecision[] = preflight.servers.map((s) => ({
        sourceId: s.sourceId,
        action: decisions[s.sourceId] || "skip",
      }));
      const res = await api.backupApplyImport(preflight.importId, payload);
      message.success(
        `导入完成：新增 ${res.created} 台，覆盖 ${res.overwritten} 台，跳过 ${res.skipped} 台`,
      );
      setImportOpen(false);
      onBackupImported();
    } catch (e) {
      message.error(String(e));
    } finally {
      setImporting(false);
    }
  };

  const isBusyCheckingOrDownloading =
    updateStatus?.phase === "checking" ||
    updateStatus?.phase === "downloading" ||
    updateStatus?.phase === "installing" ||
    installingUpdate;

  const canInstallUpdate =
    updateStatus?.phase === "ready" || updateStatus?.phase === "available";

  return (
    <>
      <Modal
        className="ncp-modal"
        open={open}
        onCancel={onClose}
        width={560}
        centered
        footer={null}
        title={<span style={{ fontSize: 14, fontWeight: 600 }}>设置</span>}
      >
        {settings && (
          <>
            <div className="srow">
              <div>
                <div className="sname">MCP 服务</div>
                <div className="sdesc">
                  允许本地 AI 客户端调用受控运维能力（需审批模式下只读命令自动免审批）
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span className={`st${settings.mcpRunning ? "" : " off"}`}>
                  <i
                    className="dot"
                    style={{
                      background: settings.mcpRunning ? "#12b76a" : "#c8372d",
                    }}
                  />
                  {settings.mcpRunning ? "运行中" : "已停止"}
                </span>
                <Switch
                  size="small"
                  checked={settings.mcpEnabled}
                  onChange={(checked) =>
                    onUpdateSettings({ mcpEnabled: checked })
                  }
                />
              </div>
            </div>

            <div className="srow" style={{ display: "block" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 8,
                }}
              >
                <div className="sname">连接命令（自动热更新配套 Skills）</div>
                <div style={{ display: "flex", gap: 6 }}>
                  <Button
                    size="small"
                    icon={<SyncOutlined spin={syncingSkills} />}
                    onClick={handleSyncSkillsNow}
                  >
                    立即同步本机 Skills
                  </Button>
                  <Button
                    size="small"
                    type="primary"
                    icon={<CopyOutlined />}
                    onClick={() =>
                      copyLine(
                        buildAiBootstrapPrompt(settings),
                        "AI 一键接入与安装 Skills 指令",
                      )
                    }
                  >
                    复制给 AI 自动配置
                  </Button>
                </div>
              </div>
              <div className="sdesc" style={{ marginTop: 3 }}>
                控制台启动、版本升级及 AI 连接时，会自动检测并将内置最新的 7 个 ssh-mcp Skills 热更新至本机 AI 目录（并通知会话刷新）
              </div>
              <div className="cmdline">
                <code>{settings.mcpStdioCommand}</code>
                <Button
                  type="text"
                  size="small"
                  icon={<CopyOutlined />}
                  onClick={() =>
                    copyLine(settings.mcpStdioCommand, "Stdio 连接命令")
                  }
                />
              </div>
              <div className="cmdline" style={{ marginTop: 6 }}>
                <code>Streamable HTTP: {settings.mcpHttpEndpoint}</code>
                <Button
                  type="text"
                  size="small"
                  icon={<CopyOutlined />}
                  onClick={() =>
                    copyLine(settings.mcpHttpEndpoint, "HTTP MCP 地址")
                  }
                />
              </div>
            </div>

            <div className="srow">
              <div>
                <div className="sname">自动刷新</div>
                <div className="sdesc">
                  服务器与任务状态的更新频率
                  {settings.refreshIntervalSeconds === 0
                    ? " · 当前已关闭"
                    : lastRefresh
                      ? ` · 最近刷新 ${lastRefresh}`
                      : ""}
                </div>
              </div>
              <Select
                value={settings.refreshIntervalSeconds}
                onChange={(value) =>
                  onUpdateSettings({ refreshIntervalSeconds: value })
                }
                style={{ width: 112 }}
                options={[
                  { value: 0, label: "关闭" },
                  { value: 3, label: "每 3 秒" },
                  { value: 5, label: "每 5 秒" },
                  { value: 10, label: "每 10 秒" },
                  { value: 30, label: "每 30 秒" },
                ]}
              />
            </div>

            <div className="srow">
              <div>
                <div className="sname">失败告警</div>
                <div className="sdesc">
                  任务失败或服务器离线时发送 Windows 系统通知
                </div>
              </div>
              <Switch
                size="small"
                checked={settings.failureAlertsEnabled}
                onChange={(checked) =>
                  onUpdateSettings({ failureAlertsEnabled: checked })
                }
              />
            </div>

            <div className="srow">
              <div>
                <div className="sname">开机自启</div>
                <div className="sdesc">
                  登录 Windows 时自动启动控制台并静默驻留系统托盘
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span
                  className="st"
                  style={{
                    color: settings.autostartEnabled ? "var(--t2)" : "var(--t4)",
                  }}
                >
                  <i
                    className="dot"
                    style={{
                      background: settings.autostartEnabled
                        ? "#12b76a"
                        : "#c9ced6",
                    }}
                  />
                  {settings.autostartEnabled ? "已开启" : "未开启"}
                </span>
                <Switch
                  size="small"
                  checked={settings.autostartEnabled}
                  onChange={(checked) =>
                    onUpdateSettings({ autostartEnabled: checked })
                  }
                />
              </div>
            </div>

            <div className="srow" style={{ display: "block" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 12,
                }}
              >
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div
                    className="sname"
                    style={{ display: "flex", alignItems: "center", gap: 8 }}
                  >
                    <span>版本更新</span>
                    <span
                      className="mono"
                      style={{
                        fontSize: 11,
                        padding: "1px 6px",
                        borderRadius: 4,
                        background: "var(--bg-soft, #f2f4f7)",
                        color: "var(--t3)",
                        fontWeight: 500,
                      }}
                    >
                      v{updateStatus?.currentVersion || "1.0.0"}
                    </span>
                  </div>
                  <div
                    className="sdesc"
                    style={{
                      color:
                        updateStatus?.phase === "error"
                          ? "#c8372d"
                          : updateStatus?.phase === "ready"
                            ? "#067647"
                            : undefined,
                    }}
                  >
                    {renderUpdateDescription()}
                  </div>
                </div>

                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    flexShrink: 0,
                  }}
                >
                  {canInstallUpdate ? (
                    <Button
                      size="small"
                      type="primary"
                      icon={<CloudSyncOutlined />}
                      loading={installingUpdate || updateStatus?.phase === "installing"}
                      onClick={handleInstallUpdateNow}
                    >
                      {updateStatus?.phase === "ready"
                        ? `立即重启更新 (v${updateStatus.latestVersion})`
                        : `下载并更新 (v${updateStatus?.latestVersion})`}
                    </Button>
                  ) : (
                    <Button
                      size="small"
                      icon={<SyncOutlined spin={isBusyCheckingOrDownloading} />}
                      disabled={isBusyCheckingOrDownloading}
                      onClick={handleCheckUpdateNow}
                    >
                      检查更新
                    </Button>
                  )}

                  <Switch
                    size="small"
                    title="开启或关闭自动版本更新"
                    checked={settings.autoUpdateEnabled}
                    onChange={(checked) =>
                      onUpdateSettings({ autoUpdateEnabled: checked })
                    }
                  />
                </div>
              </div>

              {updateStatus?.releaseNotes &&
                (updateStatus.phase === "available" ||
                  updateStatus.phase === "downloading" ||
                  updateStatus.phase === "ready") && (
                  <div
                    className="cmdline"
                    style={{
                      marginTop: 8,
                      display: "block",
                      maxHeight: 96,
                      overflow: "auto",
                      whiteSpace: "pre-wrap",
                      fontSize: 11.5,
                      color: "var(--t3)",
                    }}
                  >
                    {updateStatus.releaseNotes}
                  </div>
                )}
            </div>

            <div className="srow">
              <div>
                <div className="sname">配置备份</div>
                <div className="sdesc">
                  使用口令加密导出或跨机恢复服务器与私钥
                </div>
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <Button
                  size="small"
                  icon={<DownloadOutlined />}
                  onClick={() => setExportOpen(true)}
                >
                  导出备份
                </Button>
                <Button
                  size="small"
                  icon={<UploadOutlined />}
                  onClick={handleOpenImport}
                >
                  导入恢复
                </Button>
              </div>
            </div>

            <div style={{ paddingTop: 10 }}>
              <button
                type="button"
                onClick={() => setShowAdvanced((v) => !v)}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: 0,
                  border: 0,
                  background: "transparent",
                  color: "var(--t2)",
                  fontSize: 12,
                  cursor: "pointer",
                }}
              >
                <RightOutlined
                  style={{
                    fontSize: 10,
                    transform: showAdvanced ? "rotate(90deg)" : "none",
                    transition: "transform .15s ease",
                  }}
                />
                高级执行与系统策略
              </button>

              {showAdvanced && (
                <div style={{ marginTop: 6 }}>
                  <div className="srow">
                    <div>
                      <div className="sname">默认并发服务器数</div>
                      <div className="sdesc">单个任务同时执行的服务器上限</div>
                    </div>
                    <InputNumber
                      min={1}
                      max={10}
                      value={settings.defaultConcurrency}
                      onChange={(val) => {
                        if (val) onUpdateSettings({ defaultConcurrency: val });
                      }}
                      style={{ width: 88 }}
                    />
                  </div>

                  <div
                    className="srow"
                    style={{ borderBottom: 0, paddingBottom: 2 }}
                  >
                    <div>
                      <div className="sname">默认命令超时（秒）</div>
                      <div className="sdesc">远程操作未显式指定时的超时上限</div>
                    </div>
                    <InputNumber
                      min={5}
                      max={1800}
                      step={30}
                      value={settings.defaultTimeoutSeconds}
                      onChange={(val) => {
                        if (val)
                          onUpdateSettings({ defaultTimeoutSeconds: val });
                      }}
                      style={{ width: 88 }}
                    />
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </Modal>

      {/* 导出备份口令弹窗 */}
      <Modal
        className="ncp-modal"
        open={exportOpen}
        onCancel={() => setExportOpen(false)}
        width={420}
        centered
        footer={null}
        title={<span style={{ fontSize: 14, fontWeight: 600 }}>导出加密备份</span>}
      >
        <div className="sdesc" style={{ marginBottom: 12 }}>
          备份文件采用 Argon2id + AES-256-GCM 加密，本机密钥路径会自动内联以便跨电脑恢复。请妥善保管口令。
        </div>
        <Input.Password
          placeholder="设置备份口令（至少 8 位，建议 12 位以上）"
          value={exportPass}
          onChange={(e) => setExportPass(e.target.value)}
        />
        <div className="modal-foot">
          <span />
          <div style={{ display: "flex", gap: 8 }}>
            <Button onClick={() => setExportOpen(false)}>取消</Button>
            <Button
              type="primary"
              loading={exporting}
              onClick={handleStartExport}
            >
              选择位置并导出
            </Button>
          </div>
        </div>
      </Modal>

      {/* 导入恢复预览弹窗 */}
      <Modal
        className="ncp-modal"
        open={importOpen}
        onCancel={() => setImportOpen(false)}
        width={500}
        centered
        footer={null}
        title={<span style={{ fontSize: 14, fontWeight: 600 }}>导入加密备份</span>}
      >
        <div className="cmdline" style={{ marginTop: 0, marginBottom: 12 }}>
          <code>{importPath}</code>
        </div>

        {!preflight ? (
          <>
            <Input.Password
              placeholder="输入备份文件解密口令"
              value={importPass}
              onChange={(e) => setImportPass(e.target.value)}
              onPressEnter={handlePreflight}
            />
            <div className="modal-foot">
              <span />
              <div style={{ display: "flex", gap: 8 }}>
                <Button onClick={() => setImportOpen(false)}>取消</Button>
                <Button
                  type="primary"
                  loading={importing}
                  onClick={handlePreflight}
                >
                  解密并预览冲突
                </Button>
              </div>
            </div>
          </>
        ) : (
          <>
            <div className="k" style={{ marginBottom: 8 }}>
              共解析到 {preflight.servers.length} 台服务器配置：
            </div>
            <div style={{ maxHeight: 240, overflow: "auto" }}>
              {preflight.servers.map((item) => (
                <div
                  key={item.sourceId}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "7px 0",
                    borderBottom: "1px solid var(--line-soft)",
                  }}
                >
                  <div>
                    <div style={{ fontSize: 12.5, fontWeight: 500 }}>
                      {item.name}{" "}
                      <span className="mono" style={{ color: "var(--t4)" }}>
                        ({item.host}:{item.port})
                      </span>
                    </div>
                    {item.conflict && (
                      <div style={{ fontSize: 11, color: "#b54708" }}>
                        与本机已有服务器同名或同地址
                      </div>
                    )}
                  </div>
                  <Select
                    size="small"
                    style={{ width: 108 }}
                    value={decisions[item.sourceId] || "skip"}
                    onChange={(val) =>
                      setDecisions((d) => ({ ...d, [item.sourceId]: val }))
                    }
                    options={
                      item.conflict
                        ? [
                            { value: "overwrite", label: "覆盖现有" },
                            { value: "create_new", label: "另存新建" },
                            { value: "skip", label: "跳过" },
                          ]
                        : [
                            { value: "create_new", label: "导入新建" },
                            { value: "skip", label: "跳过" },
                          ]
                    }
                  />
                </div>
              ))}
            </div>
            <div className="modal-foot">
              <span style={{ fontSize: 11, color: "var(--t4)" }}>
                导入后将重新使用本机 DPAPI 加密存储
              </span>
              <div style={{ display: "flex", gap: 8 }}>
                <Button onClick={() => setImportOpen(false)}>取消</Button>
                <Button
                  type="primary"
                  loading={importing}
                  onClick={handleApplyImport}
                >
                  确认恢复
                </Button>
              </div>
            </div>
          </>
        )}
      </Modal>
    </>
  );
};
