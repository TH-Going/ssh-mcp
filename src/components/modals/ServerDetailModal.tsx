import React from "react";
import { Button, Modal, Popconfirm, Tooltip, message } from "antd";
import {
  CodeOutlined,
  CopyOutlined,
  DeleteOutlined,
  EditOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
  WarningOutlined,
} from "@ant-design/icons";
import type { ConnectionStatus, Server } from "../../types/models";
import { authKindLabel, formatRelativeTime } from "../../api/client";

export const SERVER_STATUS_META: Record<
  ConnectionStatus,
  { label: string; cls: string }
> = {
  online: { label: "在线", cls: "" },
  offline: { label: "离线", cls: "off" },
  unknown: { label: "未检查", cls: "warn" },
  checking: { label: "校验中", cls: "warn" },
  host_key_required: { label: "待确认", cls: "warn" },
  host_key_changed: { label: "密钥变更", cls: "off" },
};

export function ServerStatusBadge({ status }: { status: ConnectionStatus }) {
  const meta = SERVER_STATUS_META[status] || SERVER_STATUS_META.unknown;
  return (
    <span className={`st ${meta.cls}`}>
      <i className="dot" style={{ background: "currentColor" }} />
      {meta.label}
    </span>
  );
}

interface Props {
  server: Server | null;
  checking: boolean;
  confirmingKey: boolean;
  onClose: () => void;
  onEdit: (server: Server) => void;
  onDelete: (server: Server) => void;
  onCheck: (server: Server) => void;
  onTerminal: (server: Server) => void;
  onConfirmKey: (server: Server, fingerprint: string) => void;
}

export const ServerDetailModal: React.FC<Props> = ({
  server,
  checking,
  confirmingKey,
  onClose,
  onEdit,
  onDelete,
  onCheck,
  onTerminal,
  onConfirmKey,
}) => {
  const isFirstSeen =
    server &&
    (server.connectionStatus === "host_key_required" ||
      (!server.hostKeyFingerprint && server.connectionStatus === "unknown"));
  const isKeyChanged = server?.connectionStatus === "host_key_changed";
  const pendingFp = server?.pendingHostKeyFingerprint;

  const copyText = async (val: string, label: string) => {
    await navigator.clipboard.writeText(val);
    message.success(`${label}已复制`);
  };

  return (
    <Modal
      className="ncp-modal"
      open={!!server}
      onCancel={onClose}
      width={560}
      centered
      footer={null}
      title={
        server ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              paddingRight: 28,
            }}
          >
            <span style={{ fontSize: 14, fontWeight: 600 }}>{server.name}</span>
            <ServerStatusBadge status={server.connectionStatus} />
          </div>
        ) : (
          ""
        )
      }
    >
      {server && (
        <>
          <div className="mono" style={{ fontSize: 12 }}>
            {server.host}:{server.port}
            {server.connectionStatus === "online" &&
              server.lastLatencyMs !== null && (
                <span style={{ color: "#12b76a", marginLeft: 10 }}>
                  · {server.lastLatencyMs}ms
                </span>
              )}
          </div>

          {server.connectionStatus === "offline" && (
            <div className="err-line">
              {server.lastError || "上次连接失败，请检查网络或 SSH 服务。"}
            </div>
          )}

          <div className="meta3" style={{ marginTop: 18 }}>
            <div>
              <div className="k">环境</div>
              <div className="v">{server.environment}</div>
            </div>
            <div>
              <div className="k">控制模式</div>
              <div className="v">
                {server.controlMode === "approval" ? "需审批" : "全自动"}
              </div>
            </div>
            <div>
              <div className="k">SSH 用户</div>
              <div className="v">{server.username}</div>
            </div>
            <div>
              <div className="k">认证</div>
              <div className="v">
                {authKindLabel(server)}
                {server.hasSudoPassword ? " · 含 sudo 口令" : ""}
              </div>
            </div>
            <div>
              <div className="k">最近检查</div>
              <div className="v">{formatRelativeTime(server.lastCheckedAt)}</div>
            </div>
            <div>
              <div className="k">主机密钥</div>
              <div className="v">
                {server.hostKeyStatus === "trusted"
                  ? "已信任"
                  : server.hostKeyStatus === "changed"
                    ? "已变更（拦截）"
                    : "未确认"}
              </div>
            </div>
          </div>

          {server.hostKeyFingerprint && !isKeyChanged && (
            <div className="cmdline" style={{ marginTop: 14 }}>
              <code>已信任指纹: {server.hostKeyFingerprint}</code>
              <Tooltip title="复制指纹">
                <Button
                  type="text"
                  size="small"
                  icon={<CopyOutlined />}
                  onClick={() =>
                    copyText(server.hostKeyFingerprint!, "主机密钥指纹")
                  }
                />
              </Tooltip>
            </div>
          )}

          {isFirstSeen && (
            <div className="key-block warn">
              <div className="key-title">
                <SafetyCertificateOutlined /> 首次连接，需要确认服务器身份
              </div>
              <div className="key-hint">
                <div>这台服务器尚未被本机信任，确认后才会建立正式连接。</div>
                {pendingFp ? (
                  <div
                    className="mono"
                    style={{
                      marginTop: 6,
                      padding: "6px 8px",
                      borderRadius: 5,
                      background: "rgba(255,255,255,0.75)",
                      color: "#7c2d12",
                    }}
                  >
                    观测到的指纹：{pendingFp}
                  </div>
                ) : (
                  <div>
                    请先点击下方「获取主机指纹」，读取远端公钥指纹并核对无误后再确认连接。
                  </div>
                )}
              </div>
              <div className="key-actions">
                {pendingFp ? (
                  <>
                    <Button
                      size="small"
                      type="primary"
                      loading={confirmingKey}
                      icon={<SafetyCertificateOutlined />}
                      onClick={() => onConfirmKey(server, pendingFp)}
                    >
                      确认并连接
                    </Button>
                    <Button
                      size="small"
                      icon={<CopyOutlined />}
                      onClick={() => copyText(pendingFp, "待确认指纹")}
                    >
                      复制指纹
                    </Button>
                  </>
                ) : (
                  <Button
                    size="small"
                    type="primary"
                    loading={checking}
                    icon={<ThunderboltOutlined />}
                    onClick={() => onCheck(server)}
                  >
                    获取主机指纹
                  </Button>
                )}
              </div>
            </div>
          )}

          {isKeyChanged && (
            <div className="key-block danger">
              <div className="key-title">
                <WarningOutlined /> 高危告警：远程主机密钥已发生变更！
              </div>
              <div className="key-hint">
                <div>
                  远端返回的 SSH 公钥与历史信任指纹不一致，可能因服务器重装或存在中间人劫持，已自动阻断连接。
                </div>
                {server.hostKeyFingerprint && (
                  <div className="mono" style={{ marginTop: 6, color: "#7f1d1d" }}>
                    原信任指纹：{server.hostKeyFingerprint}
                  </div>
                )}
                {pendingFp && (
                  <div className="mono" style={{ marginTop: 4, color: "#991b1b", fontWeight: 600 }}>
                    新观测指纹：{pendingFp}
                  </div>
                )}
              </div>
              {pendingFp && (
                <div className="key-actions">
                  <Popconfirm
                    title="确认信任新的主机密钥？"
                    description="请务必与运维人员核实服务器确实重装或更换过 SSH 密钥。"
                    okText="确认替换并重连"
                    okButtonProps={{ danger: true }}
                    cancelText="取消"
                    onConfirm={() => onConfirmKey(server, pendingFp)}
                  >
                    <Button
                      size="small"
                      danger
                      type="primary"
                      loading={confirmingKey}
                      icon={<SafetyCertificateOutlined />}
                    >
                      信任新指纹并连接
                    </Button>
                  </Popconfirm>
                </div>
              )}
            </div>
          )}

          <div className="modal-foot">
            <Popconfirm
              title={`确认删除服务器「${server.name}」？`}
              description="关联的加密凭据将被永久销毁；若有运行中任务将阻止删除。"
              okText="删除"
              okButtonProps={{ danger: true }}
              cancelText="取消"
              onConfirm={() => onDelete(server)}
            >
              <Button
                type="text"
                danger
                size="small"
                icon={<DeleteOutlined />}
                style={{ paddingLeft: 0 }}
              >
                删除服务器
              </Button>
            </Popconfirm>
            <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <Button
                type="text"
                icon={<EditOutlined />}
                onClick={() => onEdit(server)}
              >
                编辑
              </Button>
              <Button
                type="text"
                loading={checking}
                icon={<ThunderboltOutlined />}
                onClick={() => onCheck(server)}
              >
                检查连接
              </Button>
              <Button
                type="primary"
                icon={<CodeOutlined />}
                disabled={server.connectionStatus !== "online"}
                onClick={() => onTerminal(server)}
              >
                打开终端
              </Button>
            </div>
          </div>
        </>
      )}
    </Modal>
  );
};
