import React, { useEffect, useState } from "react";
import {
  AutoComplete,
  Button,
  Input,
  InputNumber,
  Modal,
  Select,
  Switch,
  message,
} from "antd";
import { FolderOpenOutlined } from "@ant-design/icons";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import type {
  AuthKind,
  ControlMode,
  Server,
  SshAuthentication,
} from "../../types/models";
import { api } from "../../api/client";

interface Props {
  open: boolean;
  server: Server | null;
  onClose: () => void;
  onSaved: (server: Server, isNew: boolean) => void;
}

const ENV_OPTIONS = [
  { value: "生产" },
  { value: "预发" },
  { value: "测试" },
  { value: "开发" },
];

export const ServerFormModal: React.FC<Props> = ({
  open,
  server,
  onClose,
  onSaved,
}) => {
  const editing = !!server;

  const [name, setName] = useState("");
  const [environment, setEnvironment] = useState("生产");
  const [host, setHost] = useState("");
  const [port, setPort] = useState<number>(22);
  const [username, setUsername] = useState("");
  const [controlMode, setControlMode] = useState<ControlMode>("approval");

  const [replaceCreds, setReplaceCreds] = useState(false);
  const [authKind, setAuthKind] = useState<AuthKind>("managed_key");
  const [password, setPassword] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [localKeyPath, setLocalKeyPath] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [sudoPassword, setSudoPassword] = useState("");
  const [clearSudo, setClearSudo] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    if (server) {
      setName(server.name);
      setEnvironment(server.environment || "生产");
      setHost(server.host);
      setPort(server.port);
      setUsername(server.username);
      setControlMode(server.controlMode);
      setReplaceCreds(false);
      setAuthKind(server.authKind);
      setLocalKeyPath(server.localKeySource || "");
    } else {
      setName("");
      setEnvironment("生产");
      setHost("");
      setPort(22);
      setUsername("root");
      setControlMode("approval");
      setReplaceCreds(true);
      setAuthKind("managed_key");
      setLocalKeyPath("");
    }
    setPassword("");
    setPrivateKey("");
    setPassphrase("");
    setSudoPassword("");
    setClearSudo(false);
  }, [open, server]);

  const pickKeyFileForManaged = async () => {
    try {
      const selected = await openFileDialog({
        multiple: false,
        title: "选择 SSH 私钥文件",
      });
      if (typeof selected === "string" && selected) {
        const content = await api.readLocalTextFile(selected);
        setPrivateKey(content);
        message.success("已载入私钥文件内容");
      }
    } catch (e) {
      message.error(String(e));
    }
  };

  const pickLocalKeyPath = async () => {
    try {
      const selected = await openFileDialog({
        multiple: false,
        title: "选择本机 SSH 密钥路径",
      });
      if (typeof selected === "string" && selected) {
        setLocalKeyPath(selected);
      }
    } catch (e) {
      message.error(String(e));
    }
  };

  const buildAuthentication = (): SshAuthentication | null => {
    if (authKind === "password") {
      if (!password) {
        message.warning("请输入 SSH 密码");
        return null;
      }
      return { kind: "password", password };
    }
    if (authKind === "managed_key") {
      if (!privateKey.trim()) {
        message.warning("请粘贴或导入 SSH 私钥");
        return null;
      }
      return {
        kind: "managed_key",
        privateKey: privateKey.trim(),
        ...(passphrase ? { passphrase } : {}),
      };
    }
    return {
      kind: "local_key_path",
      path: localKeyPath.trim() || "ssh-agent",
      ...(passphrase ? { passphrase } : {}),
    };
  };

  const handleSave = async () => {
    if (!name.trim() || !host.trim() || !username.trim()) {
      message.warning("请填写完整的名称、主机地址与 SSH 用户名");
      return;
    }

    setSaving(true);
    try {
      if (!editing) {
        const authentication = buildAuthentication();
        if (!authentication) {
          setSaving(false);
          return;
        }
        const created = await api.serverCreate({
          name: name.trim(),
          host: host.trim(),
          port: port || 22,
          username: username.trim(),
          environment: environment.trim() || "生产",
          controlMode,
          authentication,
          ...(sudoPassword ? { sudoPassword } : {}),
        });
        message.success(`已添加服务器 ${created.name}`);
        onSaved(created, true);
        onClose();
      } else {
        let updated = await api.serverPatch(server.id, {
          expectedRevision: server.revision,
          name: name.trim(),
          host: host.trim(),
          port: port || 22,
          username: username.trim(),
          environment: environment.trim() || "生产",
          controlMode,
        });

        if (replaceCreds) {
          const authentication = buildAuthentication();
          if (!authentication) {
            setSaving(false);
            return;
          }
          updated = await api.serverReplaceCredentials(server.id, {
            expectedRevision: updated.revision,
            authentication,
            sudoPassword: clearSudo
              ? null
              : sudoPassword
                ? sudoPassword
                : undefined,
          });
        }
        message.success(`已保存服务器 ${updated.name}`);
        onSaved(updated, false);
        onClose();
      }
    } catch (e) {
      message.error(String(e));
    } finally {
      setSaving(false);
    }
  };

  const showCredFields = !editing || replaceCreds;

  return (
    <Modal
      className="ncp-modal"
      open={open}
      onCancel={onClose}
      width={500}
      centered
      footer={null}
      destroyOnClose
      title={
        <span style={{ fontSize: 14, fontWeight: 600 }}>
          {editing ? "编辑服务器" : "添加服务器"}
        </span>
      }
    >
      <div className="form-grid-2">
        <div>
          <div className="k" style={{ marginBottom: 5 }}>
            名称
          </div>
          <Input
            placeholder="web-prod-03"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div>
          <div className="k" style={{ marginBottom: 5 }}>
            环境
          </div>
          <AutoComplete
            style={{ width: "100%" }}
            options={ENV_OPTIONS}
            value={environment}
            onChange={setEnvironment}
            placeholder="生产"
          />
        </div>
      </div>

      <div className="form-grid-2">
        <div>
          <div className="k" style={{ marginBottom: 5 }}>
            主机
          </div>
          <Input
            placeholder="10.0.1.14"
            value={host}
            onChange={(e) => setHost(e.target.value)}
          />
        </div>
        <div>
          <div className="k" style={{ marginBottom: 5 }}>
            端口
          </div>
          <InputNumber
            min={1}
            max={65535}
            style={{ width: "100%" }}
            value={port}
            onChange={(v) => setPort(v || 22)}
          />
        </div>
      </div>

      <div className="form-grid-2">
        <div>
          <div className="k" style={{ marginBottom: 5 }}>
            SSH 用户
          </div>
          <Input
            placeholder="deploy"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div>
          <div className="k" style={{ marginBottom: 5 }}>
            控制模式
          </div>
          <Select
            value={controlMode}
            onChange={setControlMode}
            style={{ width: "100%" }}
            options={[
              { value: "approval", label: "需审批（变更操作需人工确认）" },
              { value: "direct", label: "全自动（仅删卷强制审批）" },
            ]}
          />
        </div>
      </div>

      {editing && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "8px 0",
            marginBottom: showCredFields ? 10 : 0,
            borderTop: "1px solid var(--line-soft)",
          }}
        >
          <span style={{ fontSize: 12, color: "var(--t2)" }}>
            替换 SSH 认证或 sudo 凭据
          </span>
          <Switch
            size="small"
            checked={replaceCreds}
            onChange={setReplaceCreds}
          />
        </div>
      )}

      {showCredFields && (
        <>
          <div className="form-field">
            <div className="k" style={{ marginBottom: 5 }}>
              认证方式
            </div>
            <Select
              value={authKind}
              onChange={setAuthKind}
              style={{ width: "100%" }}
              options={[
                {
                  value: "managed_key",
                  label: "托管私钥（Windows DPAPI 加密保存）",
                },
                { value: "password", label: "密码" },
                {
                  value: "local_key_path",
                  label: "本机密钥路径 / Windows OpenSSH Agent",
                },
              ]}
            />
          </div>

          {authKind === "password" && (
            <div className="form-field">
              <div className="k" style={{ marginBottom: 5 }}>
                SSH 密码
              </div>
              <Input.Password
                placeholder="输入远程登录密码"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          )}

          {authKind === "managed_key" && (
            <>
              <div className="form-field">
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    marginBottom: 5,
                  }}
                >
                  <span className="k">OpenSSH 私钥内容</span>
                  <Button
                    type="link"
                    size="small"
                    icon={<FolderOpenOutlined />}
                    style={{ height: 20, padding: 0, fontSize: 11.5 }}
                    onClick={pickKeyFileForManaged}
                  >
                    从文件导入
                  </Button>
                </div>
                <Input.TextArea
                  rows={3}
                  className="mono"
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                  value={privateKey}
                  onChange={(e) => setPrivateKey(e.target.value)}
                />
              </div>
              <div className="form-field">
                <div className="k" style={{ marginBottom: 5 }}>
                  私钥口令（选填）
                </div>
                <Input.Password
                  placeholder="若私钥无加密口令请留空"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                />
              </div>
            </>
          )}

          {authKind === "local_key_path" && (
            <>
              <div className="form-field">
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    marginBottom: 5,
                  }}
                >
                  <span className="k">
                    本机私钥路径（留空或填 ssh-agent 则走系统 OpenSSH Agent）
                  </span>
                  <Button
                    type="link"
                    size="small"
                    icon={<FolderOpenOutlined />}
                    style={{ height: 20, padding: 0, fontSize: 11.5 }}
                    onClick={pickLocalKeyPath}
                  >
                    浏览
                  </Button>
                </div>
                <Input
                  className="mono"
                  placeholder="C:\Users\Administrator\.ssh\id_ed25519 或留空使用 ssh-agent"
                  value={localKeyPath}
                  onChange={(e) => setLocalKeyPath(e.target.value)}
                />
              </div>
              {localKeyPath.trim() &&
                localKeyPath.trim().toLowerCase() !== "ssh-agent" && (
                  <div className="form-field">
                    <div className="k" style={{ marginBottom: 5 }}>
                      私钥口令（选填）
                    </div>
                    <Input.Password
                      placeholder="若私钥无口令请留空"
                      value={passphrase}
                      onChange={(e) => setPassphrase(e.target.value)}
                    />
                  </div>
                )}
            </>
          )}

          <div className="form-field" style={{ marginBottom: 0 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: 5,
              }}
            >
              <span className="k">独立 sudo 密码（选填）</span>
              {editing && server?.hasSudoPassword && (
                <span style={{ fontSize: 11, color: "var(--t3)" }}>
                  清空已有 sudo 密码{" "}
                  <Switch
                    size="small"
                    checked={clearSudo}
                    onChange={setClearSudo}
                  />
                </span>
              )}
            </div>
            <Input.Password
              disabled={clearSudo}
              placeholder={
                editing && server?.hasSudoPassword
                  ? "留空保留现有 sudo 密码，输入则替换"
                  : "留空则默认使用免密 sudo -n"
              }
              value={sudoPassword}
              onChange={(e) => setSudoPassword(e.target.value)}
            />
          </div>
        </>
      )}

      <div className="modal-foot">
        <span />
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={saving} onClick={handleSave}>
            保存
          </Button>
        </div>
      </div>
    </Modal>
  );
};
