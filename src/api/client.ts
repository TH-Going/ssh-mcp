import { invoke } from "@tauri-apps/api/core";
import dayjs from "dayjs";
import type {
  AppSettings,
  Approval,
  BackupApplyDecision,
  BackupApplyResult,
  BackupPreflight,
  CredentialReplaceRequest,
  DashboardSnapshot,
  DirectProbeResult,
  Job,
  JobOutput,
  Server,
  ServerCreateRequest,
  ServerPatchRequest,
  SettingsUpdateRequest,
  SkillsSyncReport,
  TerminalSessionInfo,
  UpdateStatusSnapshot,
} from "../types/models";

export const api = {
  dashboardSnapshot: () => invoke<DashboardSnapshot>("dashboard_snapshot"),

  serverCreate: (req: ServerCreateRequest) =>
    invoke<Server>("server_create", { req }),

  serverPatch: (serverId: string, req: ServerPatchRequest) =>
    invoke<Server>("server_patch", { serverId, req }),

  serverReplaceCredentials: (serverId: string, req: CredentialReplaceRequest) =>
    invoke<Server>("server_replace_credentials", { serverId, req }),

  serverDelete: (serverId: string) =>
    invoke<void>("server_delete", { serverId }),

  serverProbe: (serverId: string) =>
    invoke<DirectProbeResult>("server_probe", { serverId }),

  serverConfirmHostKeyAndConnect: (
    serverId: string,
    fingerprint: string,
    expectedRevision: number,
  ) =>
    invoke<DirectProbeResult>("server_confirm_host_key_and_connect", {
      serverId,
      req: { fingerprint, expectedRevision },
    }),

  approvalDecide: (
    approvalId: string,
    decision: "approve" | "reject",
    expectedRequestDigest: string,
    reason?: string,
  ) =>
    invoke<Approval>("approval_decide", {
      approvalId,
      req: { decision, expectedRequestDigest, reason },
    }),

  jobGet: (jobId: string) => invoke<Job>("job_get", { jobId }),

  jobReadOutput: (
    jobId: string,
    targetId: string,
    offset = 0,
    limitBytes = 65536,
    cursor?: string,
  ) =>
    invoke<JobOutput>("job_read_output", {
      jobId,
      targetId,
      offset,
      limitBytes,
      cursor,
    }),

  jobReadFullOutput: (jobId: string, targetId: string) =>
    invoke<string>("job_read_full_output", { jobId, targetId }),

  jobSaveOutputFile: (jobId: string, targetId: string, destPath: string) =>
    invoke<void>("job_save_output_file", { jobId, targetId, destPath }),

  jobCancel: (jobId: string) => invoke<Job>("job_cancel", { jobId }),

  jobDelete: (jobId: string) => invoke<void>("job_delete", { jobId }),

  jobsClearFinished: () => invoke<number>("jobs_clear_finished"),

  settingsGet: () => invoke<AppSettings>("settings_get"),

  settingsUpdate: (req: SettingsUpdateRequest) =>
    invoke<AppSettings>("settings_update", { req }),

  backupExportToFile: (destPath: string, passphrase: string) =>
    invoke<void>("backup_export_to_file", { destPath, passphrase }),

  backupPreflightFromFile: (srcPath: string, passphrase: string) =>
    invoke<BackupPreflight>("backup_preflight_from_file", {
      srcPath,
      passphrase,
    }),

  backupApplyImport: (importId: string, decisions: BackupApplyDecision[]) =>
    invoke<BackupApplyResult>("backup_apply_import", { importId, decisions }),

  readLocalTextFile: (path: string) =>
    invoke<string>("read_local_text_file", { path }),

  terminalOpen: (serverId: string, cols: number, rows: number) =>
    invoke<TerminalSessionInfo>("terminal_open", { serverId, cols, rows }),

  terminalInput: (sessionId: string, data: string) =>
    invoke<void>("terminal_input", { sessionId, data }),

  terminalResize: (sessionId: string, cols: number, rows: number) =>
    invoke<void>("terminal_resize", { sessionId, cols, rows }),

  terminalClose: (sessionId: string) =>
    invoke<void>("terminal_close", { sessionId }),

  skillsSyncNow: () => invoke<SkillsSyncReport>("skills_sync_now"),

  updaterGetStatus: () => invoke<UpdateStatusSnapshot>("updater_get_status"),

  updaterCheckNow: () => invoke<UpdateStatusSnapshot>("updater_check_now"),

  updaterInstallNow: () => invoke<void>("updater_install_now"),
};

export function formatRelativeTime(iso: string | null): string {
  if (!iso) return "尚未检查";
  const parsed = dayjs(iso);
  if (!parsed.isValid()) return "尚未检查";
  const diffSec = Math.max(0, dayjs().diff(parsed, "second"));
  if (diffSec < 30) return "刚刚";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} 分钟前`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} 小时前`;
  return parsed.format("MM-DD HH:mm");
}

export function formatJobTime(iso: string): string {
  const parsed = dayjs(iso);
  if (!parsed.isValid()) return "";
  if (parsed.isSame(dayjs(), "day")) {
    return parsed.format("HH:mm");
  }
  return parsed.format("MM-DD HH:mm");
}

export function formatRemainingExpiry(expiresIso: string): string {
  const parsed = dayjs(expiresIso);
  if (!parsed.isValid()) return "";
  const diffSec = parsed.diff(dayjs(), "second");
  if (diffSec <= 0) return "已过期";
  if (diffSec < 60) return `${diffSec} 秒后过期`;
  return `${Math.ceil(diffSec / 60)} 分钟后过期`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function authKindLabel(server: Server): string {
  if (server.authKind === "password") return "密码";
  if (server.authKind === "managed_key") return "托管私钥";
  if (
    !server.localKeySource ||
    server.localKeySource.toLowerCase() === "ssh-agent"
  ) {
    return "OpenSSH Agent";
  }
  return "本机密钥";
}
