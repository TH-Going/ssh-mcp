export type ControlMode = "approval" | "direct";
export type AuthKind = "managed_key" | "password" | "local_key_path";
export type ConnectionStatus =
  | "unknown"
  | "checking"
  | "online"
  | "offline"
  | "host_key_required"
  | "host_key_changed";
export type HostKeyStatus = "unknown" | "trusted" | "changed";

export type SshAuthentication =
  | { kind: "password"; password: string }
  | { kind: "managed_key"; privateKey: string; passphrase?: string }
  | { kind: "local_key_path"; path: string; passphrase?: string };

export interface ServerMetrics {
  cpuPercent: number;
  memoryPercent: number;
  diskPercent: number;
  sampledAt: string;
}

export interface Server {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  environment: string;
  controlMode: ControlMode;
  authKind: AuthKind;
  localKeySource: string | null;
  hasPassphrase: boolean;
  hasSudoPassword: boolean;
  connectionStatus: ConnectionStatus;
  hostKeyStatus: HostKeyStatus;
  hostKeyFingerprint: string | null;
  pendingHostKeyFingerprint: string | null;
  lastCheckedAt: string | null;
  lastLatencyMs: number | null;
  lastError: string | null;
  metrics: ServerMetrics | null;
  revision: number;
  createdAt: string;
  updatedAt: string;
}

export interface ServerCreateRequest {
  name: string;
  host: string;
  port: number;
  username: string;
  environment: string;
  controlMode: ControlMode;
  authentication: SshAuthentication;
  sudoPassword?: string;
}

export interface ServerPatchRequest {
  expectedRevision: number;
  name?: string;
  host?: string;
  port?: number;
  username?: string;
  environment?: string;
  controlMode?: ControlMode;
}

export interface CredentialReplaceRequest {
  expectedRevision: number;
  authentication: SshAuthentication;
  sudoPassword?: string | null;
}

export interface DirectProbeResult {
  server: Server;
  latencyMs: number | null;
}

export type ApprovalRiskLevel = "low" | "medium" | "high";
export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired" | "used";

export interface Approval {
  id: string;
  jobId: string;
  targetId: string;
  serverId: string;
  serverName: string;
  toolLabel: string;
  commandPreview: string;
  requester: string;
  callerReason: string | null;
  operation: Record<string, unknown>;
  contentDigest: string | null;
  requestDigest: string;
  risk: ApprovalRiskLevel;
  riskLevel: ApprovalRiskLevel;
  approvalReason: string;
  matchedPolicy: string;
  policySummary: string | null;
  sudo: boolean;
  status: ApprovalStatus;
  createdAt: string;
  expiresAt: string;
  decidedAt: string | null;
}

export type JobStatus =
  | "queued"
  | "waiting_approval"
  | "running"
  | "succeeded"
  | "partial_failure"
  | "failed"
  | "cancelled";

export type TargetStatus =
  | "queued"
  | "waiting_approval"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled";

export interface JobTarget {
  id: string;
  serverId: string;
  serverName: string;
  status: TargetStatus;
  exitCode: number | null;
  error: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  outputBytes: number;
  outputTruncated: boolean;
  executedCommand: string | null;
  structuredResult: unknown | null;
  approvalId: string | null;
  approvalReason: string | null;
  matchedPolicy: string | null;
  riskLevel: ApprovalRiskLevel | null;
}

export interface Job {
  id: string;
  tool: string;
  toolLabel: string;
  requester: string;
  reason: string | null;
  operation: Record<string, unknown>;
  status: JobStatus;
  targets: JobTarget[];
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  revision: number;
}

export interface JobOutput {
  targetId: string;
  content: string;
  offset: number;
  nextOffset: number | null;
  totalBytes: number;
  expiresAt: string;
  cursor: string;
  nextCursor: string | null;
  truncated: boolean;
}

export interface AppSettings {
  mcpEnabled: boolean;
  mcpRunning: boolean;
  mcpPort: number;
  mcpHttpEndpoint: string;
  mcpStdioCommand: string;
  refreshIntervalSeconds: number;
  failureAlertsEnabled: boolean;
  autostartEnabled: boolean;
  defaultConcurrency: number;
  defaultTimeoutSeconds: number;
  allowReadOnlyShellWithoutApproval: boolean;
  approvalTtlSeconds: number;
  outputRetentionHours: number;
  auditRetentionDays: number;
}

export interface SettingsUpdateRequest {
  mcpEnabled?: boolean;
  refreshIntervalSeconds?: number;
  failureAlertsEnabled?: boolean;
  autostartEnabled?: boolean;
  defaultConcurrency?: number;
  defaultTimeoutSeconds?: number;
  allowReadOnlyShellWithoutApproval?: boolean;
}

export interface BackupPreflightItem {
  sourceId: string;
  name: string;
  host: string;
  port: number;
  conflict: boolean;
  existingId: string | null;
}

export interface BackupPreflight {
  importId: string;
  version: number;
  servers: BackupPreflightItem[];
  expiresAt: string;
}

export type BackupImportAction = "create_new" | "overwrite" | "skip";

export interface BackupApplyDecision {
  sourceId: string;
  action: BackupImportAction;
}

export interface BackupApplyResult {
  created: number;
  overwritten: number;
  skipped: number;
}

export interface DashboardSnapshot {
  servers: Server[];
  approvals: Approval[];
  jobs: Job[];
  settings: AppSettings;
}

export interface TerminalSessionInfo {
  sessionId: string;
  serverId: string;
  serverName: string;
}

export interface SkillsSyncReport {
  skillCount: number;
  syncedTargets: string[];
  filesWritten: number;
}
