use serde::{Deserialize, Serialize};

use super::jobs::ToolOperation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Used,
}

impl ApprovalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Used => "used",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "approved" => Self::Approved,
            "rejected" => Self::Rejected,
            "expired" => Self::Expired,
            _ => Self::Used,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRiskLevel {
    Low,
    Medium,
    High,
}

impl ApprovalRiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "low" => Self::Low,
            "medium" => Self::Medium,
            _ => Self::High,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub id: String,
    pub job_id: String,
    pub target_id: String,
    pub server_id: String,
    pub server_name: String,
    pub tool_label: String,
    pub command_preview: String,
    pub requester: String,
    pub caller_reason: Option<String>,
    pub operation: ToolOperation,
    pub content_digest: Option<String>,
    pub request_digest: String,
    pub risk: ApprovalRiskLevel,
    pub risk_level: ApprovalRiskLevel,
    pub approval_reason: String,
    pub matched_policy: String,
    pub policy_summary: Option<String>,
    pub sudo: bool,
    pub status: ApprovalStatus,
    pub created_at: String,
    pub expires_at: String,
    pub decided_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalDecisionRequest {
    pub decision: ApprovalDecision,
    pub expected_request_digest: String,
    #[serde(default)]
    pub reason: Option<String>,
}
