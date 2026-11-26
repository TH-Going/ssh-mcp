import React from "react";
import { Button, Modal, Tag, Tooltip, message } from "antd";
import { CopyOutlined } from "@ant-design/icons";
import type { Approval } from "../../types/models";
import { formatJobTime, formatRemainingExpiry } from "../../api/client";

interface Props {
  approval: Approval | null;
  submitting: boolean;
  onClose: () => void;
  onDecide: (approval: Approval, decision: "approve" | "reject") => void;
}

export const ApprovalModal: React.FC<Props> = ({
  approval,
  submitting,
  onClose,
  onDecide,
}) => {
  const copyDigest = async (val: string) => {
    await navigator.clipboard.writeText(val);
    message.success("防篡改摘要已复制");
  };

  return (
    <Modal
      className="ncp-modal"
      open={!!approval}
      onCancel={onClose}
      width={560}
      centered
      footer={null}
      title={
        approval ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              paddingRight: 28,
            }}
          >
            <span style={{ fontSize: 14, fontWeight: 600 }}>
              {approval.serverName}
            </span>
            <span
              className={`risk${approval.risk === "high" ? "" : " mid"}`}
            >
              <i className="dot" style={{ background: "currentColor" }} />
              {approval.risk === "high" ? "高风险" : "中风险"}
            </span>
            {approval.sudo && (
              <Tag color="volcano" style={{ margin: 0, fontSize: 10.5 }}>
                sudo 提权
              </Tag>
            )}
          </div>
        ) : (
          ""
        )
      }
    >
      {approval && (
        <>
          <div style={{ fontSize: 11.5, color: "#98a0ab" }}>
            {approval.toolLabel} · 由 {approval.requester} 发起 ·{" "}
            {formatJobTime(approval.createdAt)}
          </div>

          <div
            style={{
              marginTop: 12,
              fontSize: 12.5,
              lineHeight: 1.7,
              color: "#5f6673",
            }}
          >
            {approval.callerReason || approval.approvalReason}
          </div>

          {approval.callerReason && (
            <div style={{ marginTop: 4, fontSize: 11.5, color: "#98a0ab" }}>
              策略说明：{approval.approvalReason}
            </div>
          )}

          <pre className="cmd">{approval.commandPreview}</pre>

          <div className="meta2" style={{ marginTop: 18 }}>
            <div>
              <div className="k">目标服务器</div>
              <div className="v">{approval.serverName}</div>
            </div>
            <div>
              <div className="k">有效期</div>
              <div className="v">{formatRemainingExpiry(approval.expiresAt)}</div>
            </div>
            <div>
              <div className="k">命中策略</div>
              <div className="v mono">{approval.matchedPolicy}</div>
            </div>
            <div>
              <div className="k">请求防篡改摘要</div>
              <div
                className="v mono"
                style={{ display: "flex", alignItems: "center", gap: 4 }}
              >
                <Tooltip title={approval.requestDigest}>
                  <span>{approval.requestDigest.slice(0, 22)}…</span>
                </Tooltip>
                <Button
                  type="text"
                  size="small"
                  icon={<CopyOutlined />}
                  style={{ width: 20, height: 20, padding: 0 }}
                  onClick={() => copyDigest(approval.requestDigest)}
                />
              </div>
            </div>
          </div>

          {approval.contentDigest && (
            <div className="cmdline" style={{ marginTop: 12 }}>
              <code>对象/文件锁定哈希: {approval.contentDigest}</code>
              <Button
                type="text"
                size="small"
                icon={<CopyOutlined />}
                onClick={() => copyDigest(approval.contentDigest!)}
              />
            </div>
          )}

          {approval.policySummary && (
            <div style={{ marginTop: 10, fontSize: 11.5, color: "var(--t3)" }}>
              清理策略：{approval.policySummary}
            </div>
          )}

          <div className="modal-foot">
            <span style={{ fontSize: 11, color: "var(--t4)" }}>
              批准后立即进入并发队列执行
            </span>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <Button
                disabled={submitting}
                onClick={() => onDecide(approval, "reject")}
              >
                拒绝
              </Button>
              <Button
                type="primary"
                loading={submitting}
                onClick={() => onDecide(approval, "approve")}
              >
                批准并执行
              </Button>
            </div>
          </div>
        </>
      )}
    </Modal>
  );
};
