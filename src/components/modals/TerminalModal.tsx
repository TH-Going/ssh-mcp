import React, { useEffect, useRef, useState } from "react";
import { Button, Modal, Tooltip, message } from "antd";
import { CompressOutlined, ExpandOutlined } from "@ant-design/icons";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import type { Server } from "../../types/models";
import { api } from "../../api/client";

interface Props {
  server: Server | null;
  onClose: () => void;
}

export const TerminalModal: React.FC<Props> = ({ server, onClose }) => {
  const [maximized, setMaximized] = useState(false);
  const [connState, setConnState] = useState<
    "connecting" | "connected" | "closed" | "error"
  >("connecting");
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const sessionIdRef = useRef<string | null>(null);

  useEffect(() => {
    if (!server) return;

    let cancelled = false;
    let unlistenOut: UnlistenFn | null = null;
    let unlistenClosed: UnlistenFn | null = null;
    let resizeObserver: ResizeObserver | null = null;

    setConnState("connecting");
    setErrMsg(null);

    const timer = window.setTimeout(async () => {
      if (cancelled || !containerRef.current) return;

      const term = new Terminal({
        cursorBlink: true,
        fontSize: 12.5,
        lineHeight: 1.45,
        fontFamily:
          '"Cascadia Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace',
        theme: {
          background: "#0e1726",
          foreground: "#d7e3ee",
          cursor: "#7ee2a8",
          selectionBackground: "rgba(56, 139, 253, 0.35)",
        },
      });
      const fitAddon = new FitAddon();
      term.loadAddon(fitAddon);
      term.open(containerRef.current);
      fitAddon.fit();

      termRef.current = term;
      fitRef.current = fitAddon;

      term.onData((data) => {
        const sid = sessionIdRef.current;
        if (sid) {
          void api.terminalInput(sid, data);
        }
      });

      resizeObserver = new ResizeObserver(() => {
        if (!fitRef.current || !termRef.current) return;
        try {
          fitRef.current.fit();
          const sid = sessionIdRef.current;
          if (sid) {
            void api.terminalResize(
              sid,
              termRef.current.cols,
              termRef.current.rows,
            );
          }
        } catch {
          // ignore transient layout errors
        }
      });
      resizeObserver.observe(containerRef.current);

      unlistenOut = await listen<{ sessionId: string; data: string }>(
        "terminal:output",
        (ev) => {
          if (ev.payload.sessionId === sessionIdRef.current) {
            term.write(ev.payload.data);
          }
        },
      );

      unlistenClosed = await listen<{
        sessionId: string;
        reason?: string | null;
      }>("terminal:closed", (ev) => {
        if (ev.payload.sessionId === sessionIdRef.current) {
          setConnState("closed");
          term.writeln(
            `\r\n\x1b[33m[终端连接已关闭${ev.payload.reason ? `：${ev.payload.reason}` : ""}]\x1b[0m`,
          );
          sessionIdRef.current = null;
        }
      });

      try {
        const info = await api.terminalOpen(
          server.id,
          term.cols || 80,
          term.rows || 24,
        );
        if (cancelled) {
          void api.terminalClose(info.sessionId);
          return;
        }
        sessionIdRef.current = info.sessionId;
        setConnState("connected");
        term.focus();
      } catch (e) {
        if (!cancelled) {
          const text = String(e);
          setConnState("error");
          setErrMsg(text);
          term.writeln(`\x1b[31m无法建立终端连接：${text}\x1b[0m`);
          message.error(`终端连接失败: ${text}`);
        }
      }
    }, 60);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      resizeObserver?.disconnect();
      unlistenOut?.();
      unlistenClosed?.();
      const sid = sessionIdRef.current;
      sessionIdRef.current = null;
      if (sid) {
        void api.terminalClose(sid);
      }
      termRef.current?.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [server]);

  useEffect(() => {
    if (!server) {
      setMaximized(false);
      return;
    }
    const id = window.setTimeout(() => {
      if (fitRef.current && termRef.current) {
        fitRef.current.fit();
        if (sessionIdRef.current) {
          void api.terminalResize(
            sessionIdRef.current,
            termRef.current.cols,
            termRef.current.rows,
          );
        }
        termRef.current.focus();
      }
    }, 80);
    return () => window.clearTimeout(id);
  }, [maximized, server]);

  return (
    <Modal
      className={`ncp-modal${maximized ? " modal-max" : ""}`}
      open={!!server}
      onCancel={onClose}
      width={maximized ? "calc(100vw - 24px)" : 760}
      centered
      destroyOnClose
      footer={null}
      title={
        server ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              paddingRight: 84,
            }}
          >
            <span style={{ fontSize: 14, fontWeight: 600 }}>{server.name}</span>
            {connState === "connected" && (
              <span className="st">
                <i className="dot" style={{ background: "#12b76a" }} />
                已连接
              </span>
            )}
            {connState === "connecting" && (
              <span className="st warn">
                <i className="dot" style={{ background: "currentColor" }} />
                连接中...
              </span>
            )}
            {(connState === "closed" || connState === "error") && (
              <span className="st off">
                <i className="dot" style={{ background: "currentColor" }} />
                已断开
              </span>
            )}
          </div>
        ) : (
          ""
        )
      }
    >
      {server && (
        <>
          <Tooltip title={maximized ? "还原窗口" : "放大到全屏"}>
            <button
              type="button"
              className="modal-max-btn"
              aria-label={maximized ? "还原窗口" : "放大到全屏"}
              onClick={() => setMaximized((v) => !v)}
            >
              {maximized ? <CompressOutlined /> : <ExpandOutlined />}
            </button>
          </Tooltip>

          {errMsg && (
            <div className="err-line" style={{ marginTop: 0, marginBottom: 10 }}>
              {errMsg}
            </div>
          )}

          <div
            className="terminal-shell"
            onClick={() => termRef.current?.focus()}
          >
            <div ref={containerRef} className="terminal-host" />
          </div>

          <div className="modal-foot">
            <span />
            <Button type="primary" onClick={onClose}>
              关闭
            </Button>
          </div>
        </>
      )}
    </Modal>
  );
};
