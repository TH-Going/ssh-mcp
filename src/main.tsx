import React from "react";
import ReactDOM from "react-dom/client";
import { ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import { App } from "./App";
import "./styles/console.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: "#1677ff",
          colorText: "#16181d",
          colorTextSecondary: "#5f6673",
          colorTextTertiary: "#98a0ab",
          colorBorder: "#e6e9ed",
          colorBorderSecondary: "#eceef1",
          borderRadius: 6,
          fontFamily:
            '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif',
          controlHeight: 30,
          fontSize: 13,
        },
        components: {
          Button: {
            primaryShadow: "none",
            defaultShadow: "none",
            fontWeight: 400,
          },
          Select: {
            optionSelectedBg: "#f5f6f8",
          },
        },
      }}
    >
      <App />
    </ConfigProvider>
  </React.StrictMode>,
);
