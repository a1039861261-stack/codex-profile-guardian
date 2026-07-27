import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Archive,
  ArrowsSplit,
  Database,
  Gauge,
  GearSix,
  Pulse,
  ShieldCheck,
} from "@phosphor-icons/react";
import { FailoverPage } from "../failover/FailoverPage.jsx";
import { createFixtureFailoverClient } from "../failover/fixtureClient.js";
import { scenarioFromLocation, scenarioOrder, scenarios } from "../fixtures/failoverPreview.js";
import { GuardianMark } from "../GuardianMark.jsx";
import "./preview.css";

const navItems = [
  [Gauge, "主页"],
  [Database, "账号"],
  [ShieldCheck, "聊天保护"],
  [ArrowsSplit, "API 容灾"],
  [Archive, "备份"],
  [Pulse, "日志"],
  [GearSix, "设置"],
];

function Mark() {
  return <div className="preview-mark"><GuardianMark /></div>;
}

function Sidebar() {
  return (
    <aside className="preview-sidebar">
      <div className="preview-brand"><Mark /><div><strong>Profile Guardian</strong><span>Codex 安全切换</span></div></div>
      <nav aria-label="主导航">
        {navItems.map(([Icon, label]) => {
          const active = label === "API 容灾";
          return (
            <button
              key={label}
              className={active ? "is-active" : ""}
              type="button"
              aria-current={active ? "page" : undefined}
              aria-label={label}
              disabled={!active}
              title={active ? "当前预览页" : "G6 fixture 暂未接入此页面"}
            >
              <Icon /><span>{label}</span>{active && <small>G6</small>}
            </button>
          );
        })}
      </nav>
      <div className="stable-note"><span className="neutral-dot" /><div><strong>稳定版 v1.6.2</strong><span>容灾版尚未安装</span></div></div>
    </aside>
  );
}

function ScenarioSelect({ selected, onChange }) {
  return (
    <label className="fo-preview-picker">
      <span>预览场景</span>
      <select value={selected} onChange={(event) => onChange(event.target.value)}>
        <optgroup label="运行场景">
          {scenarioOrder.slice(0, 4).map((id) => <option key={id} value={id}>{scenarios[id].label}</option>)}
        </optgroup>
        <optgroup label="界面状态">
          {scenarioOrder.slice(4).map((id) => <option key={id} value={id}>{scenarios[id].label}</option>)}
        </optgroup>
      </select>
    </label>
  );
}

function App() {
  const [scenarioId, setScenarioId] = useState(scenarioFromLocation);
  const [client] = useState(() => createFixtureFailoverClient());
  client.setScenario(scenarioId);

  const selectScenario = (id) => {
    setScenarioId(id);
    window.history.replaceState({}, "", `${window.location.pathname}?scenario=${id}`);
  };

  return (
    <div className="preview-shell">
      <Sidebar />
      <main>
        <FailoverPage
          client={client}
          refreshKey={scenarioId}
          previewControl={<ScenarioSelect selected={scenarioId} onChange={selectScenario} />}
        />
      </main>
    </div>
  );
}

const previewRoot = window.__guardianFailoverPreviewRoot ?? createRoot(document.getElementById("root"));
window.__guardianFailoverPreviewRoot = previewRoot;
previewRoot.render(<React.StrictMode><App /></React.StrictMode>);
