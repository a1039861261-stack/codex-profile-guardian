import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Archive,
  ArrowClockwise,
  ArrowRight,
  ArrowsSplit,
  CaretRight,
  ChatsCircle,
  CheckCircle,
  CircleNotch,
  Cloud,
  Database,
  Desktop,
  DownloadSimple,
  Eye,
  FolderOpen,
  Gauge,
  GearSix,
  HardDrives,
  Key,
  Lightning,
  LockKey,
  MagnifyingGlass,
  Monitor,
  PencilSimple,
  Play,
  PlugsConnected,
  Plus,
  RocketLaunch,
  Scroll,
  ShieldCheck,
  Trash,
  UserSwitch,
  Warning,
  X,
} from "@phosphor-icons/react";
import { api, createFailoverApiClient } from "./api.js";
import { FailoverPage } from "./failover/FailoverPage.jsx";
import { GuardianMark } from "./GuardianMark.jsx";

const navItems = [
  { id: "overview", label: "概览", icon: Gauge },
  { id: "accounts", label: "账号", icon: UserSwitch },
  { id: "protection", label: "聊天保护", icon: ShieldCheck },
  { id: "failover", label: "API 容灾", icon: ArrowsSplit },
  { id: "backups", label: "备份", icon: Archive },
  { id: "logs", label: "日志", icon: Scroll },
  { id: "settings", label: "设置", icon: GearSix },
];

const pageCopy = {
  overview: ["概览", "账号、会话与安全状态一眼看清"],
  accounts: ["账号", "管理官方登录与第三方 API"],
  protection: ["聊天保护", "所有账号共享同一套聊天列表与归档状态"],
  failover: ["API 容灾", "当前线路、故障原因与下一步"],
  backups: ["备份", "每次切换前自动留存配置与元数据回滚点"],
  logs: ["操作日志", "只记录结果，不记录 Token 或 API Key"],
  settings: ["应用设置", "调整安全切换与备份策略"],
  claude: ["Claude Desktop", "由 Guardian 独立管理供应商、凭据与切换"],
};

const failoverApiClient = createFailoverApiClient();

function formatDate(value) {
  if (!value) return "尚未使用";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function quotaForProfile(profile) {
  return profile?.official_quota || profile?.quota || profile?.rate_limits || null;
}

function quotaPlanLabel(profile) {
  const quota = quotaForProfile(profile);
  if (quota?.plan_label) return quota.plan_label;
  const rawPlan = String(
    quota?.plan_type || quota?.planType || profile?.plan_type || profile?.plan || "",
  ).trim();
  const normalized = rawPlan.toLowerCase();
  if (normalized === "plus" || normalized === "chatgpt plus") return "Plus";
  if (normalized === "prolite" || normalized === "pro 5x") return "Pro 5x";
  if (normalized === "pro" || normalized === "chatgpt pro") return "Pro 20x";
  if (!rawPlan || normalized === "unknown" || normalized === "chatgpt") return "等级待同步";
  return rawPlan
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function weeklyQuotaWindow(quota) {
  if (!quota) return null;
  const aliases = ["weekly", "week", "secondary"];
  return aliases.map((name) => quota[name]).find((value) => value && typeof value === "object") || null;
}

function quotaRemaining(windowData) {
  if (!windowData) return null;
  const remaining = windowData.remaining_percent ?? windowData.remainingPercent;
  const used = windowData.used_percent ?? windowData.usedPercent;
  const value = remaining ?? (used == null ? null : 100 - Number(used));
  if (value == null || Number.isNaN(Number(value))) return null;
  return Math.max(0, Math.min(100, Math.round(Number(value))));
}

function formatQuotaReset(value) {
  if (value == null || value === "") return "刷新时间待同步";
  const numeric = typeof value === "number" ? value : Number(value);
  const date = Number.isFinite(numeric)
    ? new Date(numeric < 1_000_000_000_000 ? numeric * 1000 : numeric)
    : new Date(value);
  if (Number.isNaN(date.getTime())) return "刷新时间待同步";
  return `刷新 ${new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date)}`;
}

function quotaTone(remaining) {
  if (remaining == null) return "unknown";
  if (remaining <= 20) return "danger";
  if (remaining <= 50) return "warning";
  return "healthy";
}

function QuotaMeter({ label, windowData }) {
  const remaining = quotaRemaining(windowData);
  const tone = quotaTone(remaining);
  return (
    <div className={`quota-meter quota-summary-card is-${tone}`}>
      <div className="quota-meter-heading">
        <div><span>额度周期</span><strong>{label}</strong></div>
        <span>{remaining == null ? "待同步" : `${remaining}%`}</span>
      </div>
      <div
        className="quota-track"
        role="progressbar"
        aria-label={`${label}剩余额度`}
        aria-valuemin="0"
        aria-valuemax="100"
        aria-valuenow={remaining ?? 0}
      >
        <span style={{ width: `${remaining ?? 0}%` }} />
      </div>
      <small>{formatQuotaReset(windowData?.resets_at ?? windowData?.resetsAt)}</small>
    </div>
  );
}

function ResetCardBalance({ data }) {
  const rawCount = data?.available_count ?? data?.availableCount;
  const count = Number.isFinite(Number(rawCount)) ? Math.max(0, Math.round(Number(rawCount))) : null;
  const expiresAt = data?.next_expires_at ?? data?.nextExpiresAt;
  return (
    <div className="reset-card-balance quota-summary-card">
      <div>
        <div><small>额外额度</small><strong>重置卡</strong></div>
        <span>{count == null ? "待同步" : `${count} 次`}</span>
      </div>
      <small>{expiresAt ? `最近到期 · ${formatQuotaReset(expiresAt).replace(/^刷新\s*/, "")}` : "无可用重置卡时显示 0 次"}</small>
    </div>
  );
}

function OfficialQuota({ profile, showPlan = true }) {
  const quota = quotaForProfile(profile);
  const weekly = weeklyQuotaWindow(quota);
  const resetCards = quota?.reset_cards ?? quota?.resetCards;
  const hasQuota = Boolean(weekly || resetCards);
  return (
    <div className={`official-quota ${hasQuota ? "has-data" : "is-empty"}`}>
      {showPlan && (
        <div className="quota-title-row">
          <span>会员额度</span>
          <Badge tone="blue">{quotaPlanLabel(profile)}</Badge>
        </div>
      )}
      {hasQuota ? (
        <>
          <div className="quota-meter-grid">
            <QuotaMeter label="每周" windowData={weekly} />
            <ResetCardBalance data={resetCards} />
          </div>
          {quota?.fetched_at && <small className="quota-live"><ArrowClockwise weight="bold" /> 自动同步于 {formatDate(quota.fetched_at)}</small>}
          {quota?.stale && <small className="quota-stale">上次同步数据 · 正在等待更新</small>}
        </>
      ) : (
        <div className="quota-empty-copy">
          <Gauge weight="duotone" />
          <span>额度暂未同步</span>
        </div>
      )}
    </div>
  );
}

function AppMark({ small = false }) {
  return (
    <div className={`app-mark ${small ? "is-small" : ""}`} aria-hidden="true">
      <GuardianMark />
    </div>
  );
}

function Button({ children, tone = "neutral", icon: Icon, loading, ...props }) {
  return (
    <button className={`button button-${tone}`} {...props}>
      {loading ? <CircleNotch className="spin" weight="bold" /> : Icon ? <Icon weight="bold" /> : null}
      <span>{children}</span>
    </button>
  );
}

function Badge({ children, tone = "neutral" }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

function modelLabel(profile) {
  if (profile?.model) return profile.model;
  return profile?.type === "api" ? "模型未指定" : "未设置";
}

function apiTestClass(test) {
  if (!test) return "";
  if (test.ok) return "is-good";
  if (apiTestWarning(test)) return "is-caution";
  return "is-bad";
}

function apiTestWarning(test) {
  return Boolean(test?.warning || (!test?.ok && /^HTTP (403|404|405)$/.test(test?.message || "")));
}

function apiTestLabel(test) {
  if (!test) return null;
  const warning = apiTestWarning(test);
  const parts = [test.ok ? "连接正常" : warning ? "接口可达" : "连接失败"];
  if (test.message) {
    parts.push(warning && /^HTTP (403|404|405)$/.test(test.message) ? `模型列表未开放 ${test.message}` : test.message);
  }
  if (test.latency_ms) parts.push(`${test.latency_ms}ms`);
  return parts.join(" · ");
}

function Modal({ title, description, onClose, children, size = "medium" }) {
  useEffect(() => {
    const onKey = (event) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className={`modal modal-${size}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="modal-header">
          <div>
            <h2>{title}</h2>
            {description && <p>{description}</p>}
          </div>
          <button className="icon-button" onClick={onClose} aria-label="关闭">
            <X weight="bold" />
          </button>
        </header>
        {children}
      </section>
    </div>
  );
}

function EmptyState({ icon: Icon = Database, title, detail, action }) {
  return (
    <div className="empty-state">
      <div className="empty-icon"><Icon weight="duotone" /></div>
      <strong>{title}</strong>
      <p>{detail}</p>
      {action}
    </div>
  );
}

function StatCard({ label, value, detail, icon: Icon, tone = "blue" }) {
  return (
    <article className="stat-card">
      <div className={`stat-icon tone-${tone}`}><Icon weight="duotone" /></div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
    </article>
  );
}

function HealthStrip({ status }) {
  const safe = status?.health?.safe;
  const db = status?.database || {};
  return (
    <section className={`health-strip ${safe ? "is-safe" : "is-warning"}`}>
      <div className="health-orb"><ShieldCheck weight="fill" /></div>
      <div className="health-copy">
        <span>聊天保护</span>
        <strong>{safe ? "状态正常，归档标记受保护" : "需要检查本地会话库"}</strong>
        <small>
          数据库 {db.integrity === "ok" ? "完整" : db.integrity || "未知"} · {db.active || 0} 条活动会话 · {db.archived || 0} 条归档会话
        </small>
      </div>
      <Badge tone={safe ? "success" : "warning"}>{safe ? "受保护" : "需处理"}</Badge>
    </section>
  );
}

function ProfileCard({ profile, onSwitch, onSync, onTest, onEdit, onDelete, busy }) {
  const official = profile.type === "official";
  const needsReauth = official && profile.credential_status === "reauth";
  const importedCredential = official && profile.credential_status === "imported";
  return (
    <article className={`profile-card ${official ? "is-official" : "is-api"} ${profile.current ? "is-current" : ""}`}>
      <div className="profile-card-top">
        <div className={`provider-logo ${official ? "official" : "api"}`}>
          {official ? <Cloud weight="duotone" /> : <Key weight="duotone" />}
        </div>
        <div className="profile-heading">
          <div className="profile-name-row">
            <h3>{profile.name}</h3>
            {profile.current && <Badge tone="success">当前</Badge>}
          </div>
          <span>{official ? "Codex 官方账号" : "OpenAI 兼容 API"}</span>
        </div>
        <Badge tone={official ? "blue" : "amber"}>{official ? quotaPlanLabel(profile) : "API"}</Badge>
      </div>
      <dl className="profile-details">
        <div><dt>模型</dt><dd>{modelLabel(profile)}</dd></div>
        <div><dt>{official ? "凭据" : "基础地址"}</dt><dd>{official ? "Windows DPAPI 已加密" : profile.base_url}</dd></div>
        <div><dt>Codex 设置</dt><dd>全账号共用 · 切换时保持不变</dd></div>
        <div><dt>最近使用</dt><dd>{formatDate(profile.last_used_at)}</dd></div>
      </dl>
      {official && <OfficialQuota profile={profile} showPlan={false} />}
      {!official && (
        <div className={`test-result ${apiTestClass(profile.last_test)}`}>
          <PlugsConnected weight="bold" />
          <span title={profile.last_test ? apiTestLabel(profile.last_test) : undefined}>
            {profile.last_test ? apiTestLabel(profile.last_test) : `密钥 ${profile.secret_hint || "已加密保存"}`}
          </span>
        </div>
      )}
      {official && (
        <div className={`test-result credential-result ${needsReauth ? "is-bad" : importedCredential ? "is-caution" : "is-good"}`}>
          {needsReauth ? <Warning weight="fill" /> : importedCredential ? <Warning weight="bold" /> : <CheckCircle weight="fill" />}
          <span>
            {needsReauth
              ? "凭据需要重新登录后更新"
              : importedCredential
                ? "来自 Cockpit，首次使用后建议更新"
                : `最新凭据已同步${profile.credential_updated_at ? ` · ${formatDate(profile.credential_updated_at)}` : ""}`}
          </span>
        </div>
      )}
      <footer className="profile-actions">
        {!official && (
          <Button tone="neutral" icon={Lightning} onClick={() => onTest(profile)} disabled={busy}>测试</Button>
        )}
        {official && profile.current && (
          <Button tone="neutral" icon={ArrowClockwise} onClick={() => onSync(profile)} disabled={busy}>更新登录</Button>
        )}
        <Button
          tone={profile.current ? "neutral" : "primary"}
          icon={profile.current ? CheckCircle : UserSwitch}
          onClick={() => onSwitch(profile)}
          disabled={busy || profile.current}
        >
          {profile.current ? "正在使用" : "安全切换"}
        </Button>
        <button className="icon-button" onClick={() => onEdit(profile)} disabled={busy} aria-label="编辑">
          <PencilSimple weight="bold" />
        </button>
        <button className="icon-button danger" onClick={() => onDelete(profile)} disabled={busy || profile.current} aria-label="删除">
          <Trash weight="bold" />
        </button>
      </footer>
    </article>
  );
}

function Overview({ status, onNavigate, onSwitch, onOpenAdd, busy }) {
  const profiles = status?.profiles || [];
  const current = status?.current_profile;
  const quotaProfile = current?.type === "official"
    ? current
    : profiles.find((profile) => profile.type === "official");
  return (
    <div className="page-stack">
      <div className="stats-grid">
        <StatCard label="账号总数" value={profiles.length} detail="官方账号与第三方 API" icon={UserSwitch} />
        <StatCard label="当前连接" value={current ? current.name : "未设置"} detail={status?.config_provider || "openai"} icon={PlugsConnected} tone="cyan" />
        <StatCard label="活动会话" value={status?.database?.active || 0} detail="左侧列表可见" icon={ChatsCircle} tone="green" />
        <StatCard label="归档会话" value={status?.database?.archived || 0} detail="保持原归档状态" icon={Archive} tone="amber" />
      </div>
      {quotaProfile && (
        <section className="content-panel overview-quota-panel">
          <div className="overview-quota-account quota-summary-card">
            <div className="overview-quota-icon"><Gauge weight="duotone" /></div>
            <div>
              <span>官方账号额度</span>
              <strong>{quotaProfile.name}</strong>
              <small>{quotaProfile.current ? "当前账号" : "首个官方账号"}</small>
            </div>
            <Badge tone="blue">{quotaPlanLabel(quotaProfile)}</Badge>
          </div>
          <OfficialQuota profile={quotaProfile} showPlan={false} />
        </section>
      )}
      <HealthStrip status={status} />
      <section className="content-panel">
        <header className="panel-heading">
          <div>
            <span className="eyebrow">快速切换</span>
            <h2>选择一个账号继续</h2>
          </div>
          <div className="panel-actions">
            <Button icon={Plus} tone="primary" onClick={onOpenAdd}>添加账号</Button>
            <Button icon={ArrowRight} onClick={() => onNavigate("accounts")}>全部账号</Button>
          </div>
        </header>
        {profiles.length ? (
          <div className="quick-profile-grid">
            {profiles.slice(0, 4).map((profile) => (
              <button
                key={profile.id}
                className={`quick-profile ${profile.current ? "is-current" : ""}`}
                onClick={() => !profile.current && onSwitch(profile)}
                disabled={busy || profile.current}
              >
                <span className={`mini-provider ${profile.type}`}>
                  {profile.type === "official" ? <Cloud weight="duotone" /> : <Key weight="duotone" />}
                </span>
                <span className="quick-profile-copy">
                  <strong>{profile.name}</strong>
                  <small>{modelLabel(profile)}</small>
                </span>
                {profile.current ? <Badge tone="success">当前</Badge> : <CaretRight weight="bold" />}
              </button>
            ))}
          </div>
        ) : (
          <EmptyState
            icon={UserSwitch}
            title="还没有账号"
            detail="可导入 Cockpit Tools 中的官方账号，或添加第三方 API。"
            action={<Button tone="primary" icon={Plus} onClick={onOpenAdd}>添加第一个账号</Button>}
          />
        )}
      </section>
      <section className="timeline-panel">
        <div className="timeline-mark"><Database weight="duotone" /></div>
        <div>
          <strong>统一会话库</strong>
          <p>所有账号继续使用同一个 <code>{status?.codex_home || "~/.codex"}</code>。切换时只把会话关联到当前请求线路，不搬走或删除聊天正文。</p>
        </div>
        <Button tone="neutral" icon={Eye} onClick={() => onNavigate("protection")}>查看保护状态</Button>
      </section>
    </div>
  );
}

function Accounts({ status, onOpenAdd, onImport, onSwitch, onSync, onTest, onEdit, onDelete, busy }) {
  const [query, setQuery] = useState("");
  const profiles = (status?.profiles || []).filter((profile) =>
    `${profile.name} ${modelLabel(profile)} ${profile.base_url || ""}`.toLowerCase().includes(query.toLowerCase()),
  );
  return (
    <div className="page-stack">
      <section className="toolbar-panel">
        <label className="search-field">
          <MagnifyingGlass weight="bold" />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索账号、模型或地址" />
        </label>
        <div className="toolbar-spacer" />
        <Button icon={ArrowClockwise} onClick={onImport} disabled={busy}>导入 Cockpit</Button>
        <Button tone="primary" icon={Plus} onClick={onOpenAdd}>添加账号</Button>
      </section>
      <div className="section-label">
        <span>全部账号</span>
        <Badge>{profiles.length}</Badge>
      </div>
      {profiles.length ? (
        <div className="profile-grid">
          {profiles.map((profile) => (
            <ProfileCard key={profile.id} profile={profile} onSwitch={onSwitch} onSync={onSync} onTest={onTest} onEdit={onEdit} onDelete={onDelete} busy={busy} />
          ))}
        </div>
      ) : (
        <section className="content-panel">
          <EmptyState icon={MagnifyingGlass} title="没有匹配的账号" detail="换个关键词，或添加新的账号配置。" />
        </section>
      )}
    </div>
  );
}

function claudeStateCopy(status) {
  const provider = status?.current_profile;
  if (status?.state === "ready") {
    return {
      tone: "success",
      eyebrow: "连接正常",
      title: "Claude API 由 Guardian 独立管理",
      detail: "Claude Desktop 正在直连 Guardian 保存的 Anthropic 兼容供应商，不依赖 CC Switch 运行。",
      action: "无需处理",
    };
  }
  if (status?.state === "external") {
    return {
      tone: "warning",
      eyebrow: "外部配置",
      title: "Claude 仍在使用非 Guardian 3P 配置",
      detail: status?.migration?.available
        ? "可在卸载 CC Switch 前一次性迁移当前 Anthropic 供应商，之后由 Guardian 独立保存和切换。"
        : "请添加 Guardian Claude 供应商，或恢复 Claude 官方登录模式。",
      action: status?.migration?.available ? "迁移当前供应商" : "添加供应商",
    };
  }
  if (status?.state === "official") {
    return {
      tone: "neutral",
      eyebrow: "官方模式",
      title: "Claude 官方登录正在使用",
      detail: "Claude Desktop 当前未启用第三方 3P profile。",
      action: "无需处理",
    };
  }
  return {
    tone: "neutral",
    eyebrow: "尚未接入",
    title: "未检测到 Claude Desktop 配置",
    detail: "添加一个 Anthropic Messages API 供应商，Guardian 会生成 Claude Desktop 3P 配置。",
    action: "添加供应商",
  };
}

function ClaudeDesktopPage({ status, loading, busy, onRefresh, onAdd, onEdit, onApply, onDelete, onRestoreOfficial, onImportCc, onRestart }) {
  if (loading && !status) {
    return (
      <div className="claude-page-state" role="status">
        <CircleNotch className="spin" weight="bold" />
        <strong>正在读取 Claude Desktop 状态</strong>
      </div>
    );
  }

  const state = claudeStateCopy(status);
  const provider = status?.current_profile;
  const gateway = status?.gateway;
  const models = status?.models || [];
  const profiles = status?.profiles || [];
  return (
    <div className="claude-page">
      <section className={`claude-summary is-${state.tone}`}>
        <div className="claude-summary-main">
          <div className="claude-product-mark"><Monitor weight="duotone" /></div>
          <div>
            <span className="claude-eyebrow">{state.eyebrow}</span>
            <h2>{state.title}</h2>
            <p>{state.detail}</p>
          </div>
        </div>
        <div className="claude-summary-actions">
          <Button icon={ArrowClockwise} onClick={onRefresh} loading={loading} disabled={busy || loading}>刷新</Button>
          <Button tone="primary" icon={Plus} onClick={onAdd} disabled={busy}>添加供应商</Button>
        </div>

        <dl className="claude-facts">
          <div>
            <dt>当前供应商</dt>
            <dd>{status?.deployment_mode === "official" ? "Claude 官方登录" : provider?.name || "未识别"}</dd>
          </div>
          <div>
            <dt>连接方式</dt>
            <dd>{status?.deployment_mode === "official" ? "官方直连" : status?.config_owner === "guardian" ? "Guardian 第三方 API 直连" : "外部 3P 配置"}</dd>
          </div>
          <div>
            <dt>CC Switch</dt>
            <dd>不作为运行依赖</dd>
          </div>
          <div>
            <dt>现在要做</dt>
            <dd>{state.action}</dd>
          </div>
        </dl>
      </section>

      <section className="claude-control-row" aria-label="Claude Desktop 操作">
        <div>
          <strong>配置所有者</strong>
          <span>{status?.config_owner === "guardian" ? "Guardian" : status?.config_owner === "official" ? "Claude 官方" : "外部配置"} · Guardian 凭据使用 DPAPI 保存</span>
        </div>
        <div className="claude-control-actions">
          <Button onClick={onRestoreOfficial} disabled={busy || status?.state === "official"}>恢复官方模式</Button>
          <Button icon={ArrowClockwise} onClick={onRestart} disabled={busy || !status?.detected}>重启 Claude Desktop</Button>
        </div>
      </section>

      {status?.migration?.available && (
        <section className={`claude-migration ${status.migration.compatible ? "is-ready" : "is-blocked"}`}>
          <div>
            <strong>卸载 CC Switch 前的一次性迁移</strong>
            <span>{status.migration.compatible
              ? `可迁移：${status.migration.provider_name}。迁移后 Key 进入 Guardian DPAPI，日常运行不再读取 CC Switch。`
              : "当前供应商需要 CC Switch 做协议转换，不能安全直连迁移；请在 Guardian 手动添加原生 Anthropic 接口。"}</span>
          </div>
          <Button tone="primary" icon={ArrowClockwise} onClick={onImportCc} disabled={busy || !status.migration.compatible}>一次性迁移</Button>
        </section>
      )}

      <section className="claude-providers" aria-labelledby="claude-providers-title">
        <header>
          <div><span>独立配置</span><h3 id="claude-providers-title">Guardian Claude 供应商</h3></div>
          <Badge tone={profiles.length ? "blue" : "neutral"}>{profiles.length} 个</Badge>
        </header>
        {profiles.length ? (
          <div className="claude-provider-list">
            {profiles.map((item) => (
              <article key={item.id} className={`claude-provider-card ${item.current ? "is-current" : ""}`}>
                <div className="claude-provider-main">
                  <div className="claude-route-icon"><Cloud weight="duotone" /></div>
                  <div><strong>{item.name}</strong><code>{item.base_url}</code><span>{item.models?.length || 0} 个模型 · Key ••••{item.secret_hint || ""}</span></div>
                </div>
                <div className="claude-provider-actions">
                  {item.current ? <Badge tone="blue">当前</Badge> : <Button tone="primary" onClick={() => onApply(item)} disabled={busy}>启用</Button>}
                  <Button icon={PencilSimple} onClick={() => onEdit(item)} disabled={busy}>编辑</Button>
                  <Button icon={Trash} onClick={() => onDelete(item)} disabled={busy || item.current}>删除</Button>
                </div>
              </article>
            ))}
          </div>
        ) : (
          <div className="claude-routes-empty"><span>还没有 Guardian 管理的 Claude 供应商。</span><Button tone="primary" icon={Plus} onClick={onAdd}>添加第一个</Button></div>
        )}
      </section>

      <section className="claude-routes" aria-labelledby="claude-routes-title">
        <header>
          <div>
            <span>模型角色</span>
            <h3 id="claude-routes-title">当前发布的模型</h3>
          </div>
          <Badge tone={models.length ? "blue" : "neutral"}>{models.length || 0} 个</Badge>
        </header>
        {models.length ? (
          <div className="claude-route-list">
            {models.map((model) => (
              <article key={model.name} className="claude-route-row">
                <div className="claude-route-icon"><Cloud weight="duotone" /></div>
                <div>
                  <strong>{model.label || model.name}</strong>
                  <code>{model.name}</code>
                </div>
                <Badge tone={model.supports_1m ? "success" : "neutral"}>{model.supports_1m ? "1M" : "直连"}</Badge>
              </article>
            ))}
          </div>
        ) : (
          <div className="claude-routes-empty">
            <span>未手动指定模型时，Claude Desktop 会读取供应商的模型列表。</span>
          </div>
        )}
      </section>

      <details className="claude-diagnostics">
        <summary>连接详情</summary>
        <dl>
          <div><dt>部署模式</dt><dd>{status?.deployment_mode || "unknown"}</dd></div>
          <div><dt>接口地址</dt><dd><code>{gateway?.address || provider?.base_url || "不适用"}</code></dd></div>
          <div><dt>凭据状态</dt><dd>{status?.credential_state === "managed_by_guardian" ? "Guardian DPAPI 加密保存" : "未配置"}</dd></div>
          <div><dt>配置更新时间</dt><dd>{formatDate(status?.updated_at)}</dd></div>
        </dl>
      </details>
    </div>
  );
}

function ClaudeProviderModal({ profile, onClose, onSaved, notify }) {
  const editing = Boolean(profile);
  const [form, setForm] = useState({
    name: profile?.name || "",
    base_url: profile?.base_url || "",
    api_key: "",
    models: (profile?.models || []).map((item) => item.name).join("\n"),
  });
  const [saving, setSaving] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      const payload = {
        name: form.name,
        base_url: form.base_url,
        api_key: form.api_key,
        models: form.models.split(/[\n,]/).map((item) => item.trim()).filter(Boolean),
      };
      const path = editing
        ? `/api/claude-desktop/providers/${profile.id}/edit`
        : "/api/claude-desktop/providers";
      await api(path, { method: "POST", body: JSON.stringify(payload) });
      notify(editing ? "Claude 供应商已更新" : "Claude 供应商已保存", "success");
      await onSaved();
      onClose();
    } catch (error) {
      notify(error.message, "error");
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal title={editing ? `编辑 ${profile.name}` : "添加 Claude 供应商"} description="仅支持原生 Anthropic Messages API；Guardian 不依赖 CC Switch 本地路由。" onClose={onClose}>
      <form className="modal-form" onSubmit={submit}>
        <label><span>供应商名称</span><input required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></label>
        <label><span>Anthropic 接口地址</span><input required value={form.base_url} onChange={(event) => setForm({ ...form, base_url: event.target.value })} placeholder="https://api.example.com" /></label>
        <label><span>API Key{editing ? "（留空不修改）" : ""}</span><input type="password" required={!editing} autoComplete="off" value={form.api_key} onChange={(event) => setForm({ ...form, api_key: event.target.value })} /></label>
        <label><span>模型 ID（可选，每行一个）</span><textarea rows="4" value={form.models} onChange={(event) => setForm({ ...form, models: event.target.value })} placeholder={"claude-sonnet-5\nclaude-opus-4-8"} /><small className="form-help">只能填写供应商真实接受的 claude-* 模型；这里不做协议转换或虚假映射。</small></label>
        <div className="info-callout"><LockKey weight="duotone" /><div><strong>凭据边界</strong><p>Guardian 自己的副本由 Windows DPAPI 加密；启用时 Claude Desktop 3P profile 按客户端要求包含运行凭据，日志和界面永不显示完整 Key。</p></div></div>
        <footer className="modal-footer"><Button type="button" onClick={onClose}>取消</Button><Button type="submit" tone="primary" icon={CheckCircle} loading={saving} disabled={saving}>保存</Button></footer>
      </form>
    </Modal>
  );
}

function Protection({ status, onRepair, busy }) {
  const database = status?.database || {};
  const providerEntries = Object.entries(database.providers || {});
  return (
    <div className="page-stack">
      <HealthStrip status={status} />
      <div className="protection-grid">
        <section className="content-panel protection-card">
          <header>
            <div className="large-icon green"><Database weight="duotone" /></div>
            <div><span>数据库</span><h2>{database.integrity === "ok" ? "完整性正常" : "需要修复"}</h2></div>
          </header>
          <div className="protection-metrics">
            <div><span>总会话</span><strong>{database.total || 0}</strong></div>
            <div><span>活动</span><strong>{database.active || 0}</strong></div>
            <div><span>归档</span><strong>{database.archived || 0}</strong></div>
          </div>
        </section>
        <section className="content-panel protection-card">
          <header>
            <div className="large-icon blue"><PlugsConnected weight="duotone" /></div>
            <div><span>共享历史线路</span><h2>{providerEntries.length <= 1 ? "聊天列表已统一" : "需要同步"}</h2></div>
          </header>
          <div className="provider-list">
            {providerEntries.map(([provider, count]) => (
              <div key={provider}><code>{provider}</code><Badge tone={provider === status?.config_provider ? "success" : "warning"}>{count} 条</Badge></div>
            ))}
          </div>
        </section>
      </div>
      <section className="content-panel repair-panel">
        <div className="repair-visual"><ShieldCheck weight="duotone" /></div>
        <div className="repair-copy">
          <span className="eyebrow">共享历史修复</span>
          <h2>保持聊天列表固定，只切换账号线路</h2>
          <p>关闭 Codex 后，把全部既有会话安全关联到当前官号或 API。聊天正文、顺序和归档状态不变，切换后仍显示同一套完整记录。</p>
          <div className="safety-checks">
            <span><CheckCircle weight="fill" /> 所有账号显示同一套完整聊天记录</span>
            <span><CheckCircle weight="fill" /> 保持 archived 标记</span>
            <span><CheckCircle weight="fill" /> 自动关闭并重新打开 Codex</span>
          </div>
        </div>
        <Button tone="primary" icon={ArrowClockwise} loading={busy} onClick={onRepair} disabled={busy}>修复共享历史</Button>
      </section>
    </div>
  );
}

function Backups({ backups, onRestore, onOpen, busy }) {
  return (
    <div className="page-stack">
      <section className="toolbar-panel">
        <div className="toolbar-title"><HardDrives weight="duotone" /><div><strong>本地回滚点</strong><span>自动保存在应用数据目录</span></div></div>
        <div className="toolbar-spacer" />
        <Button icon={FolderOpen} onClick={onOpen}>打开备份目录</Button>
      </section>
      <section className="content-panel table-panel">
        {backups.length ? (
          <div className="backup-list">
            {backups.map((backup) => (
              <article className="backup-row" key={backup.name}>
                <div className="backup-icon"><Archive weight="duotone" /></div>
                <div className="backup-main">
                  <strong>{backup.reason === "before-switch" ? "切换前自动备份" : backup.reason === "before-repair" ? "修复前自动备份" : "安全回滚备份"}</strong>
                  <span>{formatDate(backup.created_at)} · {backup.rollout_file_count || 0} 个会话文件</span>
                </div>
                <div className="backup-counts"><span>{backup.active_count || 0} 活动</span><span>{backup.archived_count || 0} 归档</span></div>
                <Button icon={ArrowClockwise} onClick={() => onRestore(backup)} disabled={busy}>恢复</Button>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState icon={Archive} title="还没有备份" detail="第一次切换账号或修复会话时会自动创建。" />
        )}
      </section>
    </div>
  );
}

function Logs({ logs, onRefresh, onClear, busy }) {
  return (
    <div className="page-stack">
      <section className="toolbar-panel">
        <div className="toolbar-title"><Scroll weight="duotone" /><div><strong>安全审计日志</strong><span>API Key 与 Token 永不写入日志</span></div></div>
        <div className="toolbar-spacer" />
        <Button icon={ArrowClockwise} onClick={onRefresh}>刷新</Button>
        <Button icon={Trash} onClick={onClear} disabled={busy}>清空</Button>
      </section>
      <section className="content-panel table-panel">
        {logs.length ? (
          <div className="log-list">
            {logs.map((event, index) => (
              <article className="log-row" key={`${event.timestamp}-${index}`}>
                <div className={`log-state ${event.status}`}>
                  {event.status === "success" ? <CheckCircle weight="fill" /> : <Warning weight="fill" />}
                </div>
                <div className="log-copy"><strong>{event.message}</strong><span>{event.action}</span></div>
                <time>{formatDate(event.timestamp)}</time>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState icon={Scroll} title="暂无操作记录" detail="账号添加、测试、切换、修复和恢复操作会显示在这里。" />
        )}
      </section>
    </div>
  );
}

function Toggle({ checked, onChange, label, detail }) {
  return (
    <label className="setting-row">
      <div><strong>{label}</strong><span>{detail}</span></div>
      <button type="button" className={`toggle ${checked ? "is-on" : ""}`} onClick={() => onChange(!checked)} aria-pressed={checked}>
        <span />
      </button>
    </label>
  );
}

function updateStateCopy(update) {
  const states = {
    idle: ["尚未检查", "打开应用后会自动检查正式版本"],
    checking: ["正在检查", "正在读取 GitHub 正式 Release"],
    up_to_date: ["已是最新版", `当前 v${update?.current_version || "-"}`],
    available: ["发现新版本", `v${update?.latest_version || "-"} 可下载`],
    downloaded: ["更新已就绪", `v${update?.latest_version || "-"} 已完成 SHA-256 校验`],
    installing: ["安装程序已启动", "安装器将负责升级和失败回滚"],
    error: ["暂时无法检查", update?.error_code === "update_repository_unavailable" ? "当前仓库为私有，匿名客户端无法读取 Release" : "网络、限流或 Release 资料暂不可用"],
  };
  return states[update?.state] || states.idle;
}

function Settings({ status, onSave, onOpen, onRemoteSync, onUpdateCheck, onUpdateDownload, onUpdateInstall, busy }) {
  const [settings, setSettings] = useState(status?.settings || {});
  useEffect(() => setSettings(status?.settings || {}), [status?.settings]);
  const setSetting = (key, value) => setSettings((current) => ({ ...current, [key]: value }));
  const currentType = status?.current_profile?.type;
  const remoteSync = status?.remote?.last_sync;
  const remoteReady =
    (status?.remote?.host_count || 0) > 0 &&
    ((currentType === "official" && settings.sync_ssh_official) ||
      (currentType === "api" && settings.sync_ssh_api));
  const updateStatus = status?.update || {};
  const [updateTitle, updateDetail] = updateStateCopy(updateStatus);
  return (
    <div className="page-stack settings-layout">
      <section className="content-panel settings-panel">
        <header className="settings-heading"><span className="section-accent" /><div><h2>切换策略</h2><p>控制 Codex 关闭与重启行为</p></div></header>
        <Toggle checked={settings.auto_close_codex ?? true} onChange={(value) => setSetting("auto_close_codex", value)} label="切换前自动关闭 Codex" detail="先正常退出；超时后只清理 Codex 自身的残留进程" />
        <Toggle checked={settings.auto_launch_codex ?? true} onChange={(value) => setSetting("auto_launch_codex", value)} label="切换成功后自动启动 Codex" detail="优先使用 Microsoft Store 系统入口" />
      </section>
      <section className="content-panel settings-panel update-panel">
        <header className="settings-heading"><span className="section-accent" /><div><h2>软件更新</h2><p>只接收 GitHub 正式 Release，不跟随普通提交、草稿或预发布版本</p></div></header>
        <Toggle
          checked={settings.auto_update_enabled ?? true}
          onChange={(value) => setSetting("auto_update_enabled", value)}
          label="自动检查并预下载更新"
          detail="启动后检查一次，运行期间每 30 分钟检查；安装前仍需你明确确认"
        />
        <div className={`update-status is-${updateStatus.state || "idle"}`}>
          <div className="update-version-mark"><ArrowClockwise weight="bold" /></div>
          <div><strong>{updateTitle}</strong><span>{updateDetail}</span><small>{updateStatus.checked_at ? `上次检查 ${formatDate(updateStatus.checked_at)}` : updateStatus.repository}</small></div>
          <Badge tone={updateStatus.state === "error" ? "amber" : "blue"}>v{updateStatus.current_version || status?.app?.version}</Badge>
        </div>
        <div className="settings-footer settings-footer-split update-actions">
          <span>来源：{updateStatus.repository || "a1039861261-stack/codex-profile-guardian"}</span>
          <div>
            <Button icon={ArrowClockwise} onClick={onUpdateCheck} disabled={busy}>检查</Button>
            {updateStatus.state === "available" && <Button tone="primary" icon={DownloadSimple} onClick={onUpdateDownload} disabled={busy}>下载并校验</Button>}
            {(updateStatus.state === "downloaded" || updateStatus.state === "installing") && <Button tone="primary" icon={RocketLaunch} onClick={onUpdateInstall} disabled={busy || updateStatus.state === "installing"}>安装更新</Button>}
          </div>
        </div>
      </section>
      <section className="content-panel settings-panel">
        <header className="settings-heading"><span className="section-accent" /><div><h2>SSH 远程 Codex</h2><p>让远程项目跟随当前账号与额度来源</p></div></header>
        <Toggle
          checked={settings.sync_ssh_official ?? false}
          onChange={(value) => setSetting("sync_ssh_official", value)}
          label={`同步已登记的 SSH 主机（${status?.remote?.host_count || 0}）`}
          detail="切换官方账号时先在远端备份，再同步最新登录和跨平台设置；Windows 路径、MCP 与项目表不会复制"
        />
        <Toggle
          checked={settings.sync_ssh_api ?? false}
          onChange={(value) => setSetting("sync_ssh_api", value)}
          label="第三方 API 也同步到 SSH 项目"
          detail="切换 API 时写入远端 provider，并把 API Key 存到远端 ~/.codex/guardian-api-profiles（600 权限）"
        />
        {settings.sync_ssh_api && (
          <div className="settings-warning">
            <Warning weight="fill" />
            <span>开启后，SSH 主机上的 Codex 会走当前第三方 API 额度；这会把该 API Key 存在远端当前 Linux 用户目录，不会写入日志。</span>
          </div>
        )}
        {remoteSync?.stale && (
          <div className="settings-warning">
            <Warning weight="fill" />
            <span>本机账号配置已更新，之前的 SSH 成功状态已经过期。请重新确认同步。</span>
          </div>
        )}
        <div className="settings-footer settings-footer-split">
          <span>当前账号：{status?.current_profile?.name || "未设置"}</span>
          <Button tone="primary" icon={Cloud} loading={busy} disabled={busy || !remoteReady} onClick={() => onRemoteSync(settings)}>
            立即同步当前账号到 SSH
          </Button>
        </div>
      </section>
      <section className="content-panel settings-panel">
        <header className="settings-heading"><span className="section-accent" /><div><h2>数据管理</h2><p>备份数量与存储目录</p></div></header>
        <label className="number-setting">
          <div><strong>最多保留备份</strong><span>最少 3 个，最多 50 个</span></div>
          <input type="number" min="3" max="50" value={settings.backup_limit || 10} onChange={(event) => setSetting("backup_limit", Number(event.target.value))} />
        </label>
        <div className="path-setting">
          <div><strong>Codex 数据目录</strong><code>{status?.codex_home}</code></div>
          <Button icon={FolderOpen} onClick={() => onOpen("codex")}>打开</Button>
        </div>
        <div className="settings-footer"><Button tone="primary" icon={CheckCircle} loading={busy} onClick={() => onSave(settings)} disabled={busy}>保存设置</Button></div>
      </section>
      <section className="about-card">
        <AppMark small />
        <div><strong>Codex Profile Guardian</strong><span>v{status?.app?.version || "1.7.0"} · 兼容新版 ChatGPT/Codex App</span></div>
        <Badge tone="success">本机模式</Badge>
      </section>
    </div>
  );
}

function AddProfileModal({ onClose, onCreated, notify }) {
  const [type, setType] = useState("official");
  const [loading, setLoading] = useState(false);
  const [official, setOfficial] = useState({ name: "", model: "" });
  const [thirdParty, setThirdParty] = useState({ name: "", base_url: "", api_key: "", model: "" });
  const submit = async (event) => {
    event.preventDefault();
    setLoading(true);
    try {
      if (type === "official") {
        await api("/api/profiles/official/capture", { method: "POST", body: JSON.stringify(official) });
        notify("已加密保存当前官方登录", "success");
      } else {
        await api("/api/profiles/api", { method: "POST", body: JSON.stringify(thirdParty) });
        notify("第三方 API 已保存", "success");
      }
      await onCreated();
      onClose();
    } catch (error) {
      notify(error.message, "error");
    } finally {
      setLoading(false);
    }
  };
  return (
    <Modal title="添加 Codex 账号" description="凭据会使用当前 Windows 用户的 DPAPI 加密" onClose={onClose}>
      <div className="segmented-control">
        <button className={type === "official" ? "is-active" : ""} onClick={() => setType("official")}><Cloud weight="duotone" /> 官方账号</button>
        <button className={type === "api" ? "is-active" : ""} onClick={() => setType("api")}><Key weight="duotone" /> 第三方 API</button>
      </div>
      <form className="modal-form" onSubmit={submit}>
        {type === "official" ? (
          <>
            <div className="info-callout"><LockKey weight="duotone" /><div><strong>保存当前登录</strong><p>读取现有 <code>auth.json</code>，加密后保存。不会显示或上传 Token。</p></div></div>
            <label><span>账号名称</span><input required value={official.name} onChange={(event) => setOfficial({ ...official, name: event.target.value })} placeholder="例如：个人 Plus" /></label>
            <label>
              <span>默认模型（可选）</span>
              <input value={official.model} onChange={(event) => setOfficial({ ...official, model: event.target.value })} placeholder="留空 = 使用 Codex 当前或可选模型" />
              <small className="form-help">留空时只切换官方登录，不锁定模型。</small>
            </label>
          </>
        ) : (
          <>
            <label><span>配置名称</span><input required value={thirdParty.name} onChange={(event) => setThirdParty({ ...thirdParty, name: event.target.value })} placeholder="例如：APIKEY.FUN" /></label>
            <label><span>基础地址</span><input required value={thirdParty.base_url} onChange={(event) => setThirdParty({ ...thirdParty, base_url: event.target.value })} placeholder="https://example.com/v1" /></label>
            <label><span>API Key</span><input required type="password" autoComplete="off" value={thirdParty.api_key} onChange={(event) => setThirdParty({ ...thirdParty, api_key: event.target.value })} placeholder="sk-..." /></label>
            <label>
              <span>模型 ID（可选）</span>
              <input value={thirdParty.model} onChange={(event) => setThirdParty({ ...thirdParty, model: event.target.value })} placeholder="留空 = 不指定模型" />
              <small className="form-help">留空时只切换 API 线路，Codex 可继续从该接口返回的模型列表里选择。</small>
            </label>
          </>
        )}
        <footer className="modal-footer"><Button type="button" onClick={onClose}>取消</Button><Button type="submit" tone="primary" icon={Plus} loading={loading} disabled={loading}>保存账号</Button></footer>
      </form>
    </Modal>
  );
}

function EditProfileModal({ profile, onClose, onSaved, onRemoteSyncRequired, notify }) {
  const official = profile.type === "official";
  const [loading, setLoading] = useState(false);
  const [officialForm, setOfficialForm] = useState({
    name: profile.name || "",
    model: profile.model || "",
  });
  const [apiForm, setApiForm] = useState({
    name: profile.name || "",
    base_url: profile.base_url || "",
    api_key: "",
    model: profile.model || "",
  });
  const submit = async (event) => {
    event.preventDefault();
    setLoading(true);
    try {
      const result = await api(`/api/profiles/${profile.id}/edit`, {
        method: "POST",
        body: JSON.stringify(official ? officialForm : apiForm),
      });
      const updatedName = official ? officialForm.name : apiForm.name;
      notify(
        result?.remote_sync_required
          ? `本机已更新 ${updatedName}，SSH 尚待同步`
          : `已更新 ${updatedName}`,
        result?.remote_sync_required ? "warning" : "success",
      );
      await onSaved();
      onClose();
      if (result?.remote_sync_required) {
        onRemoteSyncRequired?.(result.profile, result.remote_host_count || 0);
      }
    } catch (error) {
      notify(error.message, "error");
    } finally {
      setLoading(false);
    }
  };
  return (
    <Modal
      title={`编辑 ${profile.name}`}
      description={official ? "可编辑显示名称；默认模型留空表示不锁定。登录凭据请用“更新登录”。" : "API Key 留空表示不修改旧密钥；模型 ID 可继续留空。"}
      onClose={onClose}
    >
      <form className="modal-form" onSubmit={submit}>
        {official ? (
          <>
            <div className="info-callout"><LockKey weight="duotone" /><div><strong>官方账号凭据不在这里手填</strong><p>如果 token 变化，请先在 Codex 重新登录，再回到账号卡片点击“更新登录”。</p></div></div>
            <label><span>账号名称</span><input required value={officialForm.name} onChange={(event) => setOfficialForm({ ...officialForm, name: event.target.value })} /></label>
            <label>
              <span>默认模型（可选）</span>
              <input value={officialForm.model} onChange={(event) => setOfficialForm({ ...officialForm, model: event.target.value })} placeholder="留空 = 使用 Codex 当前或可选模型" />
              <small className="form-help">留空时切换账号不会写入固定模型。</small>
            </label>
          </>
        ) : (
          <>
            <label><span>配置名称</span><input required value={apiForm.name} onChange={(event) => setApiForm({ ...apiForm, name: event.target.value })} /></label>
            <label><span>基础地址</span><input required value={apiForm.base_url} onChange={(event) => setApiForm({ ...apiForm, base_url: event.target.value })} placeholder="https://example.com/v1" /></label>
            <label>
              <span>API Key（可选更新）</span>
              <input type="password" autoComplete="off" value={apiForm.api_key} onChange={(event) => setApiForm({ ...apiForm, api_key: event.target.value })} placeholder="留空 = 不修改当前密钥" />
              <small className="form-help">只有填写新 Key 时才会覆盖旧 Key；旧 Key 不会显示，也不会写入日志。</small>
            </label>
            <label>
              <span>模型 ID（可选）</span>
              <input value={apiForm.model} onChange={(event) => setApiForm({ ...apiForm, model: event.target.value })} placeholder="留空 = 不指定模型" />
              <small className="form-help">留空时只切换 API 线路，Codex 可继续从该接口返回的模型列表里选择。</small>
            </label>
          </>
        )}
        <footer className="modal-footer">
          <Button type="button" onClick={onClose}>取消</Button>
          <Button type="submit" tone="primary" icon={PencilSimple} loading={loading} disabled={loading}>保存修改</Button>
        </footer>
      </form>
    </Modal>
  );
}

function ConfirmModal({ action, status, onClose, onConfirm, busy }) {
  const profile = action?.profile;
  const backup = action?.backup;
  const isRestore = action?.type === "restore";
  const isDelete = action?.type === "delete";
  const isSync = action?.type === "sync";
  const isRemoteSync = action?.type === "remote-sync";
  const isUpdateInstall = action?.type === "update-install";
  return (
    <Modal
      title={isUpdateInstall ? "安装已经校验的新版本？" : isRestore ? "恢复这个备份？" : isDelete ? "删除这个账号？" : isSync ? `更新 ${profile?.name} 的登录？` : isRemoteSync ? `同步 ${profile?.name} 到 SSH？` : `切换到 ${profile?.name}？`}
      description={isUpdateInstall ? "将启动版本化安装包；安装器会排空后台网关，并在升级失败时恢复旧版本" : isRestore ? "恢复会回到该时间点的配置与会话索引" : isDelete ? "只删除 Guardian 保存的加密凭据" : isSync ? "将自动关闭 Codex，并读取刚刚重新登录后的最新凭据" : isRemoteSync ? `将写入 ${action?.hostCount || 0} 台已登记 SSH 主机，并让远端 Codex 重新加载配置` : "将自动关闭 Codex 并创建配置与元数据回滚点"}
      onClose={onClose}
      size="small"
    >
      <div className={`confirm-visual ${isDelete ? "danger" : ""}`}>
        {isUpdateInstall ? <RocketLaunch weight="duotone" /> : isRestore ? <Archive weight="duotone" /> : isDelete ? <Trash weight="duotone" /> : isSync ? <ArrowClockwise weight="duotone" /> : <UserSwitch weight="duotone" />}
      </div>
      <div className="confirm-list">
        {isUpdateInstall ? (
          <><span><CheckCircle weight="fill" /> 安装包名称、大小与 SHA-256 已核对</span><span><CheckCircle weight="fill" /> 只接受固定 GitHub 仓库的正式 Release</span><span><CheckCircle weight="fill" /> 旧版本保留供失败回滚</span></>
        ) : isRestore ? (
          <>
            <span><CheckCircle weight="fill" /> 恢复前会再创建一个安全备份</span>
            <span><CheckCircle weight="fill" /> 目标含 {backup?.active_count || 0} 条活动、{backup?.archived_count || 0} 条归档</span>
          </>
        ) : isDelete ? (
          <><span><Warning weight="fill" /> 当前 Codex 会话和备份不会删除</span><span><CheckCircle weight="fill" /> API Key / Token 加密文件会清除</span></>
        ) : isSync ? (
          <><span><CheckCircle weight="fill" /> 只接受同一个官方账号的最新登录</span><span><CheckCircle weight="fill" /> 更新前自动创建安全备份</span><span><CheckCircle weight="fill" /> 不改变聊天记录与归档状态</span></>
        ) : isRemoteSync ? (
          <><span><CheckCircle weight="fill" /> 远端有活动任务时会拒绝同步</span><span><CheckCircle weight="fill" /> API Key 只通过 SSH 标准输入传输</span><span><CheckCircle weight="fill" /> 每台主机都会返回独立结果</span></>
        ) : (
          <>
            <span><CheckCircle weight="fill" /> 自动备份 auth、config、SQLite 与会话文件</span>
            <span><CheckCircle weight="fill" /> 保持 {status?.database?.archived || 0} 条归档会话状态</span>
            <span><CheckCircle weight="fill" /> Provider 统一失败会自动回滚</span>
          </>
        )}
      </div>
      <footer className="modal-footer">
        <Button onClick={onClose}>取消</Button>
        <Button tone={isDelete ? "danger" : "primary"} icon={isDelete ? Trash : ArrowClockwise} loading={busy} onClick={onConfirm} disabled={busy}>
          {isUpdateInstall ? "启动安装" : isRestore ? "确认恢复" : isDelete ? "确认删除" : isSync ? "更新登录" : isRemoteSync ? "同步到 SSH" : "安全切换"}
        </Button>
      </footer>
    </Modal>
  );
}

export function App() {
  const [route, setRoute] = useState("overview");
  const [status, setStatus] = useState(null);
  const [backups, setBackups] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [editProfile, setEditProfile] = useState(null);
  const [confirmAction, setConfirmAction] = useState(null);
  const [toast, setToast] = useState(null);
  const [claudeStatus, setClaudeStatus] = useState(null);
  const [claudeLoading, setClaudeLoading] = useState(false);
  const [claudeRestartOpen, setClaudeRestartOpen] = useState(false);
  const [claudeProfileModal, setClaudeProfileModal] = useState(null);
  const [claudeAction, setClaudeAction] = useState(null);
  const quotaRefreshSignature = useRef("");

  const notify = useCallback((message, tone = "success") => {
    setToast({ message, tone, id: Date.now() });
  }, []);

  useEffect(() => {
    if (!toast) return undefined;
    const timer = window.setTimeout(() => setToast(null), 4200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const refresh = useCallback(async () => {
    try {
      const [nextStatus, nextBackups, nextLogs] = await Promise.all([
        api("/api/status"), api("/api/backups"), api("/api/logs"),
      ]);
      setStatus(nextStatus);
      setBackups(nextBackups);
      setLogs(nextLogs);
      return true;
    } catch (error) {
      notify(error.message, "error");
      return false;
    } finally {
      setLoading(false);
    }
  }, [notify]);

  const refreshOfficialQuotas = useCallback(async ({ silent = false } = {}) => {
    try {
      const result = await api("/api/quotas/refresh", { method: "POST", body: "{}" });
      if (result?.status) setStatus(result.status);
      return result;
    } catch (error) {
      if (!silent) notify(`额度同步失败：${error.message}`, "error");
      return null;
    }
  }, [notify]);

  const refreshClaude = useCallback(async () => {
    setClaudeLoading(true);
    try {
      const nextStatus = await api("/api/claude-desktop/status");
      setClaudeStatus(nextStatus);
      return nextStatus;
    } catch (error) {
      notify(`Claude 状态读取失败：${error.message}`, "error");
      return null;
    } finally {
      setClaudeLoading(false);
    }
  }, [notify]);

  const refreshAll = useCallback(async () => {
    if (refreshing) return;
    setRefreshing(true);
    try {
      if (route === "claude") {
        const result = await refreshClaude();
        if (result) notify("Claude Desktop 状态已刷新");
        return;
      }
      const statusOk = await refresh();
      const quotaResult = await refreshOfficialQuotas();
      if (statusOk && quotaResult !== null) notify("状态与额度已刷新");
    } finally {
      setRefreshing(false);
    }
  }, [refreshing, route, refresh, refreshClaude, refreshOfficialQuotas, notify]);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    if (route === "claude") refreshClaude();
  }, [route, refreshClaude]);

  useEffect(() => {
    if (!status) return;
    const signature = (status.profiles || [])
      .filter((profile) => profile.type === "official")
      .map((profile) => profile.id)
      .sort()
      .join("|");
    if (!signature || quotaRefreshSignature.current === signature) return;
    quotaRefreshSignature.current = signature;
    refreshOfficialQuotas({ silent: true });
  }, [status, refreshOfficialQuotas]);

  useEffect(() => {
    const hasOfficialProfile = (status?.profiles || []).some((profile) => profile.type === "official");
    if (!hasOfficialProfile) return undefined;
    const syncVisibleQuota = () => {
      if (document.visibilityState === "visible") refreshOfficialQuotas({ silent: true });
    };
    const timer = window.setInterval(syncVisibleQuota, 60_000);
    window.addEventListener("focus", syncVisibleQuota);
    document.addEventListener("visibilitychange", syncVisibleQuota);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("focus", syncVisibleQuota);
      document.removeEventListener("visibilitychange", syncVisibleQuota);
    };
  }, [status?.profiles, refreshOfficialQuotas]);

  const run = async (work, successMessage) => {
    setBusy(true);
    try {
      const result = await work();
      if (successMessage) notify(successMessage, "success");
      await refresh();
      return result;
    } catch (error) {
      notify(error.message, "error");
      return null;
    } finally {
      setBusy(false);
    }
  };

  const runClaudeAction = async (work, successMessage) => {
    setBusy(true);
    try {
      const result = await work();
      notify(successMessage, "success");
      await refreshClaude();
      return result;
    } catch (error) {
      notify(error.message, "error");
      return null;
    } finally {
      setBusy(false);
    }
  };

  const handleConfirm = async () => {
    const action = confirmAction;
    if (!action) return;
    let result;
    if (action.type === "switch") {
      result = await run(() => api(`/api/profiles/${action.profile.id}/switch`, { method: "POST", body: "{}" }), `已切换到 ${action.profile.name}`);
    } else if (action.type === "sync") {
      result = await run(() => api(`/api/profiles/${action.profile.id}/sync`, { method: "POST", body: "{}" }), `${action.profile.name} 的登录凭据已更新`);
    } else if (action.type === "remote-sync") {
      result = await run(() => api("/api/remote/sync-current", { method: "POST", body: "{}" }), null);
      if (result) {
        const complete = result.host_count > 0 && result.success_count === result.host_count;
        notify(
          complete
            ? `SSH 已同步 ${result.success_count}/${result.host_count}`
            : `SSH 同步未完成 ${result.success_count || 0}/${result.host_count || 0}`,
          complete ? "success" : "error",
        );
      }
    } else if (action.type === "restore") {
      result = await run(() => api(`/api/backups/${encodeURIComponent(action.backup.name)}/restore`, { method: "POST", body: "{}" }), "备份已恢复");
    } else if (action.type === "delete") {
      result = await run(() => api(`/api/profiles/${action.profile.id}`, { method: "DELETE" }), "账号已删除");
    } else if (action.type === "update-install") {
      result = await run(() => api("/api/update/install", { method: "POST", body: JSON.stringify({ confirm: true }) }), "已启动经过校验的更新安装程序");
    }
    if (result) setConfirmAction(null);
  };

  const body = useMemo(() => {
    const shared = {
      status,
      busy,
      onSwitch: (profile) => setConfirmAction({ type: "switch", profile }),
    };
    if (route === "overview") return <Overview {...shared} onNavigate={setRoute} onOpenAdd={() => setAddOpen(true)} />;
    if (route === "accounts") return (
      <Accounts
        {...shared}
        onOpenAdd={() => setAddOpen(true)}
        onImport={() => run(() => api("/api/import/cockpit", { method: "POST", body: "{}" }), "Cockpit 账号导入完成")}
        onSync={(profile) => setConfirmAction({ type: "sync", profile })}
        onTest={(profile) => run(() => api(`/api/profiles/${profile.id}/test`, { method: "POST", body: "{}" }), "API 连通性测试完成")}
        onEdit={(profile) => setEditProfile(profile)}
        onDelete={(profile) => setConfirmAction({ type: "delete", profile })}
      />
    );
    if (route === "protection") return <Protection status={status} busy={busy} onRepair={() => run(() => api("/api/protection/repair", { method: "POST", body: "{}" }), "共享聊天历史已修复")} />;
    if (route === "failover") return <FailoverPage client={failoverApiClient} onNavigateAccounts={() => setRoute("accounts")} />;
    if (route === "claude") return (
      <ClaudeDesktopPage
        status={claudeStatus}
        loading={claudeLoading}
        busy={busy}
        onRefresh={refreshClaude}
        onAdd={() => setClaudeProfileModal({ profile: null })}
        onEdit={(profile) => setClaudeProfileModal({ profile })}
        onApply={(profile) => setClaudeAction({ type: "apply", profile })}
        onDelete={(profile) => setClaudeAction({ type: "delete", profile })}
        onRestoreOfficial={() => setClaudeAction({ type: "restore" })}
        onImportCc={() => setClaudeAction({ type: "import" })}
        onRestart={() => setClaudeRestartOpen(true)}
      />
    );
    if (route === "backups") return <Backups backups={backups} busy={busy} onRestore={(backup) => setConfirmAction({ type: "restore", backup })} onOpen={() => api("/api/open-folder", { method: "POST", body: JSON.stringify({ kind: "backups" }) })} />;
    if (route === "logs") return <Logs logs={logs} busy={busy} onRefresh={refresh} onClear={() => run(() => api("/api/logs/clear", { method: "POST", body: "{}" }), "日志已清空")} />;
    return <Settings status={status} busy={busy} onSave={(settings) => run(() => api("/api/settings", { method: "POST", body: JSON.stringify(settings) }), "设置已保存")} onRemoteSync={async (settings) => { const saved = await run(() => api("/api/settings", { method: "POST", body: JSON.stringify(settings) }), null); if (saved) setConfirmAction({ type: "remote-sync", profile: status?.current_profile, hostCount: status?.remote?.host_count || 0 }); }} onUpdateCheck={() => run(() => api("/api/update/check", { method: "POST", body: "{}" }), "版本检查完成")} onUpdateDownload={() => run(() => api("/api/update/download", { method: "POST", body: "{}" }), "新版安装包已下载并通过校验")} onUpdateInstall={() => setConfirmAction({ type: "update-install" })} onOpen={(kind) => api("/api/open-folder", { method: "POST", body: JSON.stringify({ kind }) })} />;
  }, [route, status, busy, backups, logs, refresh, claudeStatus, claudeLoading, refreshClaude]);

  if (loading) {
    return <div className="boot-screen"><AppMark /><CircleNotch className="spin" weight="bold" /><span>正在检查本机 AI 客户端…</span></div>;
  }

  const [title, subtitle] = pageCopy[route];
  const activePlatform = route === "claude" ? "claude" : "codex";
  const claudeState = claudeStateCopy(claudeStatus);
  const choosePlatform = (platform) => {
    if (platform === "claude") {
      setRoute("claude");
    } else if (route === "claude") {
      setRoute("overview");
    }
  };
  return (
    <div className="app-shell is-gray">
      <aside className="sidebar">
        <div className="brand"><AppMark /><div><strong>Profile Guardian</strong><span>Codex + Claude</span></div></div>
        <div className="platform-switcher" role="tablist" aria-label="选择 AI 客户端">
          <button type="button" role="tab" aria-selected={activePlatform === "codex"} className={activePlatform === "codex" ? "is-active" : ""} onClick={() => choosePlatform("codex")}>
            <Desktop weight={activePlatform === "codex" ? "fill" : "regular"} /><span>Codex</span>
          </button>
          <button type="button" role="tab" aria-selected={activePlatform === "claude"} className={activePlatform === "claude" ? "is-active" : ""} onClick={() => choosePlatform("claude")}>
            <Monitor weight={activePlatform === "claude" ? "fill" : "regular"} /><span>Claude</span>
          </button>
        </div>
        <nav>
          {activePlatform === "codex" ? navItems.map((item) => {
            const Icon = item.icon;
            return <button key={item.id} className={route === item.id ? "is-active" : ""} onClick={() => setRoute(item.id)}><Icon weight={route === item.id ? "fill" : "regular"} /><span>{item.label}</span>{item.id === "backups" && backups.length > 0 && <small>{backups.length}</small>}</button>;
          }) : (
            <button className="is-active" onClick={() => setRoute("claude")}><Monitor weight="fill" /><span>连接状态</span></button>
          )}
        </nav>
        <div className="sidebar-status">
          <span className={`status-dot ${activePlatform === "claude" ? (claudeStatus?.state === "ready" || claudeStatus?.state === "official" ? "is-live" : "") : status?.codex_running ? "is-live" : ""}`} />
          {activePlatform === "claude" ? (
            <div><strong>{claudeState.title}</strong><span>{claudeStatus?.current_profile?.name || "Claude Desktop"}</span></div>
          ) : (
            <div><strong>{status?.codex_running ? "Codex 运行中" : "Codex 已关闭"}</strong><span>{status?.config_provider || "openai"}</span></div>
          )}
        </div>
        {activePlatform === "claude" ? (
          <Button tone="sidebar" icon={Plus} disabled={busy} onClick={() => setClaudeProfileModal({ profile: null })}>添加 Claude 供应商</Button>
        ) : (
          <Button tone="sidebar" icon={Play} onClick={() => run(() => api("/api/launch", { method: "POST", body: "{}" }), "已请求启动 Codex")}>启动 Codex</Button>
        )}
      </aside>
      <main className={`main-area ${route === "failover" ? "is-failover" : ""}`}>
        {route === "failover" ? body : (
          <>
            <header className="topbar">
              <div><span className="breadcrumb">CODEX PROFILE GUARDIAN</span><h1>{title}</h1><p>{subtitle}</p></div>
              <div className="topbar-actions">
                {route === "claude" ? (
                  <div className={`connection-pill ${claudeStatus?.state === "ready" || claudeStatus?.state === "official" ? "is-safe" : "is-warning"}`}><span /><div><strong>{claudeState.eyebrow}</strong><small>{claudeStatus?.current_profile?.name || "Claude Desktop"}</small></div></div>
                ) : (
                  <div className={`connection-pill ${status?.health?.safe ? "is-safe" : "is-warning"}`}><span /><div><strong>{status?.health?.safe ? "会话库正常" : "需要检查"}</strong><small>{status?.config_provider}</small></div></div>
                )}
                <button
                  className="icon-button top-refresh"
                  onClick={refreshAll}
                  disabled={refreshing}
                  aria-busy={refreshing}
                  aria-label={route === "claude" ? "刷新 Claude Desktop 状态" : "刷新状态与额度"}
                >
                  {refreshing ? <CircleNotch className="spin" weight="bold" /> : <ArrowClockwise weight="bold" />}
                </button>
              </div>
            </header>
            <div className="page-content">{body}</div>
          </>
        )}
      </main>
      {addOpen && <AddProfileModal onClose={() => setAddOpen(false)} onCreated={refresh} notify={notify} />}
      {editProfile && <EditProfileModal profile={editProfile} onClose={() => setEditProfile(null)} onSaved={refresh} onRemoteSyncRequired={(profile, hostCount) => setConfirmAction({ type: "remote-sync", profile, hostCount })} notify={notify} />}
      {confirmAction && <ConfirmModal action={confirmAction} status={status} busy={busy} onClose={() => !busy && setConfirmAction(null)} onConfirm={handleConfirm} />}
      {claudeProfileModal && <ClaudeProviderModal profile={claudeProfileModal.profile} onClose={() => setClaudeProfileModal(null)} onSaved={refreshClaude} notify={notify} />}
      {claudeAction && (
        <Modal
          title={claudeAction.type === "apply" ? `启用 ${claudeAction.profile?.name}？` : claudeAction.type === "delete" ? `删除 ${claudeAction.profile?.name}？` : claudeAction.type === "import" ? "从 CC Switch 一次性迁移？" : "恢复 Claude 官方模式？"}
          description={claudeAction.type === "apply" ? "Guardian 会先加密备份现有 Claude 配置，再写入新的 3P profile。" : claudeAction.type === "delete" ? "只删除 Guardian 保存的该供应商和 DPAPI 凭据。" : claudeAction.type === "import" ? "仅本次读取 CC Switch 当前 Anthropic 供应商，迁移后日常运行不再依赖 CC Switch。" : "Guardian 会备份当前 3P 配置并切回 Claude 官方登录。"}
          onClose={() => !busy && setClaudeAction(null)}
          size="small"
        >
          <div className={`confirm-visual ${claudeAction.type === "delete" ? "danger" : ""}`}>{claudeAction.type === "delete" ? <Trash weight="duotone" /> : <Monitor weight="duotone" />}</div>
          <div className="confirm-list">
            {claudeAction.type === "apply" && <><span><CheckCircle weight="fill" /> 原配置进入 DPAPI 加密回滚包</span><span><CheckCircle weight="fill" /> 启用后需要重启 Claude Desktop</span></>}
            {claudeAction.type === "delete" && <><span><CheckCircle weight="fill" /> 不删除 Claude 聊天或官方账号</span><span><Warning weight="fill" /> 删除后无法从 Guardian 恢复该 Key</span></>}
            {claudeAction.type === "import" && <><span><CheckCircle weight="fill" /> 上游 Key 转存到 Guardian DPAPI</span><span><CheckCircle weight="fill" /> 不启动、不调用 CC Switch 进程或本地路由</span></>}
            {claudeAction.type === "restore" && <><span><CheckCircle weight="fill" /> 保留 Guardian 供应商供以后再次启用</span><span><CheckCircle weight="fill" /> 恢复后需要重启 Claude Desktop</span></>}
          </div>
          <footer className="modal-footer">
            <Button onClick={() => setClaudeAction(null)} disabled={busy}>取消</Button>
            <Button
              tone={claudeAction.type === "delete" ? "danger" : "primary"}
              icon={claudeAction.type === "delete" ? Trash : ArrowClockwise}
              loading={busy}
              disabled={busy}
              onClick={async () => {
                let result = null;
                if (claudeAction.type === "apply") result = await runClaudeAction(() => api(`/api/claude-desktop/providers/${claudeAction.profile.id}/apply`, { method: "POST", body: JSON.stringify({ confirm: true }) }), "Claude 供应商已启用");
                if (claudeAction.type === "delete") result = await runClaudeAction(() => api(`/api/claude-desktop/providers/${claudeAction.profile.id}`, { method: "DELETE" }), "Claude 供应商已删除");
                if (claudeAction.type === "import") result = await runClaudeAction(() => api("/api/claude-desktop/import-cc-switch", { method: "POST", body: JSON.stringify({ confirm: true }) }), "CC Switch 当前供应商已迁移到 Guardian");
                if (claudeAction.type === "restore") result = await runClaudeAction(() => api("/api/claude-desktop/restore-official", { method: "POST", body: JSON.stringify({ confirm: true }) }), "Claude 已恢复官方模式");
                if (result) {
                  const needsRestart = claudeAction.type === "apply" || claudeAction.type === "restore";
                  setClaudeAction(null);
                  if (needsRestart) setClaudeRestartOpen(true);
                }
              }}
            >
              {claudeAction.type === "apply" ? "确认启用" : claudeAction.type === "delete" ? "确认删除" : claudeAction.type === "import" ? "确认迁移" : "恢复官方模式"}
            </Button>
          </footer>
        </Modal>
      )}
      {claudeRestartOpen && (
        <Modal
          title="重启 Claude Desktop？"
          description="当前窗口会关闭并重新打开；Claude Code CLI 不受影响。"
          onClose={() => !busy && setClaudeRestartOpen(false)}
          size="small"
        >
          <div className="confirm-visual"><Monitor weight="duotone" /></div>
          <div className="confirm-list">
            <span><CheckCircle weight="fill" /> 只关闭 Anthropic Desktop 安装目录中的进程</span>
            <span><CheckCircle weight="fill" /> Guardian 供应商与 DPAPI 凭据保持不变</span>
          </div>
          <footer className="modal-footer">
            <Button onClick={() => setClaudeRestartOpen(false)} disabled={busy}>取消</Button>
            <Button
              tone="primary"
              icon={ArrowClockwise}
              loading={busy}
              disabled={busy}
              onClick={async () => {
                const result = await runClaudeAction(
                  () => api("/api/claude-desktop/restart", { method: "POST", body: "{}" }),
                  "Claude Desktop 已重新启动",
                );
                if (result) setClaudeRestartOpen(false);
              }}
            >
              确认重启
            </Button>
          </footer>
        </Modal>
      )}
      {toast && <div className={`toast toast-${toast.tone}`}><span>{toast.tone === "success" ? <CheckCircle weight="fill" /> : <Warning weight="fill" />}</span><strong>{toast.message}</strong><button onClick={() => setToast(null)}><X weight="bold" /></button></div>}
    </div>
  );
}
