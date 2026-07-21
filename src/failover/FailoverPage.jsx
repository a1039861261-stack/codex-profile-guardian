import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowClockwise,
  ArrowsDownUp,
  CaretDown,
  CheckCircle,
  CircleDashed,
  CircleNotch,
  Database,
  Desktop,
  DownloadSimple,
  DotsThreeVertical,
  HardDrives,
  Info,
  Key,
  PencilSimple,
  Plus,
  Pulse,
  ShieldCheck,
  Trash,
  Warning,
  WarningCircle,
  WifiSlash,
  X,
} from "@phosphor-icons/react";
import { useFailoverData } from "./useFailoverData.js";
import {
  breakerState,
  failureLabel,
  formatTimestamp,
  nextActionLabel,
  overallState,
  routeLetter,
  routeRole,
} from "./presentation.js";
import "./failover.css";

const defaultBreakerPolicy = {
  failure_threshold: 3,
  protocol_failure_threshold: 2,
  error_rate_threshold: 0.5,
  minimum_samples: 4,
  window_size: 20,
  recovery_success_threshold: 2,
  base_cooldown_seconds: 30,
  max_cooldown_seconds: 300,
  jitter_ratio: 0.1,
};

const defaultProbePolicy = {
  enabled: true,
  mode: "models",
  interval_seconds: 300,
  timeout_seconds: 5,
  allow_billable: false,
  allow_action_required_auto_retest: false,
};

function StatePill({ tone = "neutral", children }) {
  const Icon = tone === "good" ? CheckCircle
    : tone === "danger" ? Warning
      : tone === "warning" ? WarningCircle
        : CircleDashed;
  return <span className={`fo-state-pill tone-${tone}`}><Icon weight="fill" />{children}</span>;
}

function ActionButton({ icon: Icon, tone = "neutral", loading = false, children, ...props }) {
  const type = props.type || "button";
  return (
    <button className={`fo-button tone-${tone}`} {...props} type={type}>
      {loading ? <CircleNotch className="fo-spin" /> : Icon ? <Icon weight="bold" /> : null}
      <span>{children}</span>
    </button>
  );
}

function IconButton({ icon: Icon, label, loading = false, ...props }) {
  return (
    <button className="fo-icon-button" type="button" aria-label={label} title={label} {...props}>
      {loading ? <CircleNotch className="fo-spin" /> : <Icon weight="bold" />}
    </button>
  );
}

function PageNotice({ overview, stale }) {
  const fixture = overview?.source === "fixture";
  return (
    <div className={`fo-notice ${stale ? "is-stale" : ""}`} role={stale ? "alert" : "note"}>
      {stale ? <WarningCircle weight="fill" /> : <Info weight="fill" />}
      <span>
        <strong>{stale ? "状态可能已过期" : fixture ? "合成预览" : "本机管理状态"}</strong>
        {fixture ? " · 稳定版 v1.6.2 · 未安装/未切 provider" : " · provider 与网关配置分开管理"}
      </span>
      <time dateTime={overview?.collected_at || undefined}>{formatTimestamp(overview?.collected_at, "尚未同步")}</time>
    </div>
  );
}

function SpecialState({ type, onAction, canCreate = true, onAccounts }) {
  const values = {
    loading: [CircleNotch, "正在读取线路状态", "正在从 Guardian 管理 API 获取脱敏快照。"],
    empty: [Database, "还没有容灾组", canCreate ? "从两个已保存的 API 档案创建第一组。" : "至少需要两个可用的第三方 API 档案。"],
    error: [WifiSlash, "状态读取失败", "无法读取线路状态，请重新加载。"],
  };
  const [Icon, title, detail] = values[type];
  return (
    <section className={`fo-special-state is-${type}`} role={type === "error" ? "alert" : "status"}>
      <Icon className={type === "loading" ? "fo-spin" : ""} />
      <h2>{title}</h2>
      <p>{detail}</p>
      {type === "empty" && canCreate && <ActionButton tone="primary" icon={Plus} onClick={onAction}>创建容灾组</ActionButton>}
      {type === "empty" && !canCreate && onAccounts && <ActionButton icon={Key} onClick={onAccounts}>打开账号</ActionButton>}
      {type === "error" && <ActionButton icon={ArrowClockwise} onClick={onAction}>重新加载</ActionButton>}
    </section>
  );
}

function StatusOverview({ overview, group, stale, onPublish, onRetest, onActivateProvider, pendingAction }) {
  const presentation = overallState(group?.overall_state, stale);
  const Icon = presentation.tone === "good" ? CheckCircle
    : presentation.tone === "danger" ? Warning
      : presentation.tone === "warning" ? WarningCircle
        : CircleDashed;
  const canRetest = overview?.capabilities?.retest_routes && (
    group?.requires_action || group?.overall_state === "unavailable"
  );
  const canPublish = overview?.capabilities?.publish_config && group?.publication_state === "draft";
  const canActivateProvider = overview?.capabilities?.activate_provider && group?.publication_state !== "draft";
  return (
    <section className={`fo-status-overview tone-${presentation.tone}`} aria-labelledby="fo-status-title" aria-live="polite">
      <div className="fo-status-heading">
        <span className="fo-status-icon"><Icon weight="fill" /></span>
        <div>
          <span className="fo-section-label">当前状态</span>
          <h2 id="fo-status-title">{presentation.headline}</h2>
          <p>{presentation.supporting}</p>
        </div>
      </div>
      <div className="fo-status-controls">
        <StatePill tone={presentation.tone}>{presentation.label}</StatePill>
        {canRetest ? (
          <ActionButton
            icon={ArrowClockwise}
            loading={pendingAction === "retest-primary"}
            disabled={Boolean(pendingAction)}
            onClick={() => onRetest("primary")}
          >重新测试 P1</ActionButton>
        ) : canPublish ? (
          <ActionButton
            tone="primary"
            icon={Pulse}
            loading={pendingAction === "publish"}
            disabled={Boolean(pendingAction)}
            onClick={onPublish}
          >发布配置</ActionButton>
        ) : canActivateProvider ? (
          <ActionButton
            tone="primary"
            icon={ShieldCheck}
            loading={pendingAction === "activate-provider"}
            disabled={Boolean(pendingAction)}
            onClick={onActivateProvider}
          >启用本地容灾</ActionButton>
        ) : null}
      </div>
    </section>
  );
}

function KeyFacts({ overview, group, stale }) {
  const primary = group.routes?.find((route) => route.role === "primary");
  const carrying = group.routes?.find((route) => route.carrying);
  const [, primaryLabel] = breakerState(primary?.breaker_state, primary?.carrying);
  const facts = [
    ["当前承载", carrying ? `${routeLetter(carrying.role)} · ${carrying.profile_name}` : "尚未确定"],
    ["主线状态", primaryLabel],
    ["需要操作", nextActionLabel({ ...overview, stale }, group)],
  ];
  return (
    <section className="fo-key-facts" aria-label="关键状态">
      {facts.map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}
    </section>
  );
}

function RouteCard({ route, revision, canRetest, pendingAction, onRetest }) {
  const [tone, label] = breakerState(route.breaker_state, route.carrying);
  const unhealthy = !route.carrying && !["closed"].includes(route.breaker_state);
  const lastResult = failureLabel(route.last_result?.category, route.last_result?.http_status);
  return (
    <article className={`fo-route-card tone-${tone} ${route.carrying ? "is-carrying" : ""}`}>
      <div className="fo-route-header">
        <div className="fo-route-identity">
          <span className="fo-route-letter">{routeLetter(route.role)}</span>
          <div><span>{routeRole(route.role)}</span><h3>{route.profile_name || "未命名档案"}</h3></div>
        </div>
        <StatePill tone={tone}>{label}</StatePill>
      </div>
      <p className="fo-route-summary"><span>{lastResult}</span>{route.last_result?.detail || formatTimestamp(route.last_result?.at)}</p>
      <details className="fo-route-details">
        <summary><span>线路详情</span><CaretDown /></summary>
        <dl>
          <div><dt>Breaker</dt><dd>{route.breaker_state || "unknown"}</dd></div>
          <div><dt>模型</dt><dd>{route.model || "待验证"}</dd></div>
          <div><dt>Base Host</dt><dd>{route.base_host || "未提供"}</dd></div>
          <div><dt>Key</dt><dd>{route.key_suffix ? `••••${route.key_suffix}` : "已加密"}</dd></div>
          <div><dt>配置版本</dt><dd>Revision {revision}</dd></div>
          <div><dt>最近结果</dt><dd>{formatTimestamp(route.last_result?.at)}</dd></div>
          {route.open_until && <div><dt>恢复时间</dt><dd>{formatTimestamp(route.open_until)}</dd></div>}
        </dl>
        {canRetest && unhealthy && (
          <ActionButton
            icon={ArrowClockwise}
            loading={pendingAction === `retest-${route.role}`}
            disabled={Boolean(pendingAction)}
            onClick={() => onRetest(route.role)}
          >重新测试 {routeLetter(route.role)}</ActionButton>
        )}
      </details>
    </article>
  );
}

function RoutesSection({ overview, group, pendingAction, onRetest }) {
  return (
    <section className="fo-routes-section" aria-labelledby="fo-routes-title">
      <div className="fo-section-heading">
        <div><h2 id="fo-routes-title">两条线路</h2><p>配置主线始终是 P1；自动切换只发生在网关内部。</p></div>
        <StatePill tone={group.enabled ? "neutral" : "warning"}>{group.enabled ? group.name : "已停用"}</StatePill>
      </div>
      <div className="fo-route-grid">
        {(group.routes || []).map((route) => (
          <RouteCard
            route={route}
            revision={group.revision}
            canRetest={Boolean(overview?.capabilities?.retest_routes)}
            pendingAction={pendingAction}
            onRetest={onRetest}
            key={route.role}
          />
        ))}
      </div>
    </section>
  );
}

function EventList({ events, onLoadMore, loadingMore }) {
  if (!events?.items?.length) return <p className="fo-muted-empty">暂无脱敏事件。</p>;
  return (
    <div className="fo-event-list">
      {events.items.map((event) => (
        <div className="fo-event-row" key={event.event_id}>
          <time dateTime={event.timestamp}>{formatTimestamp(event.timestamp)}</time>
          <div><strong>{event.title || event.event || "状态更新"}</strong><span>{event.detail || event.status}</span></div>
          <small>{event.kind || event.signal || "事件"}</small>
        </div>
      ))}
      {events.page?.has_more && (
        <ActionButton loading={loadingMore} disabled={loadingMore} onClick={onLoadMore}>加载更多</ActionButton>
      )}
    </div>
  );
}

function hostState(host) {
  if (host?.online && !host?.stale) return ["good", "在线"];
  if (host?.collected_at) return ["warning", "离线 · 旧状态"];
  return ["warning", "尚未采集"];
}

function carrierLabel(value) {
  if (value === "primary") return "P1";
  if (value === "backup") return "P2";
  return "未确定";
}

function HostStatusList({ hosts, error, onRefresh, refreshing }) {
  const items = hosts?.items || [];
  return (
    <div className="fo-host-status">
      <div className="fo-host-status-heading">
        <p>页面读取只使用脱敏缓存；点击刷新才执行只读 SSH 状态检查。</p>
        <ActionButton icon={ArrowClockwise} loading={refreshing} disabled={refreshing} onClick={onRefresh}>刷新远端状态</ActionButton>
      </div>
      {error && <div className="fo-host-warning" role="status"><WarningCircle weight="fill" />远端状态暂未刷新，已保留旧快照。</div>}
      <div className="fo-host-grid">
        {items.map((host) => {
          const [tone, label] = hostState(host);
          return (
            <article className={`fo-host-card tone-${tone}`} key={host.host_key}>
              <header><span><HardDrives weight="bold" /></span><div><strong>{host.display_name}</strong><small>{host.kind === "nas" ? "SSH / NAS" : "本机 Gateway"}</small></div><StatePill tone={tone}>{label}</StatePill></header>
              <dl>
                <div><dt>版本</dt><dd>{host.version || "待确认"}</dd></div>
                <div><dt>Revision</dt><dd>{host.config_revision ?? "-"}</dd></div>
                <div><dt>当前承载</dt><dd>{carrierLabel(host.carrier)}</dd></div>
                <div><dt>线路</dt><dd>P1 {host.routes?.primary || "unknown"} · P2 {host.routes?.backup || "unknown"}</dd></div>
              </dl>
              <time dateTime={host.collected_at || undefined}>{host.collected_at ? `采集于 ${formatTimestamp(host.collected_at)}` : "尚未进行只读采集"}</time>
            </article>
          );
        })}
      </div>
      {!items.length && <p className="fo-muted-empty">暂无可显示的 Gateway 主机。</p>}
    </div>
  );
}

function AdvancedDetails({ overview, group, events, hosts, hostsError, onRefreshHosts, onLoadMore, pendingAction, onDownloadDiagnostics, diagnosticsBusy, diagnosticsError, onRestoreDirect }) {
  const gatewayState = overview?.gateway?.state || "unknown";
  return (
    <details className="fo-advanced-panel">
      <summary><div><Info /><span><strong>更多信息</strong><small>主机、事件、运行环境与可靠性边界</small></span></div><CaretDown /></summary>
      <div className="fo-advanced-content">
        <section className="fo-host-section"><h3>Gateway 主机</h3><HostStatusList hosts={hosts} error={hostsError} onRefresh={onRefreshHosts} refreshing={pendingAction === "hosts"} /></section>
        <section><h3>最近事件</h3><EventList events={events} onLoadMore={onLoadMore} loadingMore={pendingAction === "events"} /></section>
        <section>
          <h3>运行环境</h3>
          <div className="fo-runtime-list">
            <div className="fo-runtime-row"><Desktop /><div><strong>Windows 本机</strong><span>{overview?.gateway?.version || "版本待确认"} · Revision {overview?.gateway?.config_revision || "-"}</span></div><StatePill tone={gatewayState.includes("running") ? "neutral" : "warning"}>{gatewayState}</StatePill></div>
            <div className="fo-runtime-row is-muted"><ShieldCheck /><div><strong>Codex provider</strong><span>{overview?.provider?.provider_id || "guardian_gateway"}</span></div><StatePill tone="neutral">{overview?.provider?.activation_state || "未知"}</StatePill></div>
            {overview?.capabilities?.restore_direct && <ActionButton icon={ArrowsDownUp} disabled={Boolean(pendingAction)} loading={pendingAction === "restore-direct"} onClick={onRestoreDirect}>恢复切入前直连</ActionButton>}
            <p>状态由 Guardian 后端聚合；React 不接收 control token。</p>
          </div>
        </section>
        <section className="fo-diagnostics-section">
          <div><h3>脱敏诊断包</h3><p>仅包含 Gateway 状态、最近事件和主机健康投影，不包含 Key、地址、账号、请求正文或聊天内容。</p></div>
          <ActionButton icon={DownloadSimple} loading={diagnosticsBusy} disabled={diagnosticsBusy} onClick={onDownloadDiagnostics}>导出诊断包</ActionButton>
          {diagnosticsError && <div className="fo-host-warning" role="alert"><WarningCircle weight="fill" />诊断包暂时无法生成，请刷新状态后重试。</div>}
        </section>
        <section className="fo-reliability-section">
          <h3>可靠性边界</h3>
          <div className="fo-reliability-grid">
            <p><strong>完整缓冲</strong><span>上游完整前向 Codex 提交 0 内容。</span></p>
            <p><strong>重复计费</strong><span>主线未完成时，备用重放可能产生双重计费。</span></p>
            <p><strong>状态引用</strong><span>状态不兼容时停止透明重放。</span></p>
            <p><strong>提交中断</strong><span>标记 delivery_uncertain，不自动重发。</span></p>
          </div>
        </section>
      </div>
    </details>
  );
}

function ModalFrame({ title, detail, onClose, children, busy = false }) {
  const dialogRef = useRef(null);
  const openerRef = useRef(document.activeElement instanceof HTMLElement ? document.activeElement : null);
  const onCloseRef = useRef(onClose);
  const busyRef = useRef(busy);
  onCloseRef.current = onClose;
  busyRef.current = busy;

  useEffect(() => {
    const dialog = dialogRef.current;
    const focusable = () => Array.from(dialog?.querySelectorAll(
      'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
    ) || []).filter((element) => !element.hasAttribute("hidden") && element.getAttribute("aria-hidden") !== "true");
    const initial = dialog?.querySelector("[data-modal-initial-focus]") || focusable()[0];
    initial?.focus();

    const handleKeyDown = (event) => {
      if (event.key === "Escape" && !busyRef.current) {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const elements = focusable();
      if (!elements.length) {
        event.preventDefault();
        dialog?.focus();
        return;
      }
      const first = elements[0];
      const last = elements[elements.length - 1];
      if (event.shiftKey && (document.activeElement === first || !dialog?.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !dialog?.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      const opener = openerRef.current;
      if (opener?.isConnected) opener.focus();
    };
  }, []);
  return (
    <div className="fo-modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && !busy && onClose()}>
      <section className="fo-modal" role="dialog" aria-modal="true" aria-labelledby="fo-modal-title" ref={dialogRef} tabIndex="-1">
        <header><div><h2 id="fo-modal-title">{title}</h2>{detail && <p>{detail}</p>}</div><IconButton icon={X} label="关闭" onClick={onClose} disabled={busy} /></header>
        {children}
      </section>
    </div>
  );
}

function GroupEditor({ group, profiles, expectedRevision, busy, error, onClose, onSubmit }) {
  const eligible = profiles.filter((profile) => profile.eligible !== false);
  const [values, setValues] = useState(() => ({
    name: group?.name || "",
    enabled: group?.enabled ?? true,
    primary_profile_id: group?.primary_profile_id || eligible[0]?.id || "",
    backup_profile_id: group?.backup_profile_id || eligible[1]?.id || "",
    allowed_models: (group?.allowed_models || [eligible[0]?.model].filter(Boolean)).join(", "),
    breaker_policy: { ...defaultBreakerPolicy, ...(group?.breaker_policy || {}) },
    probe_policy: { ...defaultProbePolicy, ...(group?.probe_policy || {}) },
  }));
  const [fieldError, setFieldError] = useState("");
  const update = (name, value) => setValues((current) => ({ ...current, [name]: value }));
  const updatePolicy = (section, name, value) => setValues((current) => ({
    ...current,
    [section]: { ...current[section], [name]: value },
  }));
  const submit = (event) => {
    event.preventDefault();
    const models = values.allowed_models.split(",").map((value) => value.trim()).filter(Boolean);
    if (!values.name.trim()) return setFieldError("请输入容灾组名称。");
    if (!values.primary_profile_id || !values.backup_profile_id) return setFieldError("请选择 P1 和 P2。 ");
    if (values.primary_profile_id === values.backup_profile_id) return setFieldError("P1 和 P2 必须使用不同档案。");
    if (!models.length) return setFieldError("至少保留一个主备兼容模型。");
    setFieldError("");
    onSubmit({
      name: values.name.trim(),
      enabled: values.enabled,
      primary_profile_id: values.primary_profile_id,
      backup_profile_id: values.backup_profile_id,
      allowed_models: models,
      breaker_policy: values.breaker_policy,
      probe_policy: values.probe_policy,
      expected_revision: expectedRevision,
    });
  };
  return (
    <ModalFrame title={group ? "编辑容灾组" : "创建容灾组"} detail="只引用已保存档案，不复制明文 Key。" onClose={onClose} busy={busy}>
      <form className="fo-group-form" onSubmit={submit}>
        <label><span>名称</span><input value={values.name} onChange={(event) => update("name", event.target.value)} maxLength="80" autoFocus data-modal-initial-focus /></label>
        <div className="fo-route-select-grid">
          <label><span>P1 · 配置主线</span><select value={values.primary_profile_id} onChange={(event) => update("primary_profile_id", event.target.value)}>{eligible.map((profile) => <option value={profile.id} key={profile.id}>{profile.name} · {profile.key_suffix}</option>)}</select></label>
          <button className="fo-swap-button" type="button" aria-label="交换 P1 和 P2" title="交换 P1 和 P2" onClick={() => setValues((current) => ({ ...current, primary_profile_id: current.backup_profile_id, backup_profile_id: current.primary_profile_id }))}><ArrowsDownUp /></button>
          <label><span>P2 · 备用线路</span><select value={values.backup_profile_id} onChange={(event) => update("backup_profile_id", event.target.value)}>{eligible.map((profile) => <option value={profile.id} key={profile.id}>{profile.name} · {profile.key_suffix}</option>)}</select></label>
        </div>
        <label><span>兼容模型</span><input value={values.allowed_models} onChange={(event) => update("allowed_models", event.target.value)} placeholder="多个模型用逗号分隔" /></label>
        <label className="fo-toggle-row"><input type="checkbox" checked={values.enabled} onChange={(event) => update("enabled", event.target.checked)} /><span><strong>启用此容灾组</strong><small>保存草稿不会切换 Codex provider。</small></span></label>
        <details className="fo-form-advanced">
          <summary><span>高级策略</span><CaretDown /></summary>
          <div className="fo-policy-grid">
            <label><span>失败阈值</span><input type="number" min="1" max="1000" value={values.breaker_policy.failure_threshold} onChange={(event) => updatePolicy("breaker_policy", "failure_threshold", Number(event.target.value))} /></label>
            <label><span>恢复成功数</span><input type="number" min="1" max="1000" value={values.breaker_policy.recovery_success_threshold} onChange={(event) => updatePolicy("breaker_policy", "recovery_success_threshold", Number(event.target.value))} /></label>
            <label><span>基础冷却（秒）</span><input type="number" min="1" max="86400" value={values.breaker_policy.base_cooldown_seconds} onChange={(event) => updatePolicy("breaker_policy", "base_cooldown_seconds", Number(event.target.value))} /></label>
            <label><span>探测间隔（秒）</span><input type="number" min="30" max="604800" value={values.probe_policy.interval_seconds} onChange={(event) => updatePolicy("probe_policy", "interval_seconds", Number(event.target.value))} /></label>
          </div>
        </details>
        {(fieldError || error) && <div className="fo-form-error" role="alert"><WarningCircle />{fieldError || error.message}</div>}
        <footer><ActionButton onClick={onClose} disabled={busy}>取消</ActionButton><ActionButton tone="primary" icon={group ? PencilSimple : Plus} loading={busy} disabled={busy} type="submit">{group ? "保存更改" : "创建"}</ActionButton></footer>
      </form>
    </ModalFrame>
  );
}

function ConfirmDialog({ action, group, fixture, busy, error, onClose, onConfirm }) {
  const values = {
    publish: {
      title: "发布容灾配置",
      detail: `把 Revision ${group.revision} 发布到${fixture ? "合成" : "本机"}网关。`,
      fact: "发布只更新网关配置，不会把 Codex 切入 provider。",
      label: "确认发布",
      icon: Pulse,
      tone: "primary",
    },
    activate: {
      title: "启用本地容灾",
      detail: `把 Codex 固定连接到已发布的 Guardian Gateway Revision ${group.revision}。`,
      fact: "Guardian 会先安全关闭 Codex、写入可回滚配置，再按设置重新启动；日常 P1/P2 切换不会再改 provider。",
      label: "确认启用",
      icon: ShieldCheck,
      tone: "primary",
    },
    restore: {
      title: "恢复切入前直连",
      detail: "恢复启用 Guardian Gateway 之前的 Codex provider 配置。",
      fact: "恢复后将失去自动容灾；Guardian 会保留网关配置和加密档案。",
      label: "确认恢复",
      icon: ArrowsDownUp,
      tone: "danger",
    },
    delete: {
      title: "删除容灾组",
      detail: `“${group.name}”将从 Guardian 配置中移除。`,
      fact: "已发布或正在使用的容灾组可能被服务端阻止删除。",
      label: "确认删除",
      icon: Trash,
      tone: "danger",
    },
  };
  const mode = values[action] || values.delete;
  const ActionIcon = mode.icon;
  return (
    <ModalFrame
      title={mode.title}
      detail={mode.detail}
      onClose={onClose}
      busy={busy}
    >
      <div className="fo-confirm-body">
        <div className="fo-confirm-fact"><Info /><span>{mode.fact}</span></div>
        {error && <div className="fo-form-error" role="alert"><WarningCircle />{error.message}</div>}
      </div>
      <footer className="fo-modal-footer"><ActionButton onClick={onClose} disabled={busy}>取消</ActionButton><ActionButton tone={mode.tone} icon={ActionIcon} loading={busy} disabled={busy} onClick={onConfirm} data-modal-initial-focus>{mode.label}</ActionButton></footer>
    </ModalFrame>
  );
}

function GroupMenu({ overview, group, pendingAction, onEdit, onEnabled, onPublish, onDelete }) {
  const ref = useRef(null);
  const closeThen = (work) => {
    if (ref.current) ref.current.open = false;
    work();
  };
  return (
    <details className="fo-group-menu" ref={ref}>
      <summary aria-label="容灾组操作" title="容灾组操作"><DotsThreeVertical weight="bold" /></summary>
      <div>
        <button type="button" onClick={() => closeThen(onEdit)}><PencilSimple />编辑</button>
        <label><input type="checkbox" checked={Boolean(group.enabled)} disabled={Boolean(pendingAction)} onChange={(event) => closeThen(() => onEnabled(event.target.checked))} /><span>{group.enabled ? "已启用" : "已停用"}</span></label>
        {overview?.capabilities?.publish_config && <button type="button" disabled={group.publication_state !== "draft" || Boolean(pendingAction)} onClick={() => closeThen(onPublish)}><Pulse />发布配置</button>}
        <button className="is-danger" type="button" disabled={Boolean(pendingAction)} onClick={() => closeThen(onDelete)}><Trash />删除</button>
      </div>
    </details>
  );
}

export function FailoverPage({ client, refreshKey, previewControl = null, onNavigateAccounts }) {
  const data = useFailoverData(client, refreshKey);
  const [editor, setEditor] = useState(null);
  const [confirmation, setConfirmation] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [feedback, setFeedback] = useState(null);
  const [diagnosticsBusy, setDiagnosticsBusy] = useState(false);
  const [diagnosticsError, setDiagnosticsError] = useState(null);
  const overview = data.overview;
  const group = overview?.group;
  const profiles = overview?.profile_options || [];
  const canCreate = profiles.filter((profile) => profile.eligible !== false).length >= 2;
  const stale = Boolean(overview?.stale || data.refreshError);

  useEffect(() => {
    if (!feedback) return undefined;
    const timer = window.setTimeout(() => setFeedback(null), 3600);
    return () => window.clearTimeout(timer);
  }, [feedback]);

  const run = async (actionId, work, message, onDone) => {
    setActionError(null);
    try {
      await data.runMutation(actionId, work);
      setFeedback(message);
      onDone?.();
    } catch (error) {
      setActionError(error);
    }
  };

  const openConfirmation = (action, targetGroup = group) => {
    if (!targetGroup) return;
    setActionError(null);
    setConfirmation({
      action,
      fixture: overview?.source === "fixture",
      group: {
        id: targetGroup.id,
        name: targetGroup.name,
        revision: targetGroup.revision,
      },
    });
  };

  const saveGroup = (values) => {
    if (editor?.mode === "edit") {
      run("edit", () => client.editGroup(editor.group.id, values), "容灾组草稿已保存", () => setEditor(null));
    } else {
      run("create", () => client.createGroup(values), "容灾组已创建", () => setEditor(null));
    }
  };

  const retest = (role) => run(
    `retest-${role}`,
    () => client.retestRoute(group.id, role, group.revision),
    `${routeLetter(role)} ${overview?.source === "fixture" ? "合成" : "线路"}复测已完成`,
  );

  const downloadDiagnostics = async () => {
    if (diagnosticsBusy) return;
    setDiagnosticsBusy(true);
    setDiagnosticsError(null);
    try {
      const result = await client.downloadDiagnostics();
      const url = URL.createObjectURL(result.blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = result.filename;
      anchor.hidden = true;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
      setFeedback("脱敏诊断包已生成");
    } catch (error) {
      setDiagnosticsError(error);
    } finally {
      setDiagnosticsBusy(false);
    }
  };

  const confirmAction = () => {
    const target = confirmation?.group;
    if (!target) return;
    if (confirmation.action === "publish") {
      run("publish", () => client.publishGroup(target.id, target.revision), "配置已发布到网关", () => setConfirmation(null));
    } else if (confirmation.action === "activate") {
      run("activate-provider", () => client.activateProvider(target.revision), "Codex 已启用本地容灾", () => setConfirmation(null));
    } else if (confirmation.action === "restore") {
      run("restore-direct", () => client.restoreDirect(), "Codex 已恢复切入前直连", () => setConfirmation(null));
    } else if (confirmation.action === "delete") {
      run("delete", () => client.deleteGroup(target.id, target.revision), "容灾组已删除", () => setConfirmation(null));
    }
  };

  const groupSummaries = overview?.groups || [];
  const pageBody = useMemo(() => {
    if (data.loading && !overview) return <SpecialState type="loading" />;
    if (data.initialError && !overview) return <SpecialState type="error" onAction={data.refresh} />;
    if (overview && !group) return <SpecialState type="empty" canCreate={canCreate} onAction={() => { setActionError(null); setEditor({ mode: "create" }); }} onAccounts={onNavigateAccounts} />;
    if (!group) return null;
    return (
      <>
        <StatusOverview overview={overview} group={group} stale={stale} pendingAction={data.pendingAction} onPublish={() => openConfirmation("publish")} onRetest={retest} onActivateProvider={() => openConfirmation("activate")} />
        <KeyFacts overview={overview} group={group} stale={stale} />
        <RoutesSection overview={overview} group={group} pendingAction={data.pendingAction} onRetest={retest} />
        <AdvancedDetails overview={overview} group={group} events={data.events} hosts={data.hosts} hostsError={data.hostsError} onRefreshHosts={data.refreshHosts} onLoadMore={data.loadMoreEvents} pendingAction={data.pendingAction} onDownloadDiagnostics={downloadDiagnostics} diagnosticsBusy={diagnosticsBusy} diagnosticsError={diagnosticsError} onRestoreDirect={() => openConfirmation("restore")} />
      </>
    );
  }, [canCreate, data.events, data.hosts, data.hostsError, data.initialError, data.loading, data.pendingAction, data.refresh, data.refreshHosts, diagnosticsBusy, diagnosticsError, group, onNavigateAccounts, overview, stale]);

  return (
    <section className="failover-surface">
      <header className="fo-topbar">
        <div><span className="fo-breadcrumb">GUARDIAN / 本机</span><h1>API 容灾</h1><p>当前线路、故障原因与下一步。</p></div>
        <div className="fo-topbar-controls">
          {previewControl}
          {groupSummaries.length > 0 && (
            <label className="fo-group-picker"><span>容灾组</span><select value={data.selectedGroupId || ""} onChange={(event) => data.selectGroup(event.target.value)}>{groupSummaries.map((item) => <option value={item.id} key={item.id}>{item.name}{item.publication_state === "draft" ? " · 未发布" : ""}</option>)}</select></label>
          )}
          <div className="fo-command-row">
            <IconButton icon={ArrowClockwise} label="刷新线路状态" loading={data.refreshing} disabled={data.refreshing} onClick={data.refresh} />
            {overview?.capabilities?.manage_groups !== false && <ActionButton icon={Plus} onClick={() => { setActionError(null); setEditor({ mode: "create" }); }} disabled={!canCreate}>新建</ActionButton>}
            {group && <GroupMenu overview={overview} group={group} pendingAction={data.pendingAction} onEdit={() => { setActionError(null); setEditor({ mode: "edit", group }); }} onEnabled={(enabled) => run("enabled", () => client.setGroupEnabled(group.id, enabled, group.revision), enabled ? "容灾组已启用" : "容灾组已停用")} onPublish={() => openConfirmation("publish", group)} onDelete={() => openConfirmation("delete", group)} />}
          </div>
        </div>
      </header>
      <div className="fo-content">
        {overview && <PageNotice overview={overview} stale={stale} />}
        {data.refreshError && overview && <div className="fo-inline-error" role="alert"><WarningCircle weight="fill" /><span>{data.refreshError.message}</span><button type="button" onClick={data.refresh}>重试</button></div>}
        {data.eventsError && overview && <div className="fo-inline-warning" role="status"><WarningCircle weight="fill" /><span>状态已更新，但最近事件暂未刷新。</span><button type="button" onClick={data.refresh}>重新读取</button></div>}
        {pageBody}
      </div>
      {editor && <GroupEditor group={editor.group} profiles={profiles} expectedRevision={overview?.revision ?? editor.group?.revision ?? 0} busy={["create", "edit"].includes(data.pendingAction)} error={actionError} onClose={() => !data.pendingAction && setEditor(null)} onSubmit={saveGroup} />}
      {confirmation && <ConfirmDialog action={confirmation.action} group={confirmation.group} fixture={confirmation.fixture} busy={["publish", "delete", "activate-provider", "restore-direct"].includes(data.pendingAction)} error={actionError} onClose={() => !data.pendingAction && setConfirmation(null)} onConfirm={confirmAction} />}
      {feedback && <div className="fo-toast" role="status"><CheckCircle weight="fill" /><span>{feedback}</span><button type="button" aria-label="关闭提示" onClick={() => setFeedback(null)}><X /></button></div>}
    </section>
  );
}
