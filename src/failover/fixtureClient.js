import { ApiError } from "../api.js";
import { scenarios } from "../fixtures/failoverPreview.js";

const now = () => new Date().toISOString();

const profileOptions = [
  { id: "f1000000000000000000000000000001", name: "主线路样例", base_host: "api-primary.fixture.invalid", key_suffix: "P1T7", model: "gpt-fixture-compatible", eligible: true },
  { id: "f2000000000000000000000000000002", name: "备用线路样例", base_host: "api-backup.fixture.invalid", key_suffix: "P2Q2", model: "gpt-fixture-compatible", eligible: true },
  { id: "f3000000000000000000000000000003", name: "备用档案 B", base_host: "api-spare.fixture.invalid", key_suffix: "SP03", model: "gpt-fixture-compatible", eligible: true },
];

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

function fixtureId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID().replaceAll("-", "");
  return `fixture${Date.now().toString(16)}${Math.random().toString(16).slice(2)}`.slice(0, 32);
}

function abortablePending(signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("Aborted", "AbortError"));
      return;
    }
    signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    void resolve;
  });
}

function delay(signal, milliseconds = 120) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("Aborted", "AbortError"));
      return;
    }
    const timer = window.setTimeout(resolve, milliseconds);
    signal?.addEventListener("abort", () => {
      window.clearTimeout(timer);
      reject(new DOMException("Aborted", "AbortError"));
    }, { once: true });
  });
}

function scenarioState(id) {
  return {
    healthy: "healthy",
    degraded: "degraded",
    action: "action_required",
    failed: "unavailable",
  }[id] || "ready";
}

function clonePolicy(value, fallback) {
  return { ...fallback, ...(value && typeof value === "object" ? value : {}) };
}

export function createFixtureFailoverClient() {
  let scenarioId = "degraded";
  let runtimeOverride = null;
  let emptyCreated = false;
  let selectedGroupId = "a1000000000000000000000000000001";
  let groups = [{
    id: selectedGroupId,
    name: "默认容灾组",
    enabled: true,
    revision: 7,
    applied_revision: 7,
    primary_profile_id: profileOptions[0].id,
    backup_profile_id: profileOptions[1].id,
    allowed_models: ["gpt-fixture-compatible"],
    breaker_policy: { ...defaultBreakerPolicy },
    probe_policy: { ...defaultProbePolicy },
    created_at: now(),
    updated_at: now(),
  }];

  const client = {
    setScenario(nextScenario) {
      if (nextScenario !== scenarioId) {
        scenarioId = nextScenario;
        runtimeOverride = null;
        if (nextScenario === "empty") emptyCreated = false;
      }
    },

    async getOverview({ groupId, signal } = {}) {
      if (scenarioId === "loading") return abortablePending(signal);
      await delay(signal);
      if (scenarioId === "error") {
        throw new ApiError("无法读取合成线路状态。", {
          code: "fixture_overview_unavailable",
          status: 503,
          retryable: true,
        });
      }

      const visibleGroups = scenarioId === "empty" && !emptyCreated ? [] : groups;
      const requested = groupId && visibleGroups.some((group) => group.id === groupId) ? groupId : null;
      const selected = visibleGroups.find((group) => group.id === (requested || selectedGroupId)) || visibleGroups[0] || null;
      if (selected) selectedGroupId = selected.id;
      const activeScenarioId = runtimeOverride || (scenarioId === "empty" ? "healthy" : scenarioId);
      const runtime = scenarios[activeScenarioId] || scenarios.healthy;
      const overall = scenarioState(activeScenarioId);
      const publicationState = selected?.applied_revision === selected?.revision ? "applied" : "draft";

      const routes = selected ? runtime.routes.map((route, index) => {
        const role = index === 0 ? "primary" : "backup";
        const profileId = role === "primary" ? selected.primary_profile_id : selected.backup_profile_id;
        const profile = profileOptions.find((item) => item.id === profileId) || profileOptions[index];
        const lastStatus = /401/.test(route.lastResult) ? 401
          : /403/.test(route.lastResult) ? 403
            : /429/.test(route.lastResult) ? 429
              : /503|5xx/.test(route.lastResult) ? 503
                : null;
        return {
          role,
          profile_id: profile.id,
          profile_name: profile.name,
          base_host: profile.base_host,
          key_suffix: profile.key_suffix,
          model: profile.model,
          adapter_name: "openai-responses",
          breaker_state: String(route.state || "UNKNOWN").toLowerCase(),
          carrying: Boolean(route.carrying),
          open_until: activeScenarioId === "degraded" && role === "primary"
            ? new Date(Date.now() + 24_000).toISOString()
            : null,
          last_result: {
            category: lastStatus === 401 || lastStatus === 403 ? "auth_rejected"
              : lastStatus === 429 ? "rate_limited"
                : lastStatus && lastStatus >= 500 ? "upstream_5xx"
                  : route.carrying ? "success" : "unknown",
            http_status: lastStatus,
            signal: "business",
            at: now(),
            detail: route.detail,
          },
        };
      }) : [];

      return {
        schema_version: 1,
        source: "fixture",
        collected_at: now(),
        stale: false,
        capabilities: {
          manage_groups: true,
          publish_config: true,
          publish_target: "fixture",
          retest_routes: true,
          activate_provider: false,
          restore_direct: false,
        },
        provider: {
          provider_id: "guardian_gateway",
          activation_state: "not_activated",
        },
        gateway: {
          state: "fixture_running",
          version: "1.7.0-fixture",
          config_revision: selected?.applied_revision || null,
        },
        groups: visibleGroups.map((group) => ({
          id: group.id,
          name: group.name,
          enabled: group.enabled,
          revision: group.revision,
          applied_revision: group.applied_revision,
          publication_state: group.applied_revision === group.revision ? "applied" : "draft",
        })),
        selected_group_id: selected?.id || null,
        profile_options: profileOptions.map((profile) => ({ ...profile })),
        group: selected ? {
          ...selected,
          publication_state: publicationState,
          overall_state: selected.enabled ? overall : "unknown",
          current_carrier: routes.find((route) => route.carrying)?.role || null,
          requires_action: activeScenarioId === "action",
          routes,
          alerts: activeScenarioId === "action" ? [{
            code: "guardian_route_action_required",
            persistent: true,
            route_role: "primary",
            failure_category: "auth_rejected",
            http_status: 401,
            next_action: "请检查 P1 的 Key、分组绑定和模型权限。",
          }] : [],
        } : null,
      };
    },

    async getEvents({ groupId, offset = 0, limit = 20, signal } = {}) {
      await delay(signal, 70);
      if (!groupId || (scenarioId === "empty" && !emptyCreated)) {
        return { items: [], page: { offset, limit, has_more: false } };
      }
      const activeScenarioId = runtimeOverride || (scenarioId === "empty" ? "healthy" : scenarioId);
      const runtime = scenarios[activeScenarioId] || scenarios.healthy;
      const items = (runtime.events || []).map(([kind, title, detail], index) => ({
        event_id: `${groupId}-${activeScenarioId}-${index}`,
        timestamp: new Date(Date.now() - index * 4_000).toISOString(),
        kind,
        title,
        detail,
        route_role: index === 1 ? "primary" : "",
        status: activeScenarioId,
      }));
      return {
        items: items.slice(offset, offset + limit),
        page: { offset, limit, has_more: offset + limit < items.length },
      };
    },

    async getHosts({ signal } = {}) {
      await delay(signal, 60);
      const runtime = runtimeOverride || (scenarioId === "empty" ? "healthy" : scenarioId);
      return {
        schema_version: 1,
        checked_at: now(),
        items: [
          {
            host_key: "local",
            display_name: "Windows 本机",
            kind: "windows",
            online: runtime !== "error",
            stale: runtime === "error",
            checked_at: now(),
            collected_at: now(),
            version: "v1.7.0-fixture",
            config_revision: 7,
            phase: runtime === "error" ? "unavailable" : "running",
            carrier: runtime === "degraded" || runtime === "action" ? "backup" : runtime === "failed" ? null : "primary",
            routes: {
              primary: runtime === "degraded" ? "open_temporary" : runtime === "action" ? "open_action_required" : runtime === "failed" ? "open_temporary" : "closed",
              backup: runtime === "failed" ? "open_temporary" : "closed",
            },
            error_code: runtime === "error" ? "local_gateway_status_unavailable" : null,
          },
          {
            host_key: "fixture-nas",
            display_name: "工作室 NAS",
            kind: "nas",
            online: false,
            stale: true,
            checked_at: now(),
            collected_at: null,
            version: null,
            config_revision: null,
            phase: "unavailable",
            carrier: null,
            routes: { primary: "unknown", backup: "unknown" },
            error_code: "nas_gateway_status_not_collected",
          },
        ],
      };
    },

    async refreshHosts({ signal } = {}) {
      await delay(signal, 180);
      const result = await client.getHosts({ signal });
      result.items[1] = {
        ...result.items[1],
        online: true,
        stale: false,
        collected_at: now(),
        version: "v1.7.0-fixture",
        config_revision: 7,
        phase: "running",
        carrier: "primary",
        routes: { primary: "closed", backup: "closed" },
        error_code: null,
      };
      return result;
    },

    async createGroup(payload) {
      await delay();
      const group = {
        id: fixtureId(),
        name: payload.name,
        enabled: Boolean(payload.enabled),
        revision: 1,
        applied_revision: null,
        primary_profile_id: payload.primary_profile_id,
        backup_profile_id: payload.backup_profile_id,
        allowed_models: payload.allowed_models,
        breaker_policy: clonePolicy(payload.breaker_policy, defaultBreakerPolicy),
        probe_policy: clonePolicy(payload.probe_policy, defaultProbePolicy),
        created_at: now(),
        updated_at: now(),
      };
      groups = [...groups, group];
      selectedGroupId = group.id;
      emptyCreated = true;
      return { group: { ...group }, overview: await client.getOverview({ groupId: group.id }) };
    },

    async editGroup(groupId, payload) {
      await delay();
      const index = groups.findIndex((group) => group.id === groupId);
      if (index < 0) throw new ApiError("找不到该容灾组。", { code: "failover_group_not_found", status: 404 });
      const current = groups[index];
      if (payload.expected_revision !== current.revision) {
        throw new ApiError("配置已更新，请刷新后重试。", { code: "failover_revision_conflict", status: 409 });
      }
      groups[index] = {
        ...current,
        name: payload.name,
        enabled: Boolean(payload.enabled),
        primary_profile_id: payload.primary_profile_id,
        backup_profile_id: payload.backup_profile_id,
        allowed_models: payload.allowed_models,
        breaker_policy: clonePolicy(payload.breaker_policy, current.breaker_policy),
        probe_policy: clonePolicy(payload.probe_policy, current.probe_policy),
        revision: current.revision + 1,
        updated_at: now(),
      };
      return { group: { ...groups[index] }, overview: await client.getOverview({ groupId }) };
    },

    async setGroupEnabled(groupId, enabled, expectedRevision) {
      const current = groups.find((group) => group.id === groupId);
      if (!current) throw new ApiError("找不到该容灾组。", { code: "failover_group_not_found", status: 404 });
      return client.editGroup(groupId, {
        ...current,
        enabled,
        expected_revision: expectedRevision,
      });
    },

    async deleteGroup(groupId, expectedRevision) {
      await delay();
      const current = groups.find((group) => group.id === groupId);
      if (!current) throw new ApiError("找不到该容灾组。", { code: "failover_group_not_found", status: 404 });
      if (expectedRevision !== current.revision) {
        throw new ApiError("配置已更新，请刷新后重试。", { code: "failover_revision_conflict", status: 409 });
      }
      groups = groups.filter((group) => group.id !== groupId);
      selectedGroupId = groups[0]?.id || null;
      return { deleted: groupId, overview: await client.getOverview({ groupId: selectedGroupId }) };
    },

    async publishGroup(groupId, expectedRevision) {
      await delay();
      const group = groups.find((item) => item.id === groupId);
      if (!group) throw new ApiError("找不到该容灾组。", { code: "failover_group_not_found", status: 404 });
      if (expectedRevision !== group.revision) {
        throw new ApiError("配置已更新，请刷新后重试。", { code: "failover_revision_conflict", status: 409 });
      }
      group.applied_revision = group.revision;
      group.updated_at = now();
      return { published_revision: group.revision, overview: await client.getOverview({ groupId }) };
    },

    async retestRoute(groupId, role, expectedRevision) {
      await delay();
      const group = groups.find((item) => item.id === groupId);
      if (!group) throw new ApiError("找不到该容灾组。", { code: "failover_group_not_found", status: 404 });
      if (expectedRevision !== group.revision) {
        throw new ApiError("配置已更新，请刷新后重试。", { code: "failover_revision_conflict", status: 409 });
      }
      if (!["primary", "backup"].includes(role)) {
        throw new ApiError("线路角色无效。", { code: "failover_route_invalid", status: 400 });
      }
      runtimeOverride = "healthy";
      return { tested_role: role, overview: await client.getOverview({ groupId }) };
    },
  };

  return client;
}
