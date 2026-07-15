const API_BASE = window.location.port === "5173"
  ? `http://${window.location.hostname || "127.0.0.1"}:8765`
  : "";

let sessionPromise = null;

export class ApiError extends Error {
  constructor(message, { code = "request_failed", status = 0, fieldErrors = null, retryable = false } = {}) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.fieldErrors = fieldErrors;
    this.retryable = retryable;
  }
}

function errorFromPayload(payload, status) {
  const value = payload?.error;
  if (value && typeof value === "object") {
    return new ApiError(value.message || `HTTP ${status}`, {
      code: value.code || "request_failed",
      status,
      fieldErrors: value.field_errors || null,
      retryable: Boolean(value.retryable),
    });
  }
  return new ApiError(typeof value === "string" && value ? value : `HTTP ${status}`, { status });
}

async function establishSession() {
  let response;
  try {
    response = await fetch(`${API_BASE}/api/session`, {
      credentials: "include",
      headers: { Accept: "application/json" },
    });
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    throw new ApiError("无法连接 Guardian 管理服务。", {
      code: "guardian_management_unreachable",
      retryable: true,
    });
  }

  const raw = await response.text();
  let payload = null;
  if (raw) {
    try {
      payload = JSON.parse(raw);
    } catch {
      throw new ApiError("管理服务返回了无法识别的数据。", {
        code: "guardian_management_invalid_response",
        status: response.status,
        retryable: response.status >= 500,
      });
    }
  }
  if (!response.ok || payload?.ok === false) throw errorFromPayload(payload, response.status);
}

async function ensureSession() {
  if (!sessionPromise) {
    sessionPromise = establishSession().catch((error) => {
      sessionPromise = null;
      throw error;
    });
  }
  return sessionPromise;
}

export async function api(path, options = {}) {
  if (path !== "/api/session") await ensureSession();
  const { headers = {}, body, sessionRetry = true, ...requestOptions } = options;
  const requestHeaders = { ...headers };
  if (body !== undefined && !Object.keys(requestHeaders).some((name) => name.toLowerCase() === "content-type")) {
    requestHeaders["Content-Type"] = "application/json";
  }

  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...requestOptions,
      credentials: "include",
      headers: requestHeaders,
      ...(body === undefined ? {} : { body }),
    });
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    throw new ApiError("无法连接 Guardian 管理服务。", {
      code: "guardian_management_unreachable",
      retryable: true,
    });
  }

  const raw = await response.text();
  let payload = null;
  if (raw) {
    try {
      payload = JSON.parse(raw);
    } catch {
      throw new ApiError(response.ok ? "管理服务返回了无法识别的数据。" : `HTTP ${response.status}`, {
        code: "guardian_management_invalid_response",
        status: response.status,
        retryable: response.status >= 500,
      });
    }
  }

  if (
    sessionRetry
    && response.status === 401
    && payload?.error?.code === "guardian_management_session_required"
  ) {
    sessionPromise = null;
    await ensureSession();
    return api(path, { ...options, sessionRetry: false });
  }
  if (!response.ok || payload?.ok === false) throw errorFromPayload(payload, response.status);
  return payload?.ok === true ? payload.data : payload;
}

async function download(path, { sessionRetry = true, signal } = {}) {
  await ensureSession();
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      credentials: "include",
      headers: { Accept: "application/zip, application/json" },
      signal,
    });
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    throw new ApiError("无法连接 Guardian 管理服务。", {
      code: "guardian_management_unreachable",
      retryable: true,
    });
  }
  if (!response.ok) {
    const raw = await response.text();
    let payload = null;
    try {
      payload = raw ? JSON.parse(raw) : null;
    } catch {
      payload = null;
    }
    if (
      sessionRetry
      && response.status === 401
      && payload?.error?.code === "guardian_management_session_required"
    ) {
      sessionPromise = null;
      await ensureSession();
      return download(path, { sessionRetry: false, signal });
    }
    throw errorFromPayload(payload, response.status);
  }
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="([A-Za-z0-9._-]{1,128})"/);
  return {
    blob: await response.blob(),
    filename: match?.[1] || "guardian-diagnostics.zip",
  };
}

function queryPath(path, values) {
  const query = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") query.set(key, String(value));
  });
  const serialized = query.toString();
  return serialized ? `${path}?${serialized}` : path;
}

function jsonMutation(path, method, payload, signal) {
  return api(path, {
    method,
    signal,
    body: JSON.stringify(payload ?? {}),
  });
}

export function createFailoverApiClient(request = api) {
  const mutate = (path, method, payload, signal) => request(path, {
    method,
    signal,
    body: JSON.stringify(payload ?? {}),
  });

  return {
    getOverview({ groupId, signal } = {}) {
      return request(queryPath("/api/failover/overview", { group_id: groupId }), { signal });
    },
    getEvents({ groupId, offset = 0, limit = 20, signal } = {}) {
      return request(queryPath("/api/failover/events", {
        group_id: groupId,
        offset,
        limit,
      }), { signal });
    },
    getHosts({ signal } = {}) {
      return request("/api/failover/hosts", { signal });
    },
    refreshHosts({ signal } = {}) {
      return mutate("/api/failover/hosts/refresh", "POST", {
        confirm_read_only: true,
      }, signal);
    },
    downloadDiagnostics({ signal } = {}) {
      return download("/api/failover/diagnostics", { signal });
    },
    createGroup(payload, { signal } = {}) {
      return mutate("/api/failover/groups", "POST", payload, signal);
    },
    editGroup(groupId, payload, { signal } = {}) {
      return mutate(`/api/failover/groups/${encodeURIComponent(groupId)}/edit`, "POST", payload, signal);
    },
    setGroupEnabled(groupId, enabled, expectedRevision, { signal } = {}) {
      return mutate(`/api/failover/groups/${encodeURIComponent(groupId)}/enabled`, "POST", {
        enabled,
        expected_revision: expectedRevision,
      }, signal);
    },
    deleteGroup(groupId, expectedRevision, { signal } = {}) {
      return mutate(`/api/failover/groups/${encodeURIComponent(groupId)}`, "DELETE", {
        expected_revision: expectedRevision,
      }, signal);
    },
    publishGroup(groupId, expectedRevision, { signal } = {}) {
      return mutate(`/api/failover/groups/${encodeURIComponent(groupId)}/publish`, "POST", {
        expected_revision: expectedRevision,
      }, signal);
    },
    retestRoute(groupId, role, expectedRevision, { signal } = {}) {
      return mutate(
        `/api/failover/groups/${encodeURIComponent(groupId)}/routes/${encodeURIComponent(role)}/retest`,
        "POST",
        { expected_revision: expectedRevision },
        signal,
      );
    },
    activateProvider(expectedRevision, { signal } = {}) {
      return mutate("/api/failover/provider/activate", "POST", {
        expected_revision: expectedRevision,
        confirm: true,
      }, signal);
    },
    restoreDirect({ signal } = {}) {
      return mutate("/api/failover/provider/restore", "POST", {
        confirm: true,
      }, signal);
    },
  };
}

export { jsonMutation };
