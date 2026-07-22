export const overallPresentation = {
  healthy: {
    tone: "good",
    label: "运行正常",
    headline: "主线路运行正常",
    supporting: "请求由 P1 承载，P2 保持待命。",
  },
  ready: {
    tone: "neutral",
    label: "等待请求",
    headline: "线路已就绪",
    supporting: "尚无业务请求，当前承载线路暂未确定。",
  },
  degraded: {
    tone: "warning",
    label: "临时切备",
    headline: "已自动切换到 P2",
    supporting: "P1 正在冷却或恢复探测，后续新请求暂由 P2 承载。",
  },
  action_required: {
    tone: "danger",
    label: "需人工处理",
    headline: "P1 需要人工处理",
    supporting: "P2 可继续承载，请检查 P1 的 Key、分组绑定或模型权限。",
  },
  unavailable: {
    tone: "danger",
    label: "双线失败",
    headline: "主备线路均不可用",
    supporting: "本轮已明确失败，原任务保持不变。",
  },
  unknown: {
    tone: "neutral",
    label: "状态未知",
    headline: "暂时无法确认线路状态",
    supporting: "请刷新状态；过期快照不会显示为健康。",
  },
};

export const breakerPresentation = {
  closed: ["good", "健康可用"],
  unknown: ["neutral", "尚未验证"],
  open_temporary: ["warning", "临时熔断"],
  half_open: ["warning", "恢复探测"],
  open_action_required: ["danger", "需要处理"],
  disabled: ["neutral", "已停用"],
};

export function overallState(value, stale = false) {
  if (stale) return overallPresentation.unknown;
  return overallPresentation[value] || overallPresentation.unknown;
}

export function breakerState(value, carrying = false) {
  if (carrying) return ["good", "正在使用"];
  return breakerPresentation[value] || breakerPresentation.unknown;
}

export function routeLetter(role) {
  return role === "backup" ? "P2" : "P1";
}

export function routeRole(role) {
  return role === "backup" ? "备用线路" : "配置主线";
}

export function formatTimestamp(value, fallback = "尚无记录") {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

export function failureLabel(category, status) {
  if (status) return `HTTP ${status}`;
  const labels = {
    auth_rejected: "凭据或权限异常",
    rate_limited: "请求频率受限",
    upstream_timeout: "上游响应超时",
    upstream_5xx: "上游服务异常",
    network_error: "网络连接失败",
    protocol_error: "响应协议异常",
    success: "完整响应成功",
  };
  return labels[category] || "暂无业务结果";
}

export function nextActionLabel(overview, group) {
  if (overview?.stale) return "刷新状态";
  if (!group?.enabled) return "启用容灾组";
  if (group?.requires_action) return "检查 P1 凭据";
  if (group?.overall_state === "unavailable") return "修复任一线路";
  if (group?.publication_state === "draft") return "发布配置";
  return "无需操作";
}
