const baseRoute = {
  model: "gpt-fixture-compatible",
  baseHost: "api.fixture.invalid",
  keySuffix: "TEST",
  revision: 7,
};

export const scenarios = {
  healthy: {
    label: "主线健康",
    tone: "good",
    headline: "主线路运行正常",
    supporting: "请求由 P1 承载，P2 保持待命。",
    carrying: "P1",
    alert: null,
    routes: [
      { ...baseRoute, id: "P1", name: "主线路样例", role: "配置主线", state: "CLOSED", stateLabel: "健康可用", tone: "good", carrying: true, lastResult: "合成完整成功", detail: "最近业务信号：完整响应" },
      { ...baseRoute, id: "P2", name: "备用线路样例", role: "备用线路", state: "CLOSED", stateLabel: "待命可用", tone: "neutral", carrying: false, lastResult: "暂无实测", detail: "最近探测信号：目录可访问" },
    ],
    events: [
      ["业务", "P1 完整响应", "只在完整终止后向 Codex 提交"],
      ["探测", "P2 目录检查", "探测结果不计入业务错误率"],
      ["配置", "Revision 7 已加载", "固定 provider 仍未切入"],
    ],
  },
  degraded: {
    label: "临时切备",
    tone: "warning",
    headline: "已自动切换到 P2",
    supporting: "P1 因 429 暂停，24 秒后自动复测。",
    carrying: "P2",
    alert: { tone: "warning", title: "临时故障转移", detail: "合成的 429/超时/5xx 场景；冷却结束后进入半开复测。" },
    routes: [
      { ...baseRoute, id: "P1", name: "主线路样例", role: "配置主线", state: "OPEN_TEMPORARY", stateLabel: "临时熔断", tone: "warning", carrying: false, lastResult: "合成 HTTP 429", detail: "冷却倒计时：00:24" },
      { ...baseRoute, id: "P2", name: "备用线路样例", role: "备用线路", state: "CLOSED", stateLabel: "实际承载", tone: "good", carrying: true, lastResult: "合成完整成功", detail: "最近业务信号：完整响应" },
    ],
    events: [
      ["路由", "P2 完整响应", "同一请求快照，仅提交一次"],
      ["熔断", "P1 进入临时冷却", "类别：rate_limited"],
      ["业务", "P1 未向 Codex 提交", "允许 P2 透明重放"],
    ],
  },
  action: {
    label: "需人工处理",
    tone: "danger",
    headline: "P1 需要人工处理",
    supporting: "P2 正在承载，请检查 P1 的 Key 或模型权限。",
    carrying: "P2",
    alert: { tone: "danger", title: "P1 需要人工处理", detail: "合成 HTTP 401。Guardian 不读取完整 Key，也不会自动修改中转站。" },
    routes: [
      { ...baseRoute, id: "P1", name: "主线路样例", role: "配置主线", state: "OPEN_ACTION_REQUIRED", stateLabel: "凭据异常", tone: "danger", carrying: false, lastResult: "合成 HTTP 401", detail: "人工复测前保持红色" },
      { ...baseRoute, id: "P2", name: "备用线路样例", role: "备用线路", state: "CLOSED", stateLabel: "实际承载", tone: "good", carrying: true, lastResult: "合成完整成功", detail: "Key 尾号：••••TEST" },
    ],
    events: [
      ["告警", "P1 action required", "持续告警，不使用短时 Toast"],
      ["路由", "P2 完整响应", "主线失败前提交 0 字节"],
      ["安全", "凭据已脱敏", "页面不含控制令牌"],
    ],
  },
  failed: {
    label: "双线失败",
    tone: "danger",
    headline: "主备线路均不可用",
    supporting: "本轮已明确失败，原任务保持不变。",
    carrying: "无",
    alert: { tone: "danger", title: "没有可承载线路", detail: "合成双线失败；本轮 Codex 收到一次结构化错误，不收到部分模型事件。" },
    routes: [
      { ...baseRoute, id: "P1", name: "主线路样例", role: "配置主线", state: "OPEN_TEMPORARY", stateLabel: "连接失败", tone: "danger", carrying: false, lastResult: "合成连接断开", detail: "本轮提交：0 模型事件" },
      { ...baseRoute, id: "P2", name: "备用线路样例", role: "备用线路", state: "OPEN_TEMPORARY", stateLabel: "上游 5xx", tone: "danger", carrying: false, lastResult: "合成 HTTP 503", detail: "本轮提交：结构化错误" },
    ],
    events: [
      ["失败", "P2 返回 503", "备用只尝试一次"],
      ["失败", "P1 连接断开", "主线未提交任何内容"],
      ["下游", "结构化错误", "原任务和 thread ID 保持"],
    ],
  },
  loading: { label: "加载中", special: "loading" },
  empty: { label: "空状态", special: "empty" },
  error: { label: "读取错误", special: "error" },
};

export const scenarioOrder = ["healthy", "degraded", "action", "failed", "loading", "empty", "error"];

export function scenarioFromLocation() {
  const requested = new URLSearchParams(window.location.search).get("scenario");
  return Object.hasOwn(scenarios, requested) ? requested : "degraded";
}
