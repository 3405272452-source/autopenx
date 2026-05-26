(function () {
  const el = (id) => document.getElementById(id);
  const stateEls = Array.from(document.querySelectorAll(".state-bar span"));
  const findingsBody = document.querySelector("#findings-table tbody");

  const healthEl = el("health");
  const logEl = el("log");
  const jobMeta = el("job-meta");
  const progressCard = el("progress-card");
  const findingsCard = el("findings-card");
  const reportCard = el("report-card");
  const telemetryStatsEl = el("telemetry-stats");
  const currentToolEl = el("current-tool");
  const phaseTasksEl = el("phase-tasks");
  const artifactListEl = el("artifact-list");
  const settingsStatusEl = el("settings-status");
  const llmChatEl = el("llm-chat");
  const capabilitiesEl = el("capabilities");
  const approvalStatusEl = el("approval-status");

  const settingsForm = el("settings-form");
  const saveSettingsBtn = el("save-settings");
  const scanForm = el("scan-form");
  const submitBtn = scanForm.querySelector("button[type='submit']");

  const state = {
    jobId: null,
    findings: [],
    artifacts: [],
    phaseTasks: {},
    eventSource: null,
    settings: null,
    approvalToken: null,
  };

  // ─── Toast Notifications (defined early for use throughout) ─────────────────
  function showToast(type, message, duration) {
    duration = duration || 3000;
    const container = document.getElementById("toast-container");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    const icons = { success: "✓", error: "✗", info: "ℹ" };
    toast.textContent = `${icons[type] || ""} ${message}`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.animation = "toastOut 0.3s ease-out forwards";
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }
  window.showToast = showToast;

  // ─── Stats Counter (defined early for use throughout) ──────────────────────
  const statsData = JSON.parse(localStorage.getItem("autopenx-stats") || '{"scans":0,"ctfSolved":0,"findings":0,"startTime":0}');
  if (!statsData.startTime) statsData.startTime = Date.now();

  function updateStatsUI() {
    const statScans = document.getElementById("stat-scans");
    const statCtf = document.getElementById("stat-ctf-solved");
    const statFindings = document.getElementById("stat-findings");
    const statUptime = document.getElementById("stat-uptime");
    if (statScans) statScans.textContent = statsData.scans;
    if (statCtf) statCtf.textContent = statsData.ctfSolved;
    if (statFindings) statFindings.textContent = statsData.findings;
    if (statUptime) {
      const elapsed = Math.floor((Date.now() - statsData.startTime) / 1000);
      if (elapsed < 60) statUptime.textContent = elapsed + "s";
      else if (elapsed < 3600) statUptime.textContent = Math.floor(elapsed / 60) + "m";
      else statUptime.textContent = Math.floor(elapsed / 3600) + "h";
    }
  }

  function incrementStat(key, amount) {
    amount = amount || 1;
    statsData[key] = (statsData[key] || 0) + amount;
    localStorage.setItem("autopenx-stats", JSON.stringify(statsData));
    updateStatsUI();
  }

  updateStatsUI();
  setInterval(updateStatsUI, 10000);

  window.toggleCard = function (id) {
    const body = el(id + "-body");
    const header = el(id + "-toggle");
    const chevron = el(id + "-chevron");
    if (!body) return;
    const isOpen = body.classList.contains("open");
    body.classList.toggle("open");
    if (header) header.classList.toggle("open");
    if (chevron) chevron.style.transform = isOpen ? "" : "rotate(180deg)";
  };

  init();

  async function init() {
    await Promise.all([loadHealth(), loadSettings()]);
    bindEvents();
  }

  function bindEvents() {
    settingsForm.addEventListener("submit", saveSettings);
    scanForm.addEventListener("submit", startScan);
  }

  async function loadHealth() {
    try {
      const data = await fetchJson("/api/health");
      if (data.llm_configured) {
        healthEl.textContent = `LLM 在线 · ${data.model}`;
        healthEl.className = "badge badge-online";
      } else {
        healthEl.textContent = "LLM 离线 · Mock 模式";
        healthEl.className = "badge badge-offline";
      }
    } catch (_err) {
      healthEl.textContent = "后端未连接";
      healthEl.className = "badge badge-offline";
    }
  }

  async function loadSettings() {
    try {
      const data = await fetchJson("/api/settings");
      state.settings = data;
      el("api-key").value = "";
      el("api-key").placeholder = data.has_api_key
        ? `已保存：${data.api_key_preview}`
        : "sk-...";
      el("clear-api-key").checked = false;
      el("base-url").value = data.deepseek_base_url || "";
      el("model").value = data.deepseek_model || "";
      el("burp-proxy-url").value = data.burp_proxy_url || "";
      el("settings-scan-mode").value = data.scan_mode || "active";
      el("settings-external-tools").checked = !!data.allow_external_tools;
      el("settings-allow-local").checked = !!data.allow_local_targets;
      el("settings-exploit-enabled").checked = !!data.exploit_enabled;
      el("scan-external-tools").checked = !!data.allow_external_tools;
      el("scan-allow-local").checked = !!data.allow_local_targets;
      el("scan-exploit-enabled").checked = !!data.exploit_enabled;
      el("scan-mode").value = data.scan_mode || "active";
      renderCapabilities(data.capabilities || []);
      settingsStatusEl.textContent = data.has_api_key
        ? `当前模型：${data.deepseek_model}`
        : "当前未配置 API Key";
      const summary = el("config-summary");
      if (summary) {
        summary.textContent = data.has_api_key
          ? `· ${data.deepseek_model} · ${data.scan_mode}`
          : "· 未配置";
      }
    } catch (err) {
      settingsStatusEl.textContent = `配置读取失败: ${err}`;
      settingsStatusEl.className = "inline-note err";
    }
  }

  async function saveSettings(ev) {
    ev.preventDefault();
    saveSettingsBtn.disabled = true;
    settingsStatusEl.className = "inline-note";
    settingsStatusEl.textContent = "正在保存配置...";

    const apiKey = el("api-key").value.trim();
    const payload = {
      clear_api_key: el("clear-api-key").checked,
      deepseek_base_url: el("base-url").value.trim(),
      deepseek_model: el("model").value.trim(),
      burp_proxy_url: el("burp-proxy-url").value.trim(),
      scan_mode: el("settings-scan-mode").value,
      allow_external_tools: el("settings-external-tools").checked,
      allow_local_targets: el("settings-allow-local").checked,
      exploit_enabled: el("settings-exploit-enabled").checked,
    };
    if (apiKey) {
      payload.api_key = apiKey;
    }

    try {
      const data = await fetchJson("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      state.settings = data;
      settingsStatusEl.className = "inline-note ok";
      settingsStatusEl.textContent = "配置已保存，并已刷新运行时设置。";
      showToast("success", "配置已保存");
      el("scan-external-tools").checked = !!data.allow_external_tools;
      renderCapabilities(data.capabilities || []);
      await loadHealth();
      await loadSettings();
    } catch (err) {
      settingsStatusEl.className = "inline-note err";
      settingsStatusEl.textContent = `保存失败: ${err}`;
    } finally {
      saveSettingsBtn.disabled = false;
    }
  }

  async function startScan(ev) {
    ev.preventDefault();
    const payload = {
      target: el("target").value.trim(),
      mock: el("mock").checked,
      max_iter: parseInt(el("max-iter").value, 10) || null,
      scan_mode: el("scan-mode").value,
      allow_external_tools: el("scan-external-tools").checked,
      allow_local_targets: el("scan-allow-local").checked,
      exploit_enabled: el("scan-exploit-enabled").checked,
    };
    if (!payload.target) return;

    submitBtn.disabled = true;
    submitBtn.textContent = "扫描中…";
    submitBtn.classList.add("running");
    resetUI();
    showToast("info", "正在启动扫描…");

    try {
      const approvalToken = await ensureApprovalToken(payload);
      if (approvalToken) {
        payload.approval_token = approvalToken;
      }
      const data = await fetchJson("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      state.jobId = data.job_id;
      progressCard.hidden = false;
      jobMeta.textContent = `job=${data.job_id} target=${payload.target}`;
      incrementStat("scans");
      renderTelemetry({
        target: payload.target,
        mode: payload.mock ? "mock" : "llm",
        findings: 0,
        scan_mode: payload.scan_mode,
        external_tools: payload.allow_external_tools ? "enabled" : "disabled",
        exploit: payload.exploit_enabled ? "enabled" : "planned_only",
        local_targets: payload.allow_local_targets ? "allowed" : "blocked",
      });
      subscribe(data.job_id);
    } catch (err) {
      appendLog("err", `提交失败: ${err}`);
      approvalStatusEl.textContent = `审批或启动失败: ${err}`;
      approvalStatusEl.className = "inline-note err";
      submitBtn.disabled = false;
      submitBtn.textContent = "开始扫描";
      submitBtn.classList.remove("running");
      showToast("error", "扫描启动失败");
    }
  }

  function resetUI() {
    logEl.textContent = "";
    findingsBody.innerHTML = "";
    findingsCard.hidden = true;
    reportCard.hidden = true;
    telemetryStatsEl.innerHTML = "";
    currentToolEl.innerHTML = '<div class="kv-empty">等待工具执行...</div>';
    phaseTasksEl.innerHTML = '<div class="kv-empty">等待阶段任务规划...</div>';
    artifactListEl.innerHTML = '<div class="kv-empty">尚无证据产物</div>';
    state.findings = [];
    state.artifacts = [];
    state.phaseTasks = {};
    stateEls.forEach((s) => s.classList.remove("active", "done"));
    llmChatEl.innerHTML = '<div class="kv-empty">等待 LLM 响应…</div>';
  }

  function subscribe(jobId) {
    if (state.eventSource) state.eventSource.close();
    let lastSeq = state.lastSeq || 0;
    let retries = 0;

    function connect() {
      const url = `/api/jobs/${jobId}/events`;
      state.eventSource = new EventSource(url);
      state.eventSource.onmessage = (event) => {
        retries = 0;
        let data;
        try {
          data = JSON.parse(event.data);
        } catch (_err) {
          return;
        }
        if (data.seq) {
          lastSeq = data.seq;
          state.lastSeq = lastSeq;
        }
        handleEvent(data, jobId);
      };
      state.eventSource.onerror = () => {
        if (state.eventSource) state.eventSource.close();
        retries++;
        if (retries > 20) {
          appendLog("err", "SSE 重连失败次数过多，已停止");
          return;
        }
        const delay = Math.min(1000 * Math.pow(2, retries - 1), 16000);
        appendLog("err", `SSE 断线，${delay / 1000}s 后重连...`);
        setTimeout(connect, delay);
      };
    }
    connect();
  }

  async function handleEvent(ev, jobId) {
    const kind = ev.event;
    if (kind === "start") {
      appendLog("state", `▶ 开始扫描 ${ev.target} mode=${ev.mode}`);
      renderTelemetry({
        target: ev.target,
        mode: ev.mode,
        findings: 0,
        state: ev.state,
        max_iter: ev.max_iter_per_state,
      });
      return;
    }
    if (kind === "job_running") {
      const cfg = ev.config || {};
      renderTelemetry({
        mode: ev.mode,
        model: cfg.deepseek_model || "-",
        scan_mode: cfg.scan_mode || "-",
        external_tools: cfg.allow_external_tools ? "enabled" : "disabled",
        exploit: cfg.exploit_enabled ? "enabled" : "planned_only",
        local_targets: cfg.allow_local_targets ? "allowed" : "blocked",
        http_timeout: cfg.http_timeout || "-",
      });
      appendLog("state", `作业线程已启动，当前模式=${ev.mode}`);
      return;
    }
    if (kind === "phase_tasks_synced") {
      state.phaseTasks[ev.phase || ev.state] = ev.tasks || [];
      renderPhaseTasks();
      appendLog("state", `  已同步 ${(ev.tasks || []).length} 条阶段任务`);
      return;
    }
    if (kind === "approval_required") {
      approvalStatusEl.className = "inline-note err";
      approvalStatusEl.textContent = `当前运行缺少 ${ev.required_capability} 授权，exploit 将只生成计划不执行。`;
      appendLog("err", approvalStatusEl.textContent);
      return;
    }
    if (kind === "exploit_planned") {
      appendLog("tool", `  已生成 ${(ev.tasks || []).length} 条 exploit 计划`);
      return;
    }
    if (kind === "state_enter") {
      stateEls.forEach((s) => {
        if (s.dataset.state === ev.state) s.classList.add("active");
      });
      appendLog("state", `\n── ${ev.state} ──`);
      renderTelemetry({ state: ev.state });
      return;
    }
    if (kind === "state_exit") {
      stateEls.forEach((s) => {
        if (s.dataset.state === ev.state) {
          s.classList.remove("active");
          s.classList.add("done");
        }
      });
      return;
    }
    if (kind === "tool_start") {
      renderCurrentTool({
        name: ev.tool,
        status: "running",
        iteration: ev.iteration,
        task_ref: ev.task_ref,
        args: JSON.stringify(ev.arguments || {}),
      });
      appendLog("tool", `  [${ev.state}#${ev.iteration}] → ${ev.tool} ${JSON.stringify(ev.arguments || {})}`);
      return;
    }
    if (kind === "tool_finish") {
      renderCurrentTool({
        name: ev.tool,
        status: ev.success ? "ok" : "error",
        iteration: ev.iteration,
        duration: `${ev.duration_ms || 0} ms`,
        summary: ev.summary || "-",
        raw: ev.raw_output_excerpt || "",
      });
      appendLog(ev.success ? "ok" : "err", `    = ${ev.summary || ""}`);
      if (ev.raw_output_excerpt) {
        appendLog("", `    raw: ${(ev.raw_output_excerpt || "").slice(0, 240)}`);
      }
      return;
    }
    if (kind === "tool_error") {
      appendLog("err", `  [${ev.state}#${ev.iteration}] ${ev.tool} 失败: ${ev.error || ev.summary}`);
      return;
    }
    if (kind === "react_step") {
      if (!ev.tool) {
        appendLog("", `  [${ev.state}#${ev.iteration}] ${ev.action}: ${(ev.reasoning || "").slice(0, 220)}`);
      }
      renderTelemetry({
        state: ev.state,
        findings: ev.findings_count,
        last_tool: ev.tool || "-",
        last_duration: ev.tool_duration_ms ? `${ev.tool_duration_ms} ms` : "-",
        new_findings: ev.new_findings_count || 0,
      });
      if (ev.decision_error) {
        appendLog("err", `  决策被拒绝: ${ev.decision_error}`);
      }
      return;
    }
    if (kind === "finding_update") {
      mergeFindings(ev.new_findings || []);
      renderTelemetry({
        findings: ev.findings_count || state.findings.length,
        new_findings: (ev.new_findings || []).length,
      });
      appendLog("ok", `  新增结果 ${String((ev.new_findings || []).length)} 条`);
      incrementStat("findings", (ev.new_findings || []).length);
      return;
    }
    if (kind === "finding_confirmed" || kind === "finding_status_changed") {
      mergeFindings([ev.finding]);
      appendLog("ok", `  条目状态更新: ${(ev.finding || {}).title || "-"} -> ${(ev.finding || {}).status || "-"}`);
      return;
    }
    if (kind === "artifact_ingested") {
      addArtifact(ev.artifact);
      appendLog("tool", `  证据产物入库: ${(ev.artifact || {}).tool || "-"} / ${(ev.artifact || {}).kind || "-"}`);
      return;
    }
    if (kind === "performance_snapshot") {
      renderTelemetry({
        total_invocations: ev.total_invocations,
        avg_ms: ev.average_duration_ms,
        artifacts: ev.artifact_count,
      });
      return;
    }
    if (kind === "llm_response") {
      renderLLMMessage(ev);
      return;
    }
    if (kind === "report_generating") {
      stateEls.forEach((s) => {
        if (s.dataset.state === "REPORT") s.classList.add("active");
      });
      appendLog("state", `\n⏳ ${ev.message || "正在生成渗透测试报告..."}`);
      renderTelemetry({ state: "REPORT" });
      return;
    }
    if (kind === "done") {
      stateEls.forEach((s) => {
        if (s.dataset.state === "DONE") s.classList.add("done", "active");
      });
      appendLog("ok", "\n✔ 扫描完成");
      submitBtn.classList.remove("running");
      showToast("success", "扫描完成！");
      return;
    }
    if (kind === "job_done") {
      await renderReport(jobId);
      return;
    }
    if (kind === "job_error") {
      appendLog("err", `✘ 扫描失败: ${ev.error}`);
      submitBtn.disabled = false;
      submitBtn.textContent = "开始扫描";
      return;
    }
    if (kind === "stream_close") {
      appendLog("state", `SSE 已结束，状态=${ev.status}`);
    }
  }

  async function renderReport(jobId) {
    try {
      const data = await fetchJson(`/api/jobs/${jobId}`);
      renderFindings(data.findings || []);
      renderTelemetry({
        findings: data.findings_count || 0,
        mode: data.mode,
      });
      state.artifacts = data.evidence_artifacts || [];
      state.phaseTasks = data.phase_tasks || state.phaseTasks;
      renderArtifacts();
      renderPhaseTasks();
      reportCard.hidden = false;
      el("md-link").href = `/api/jobs/${jobId}/report`;
      el("html-link").href = `/api/jobs/${jobId}/report.html`;
      el("report-frame").src = `/api/jobs/${jobId}/report.html`;
    } catch (err) {
      appendLog("err", `读取结果失败: ${err}`);
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "开始扫描";
    }
  }

  function renderTelemetry(patch) {
    const current = {
      target: readTelemetryValue("target"),
      mode: readTelemetryValue("mode"),
      model: readTelemetryValue("model"),
      scan_mode: readTelemetryValue("scan_mode"),
      state: readTelemetryValue("state"),
      findings: readTelemetryValue("findings"),
      last_tool: readTelemetryValue("last_tool"),
      last_duration: readTelemetryValue("last_duration"),
      new_findings: readTelemetryValue("new_findings"),
      external_tools: readTelemetryValue("external_tools"),
      exploit: readTelemetryValue("exploit"),
      local_targets: readTelemetryValue("local_targets"),
      total_invocations: readTelemetryValue("total_invocations"),
      avg_ms: readTelemetryValue("avg_ms"),
      artifacts: readTelemetryValue("artifacts"),
      http_timeout: readTelemetryValue("http_timeout"),
      ...patch,
    };
    telemetryStatsEl.innerHTML = "";
    Object.entries(current).forEach(([key, value]) => {
      if (value === undefined || value === null || value === "") return;
      const item = document.createElement("div");
      item.className = "kv-item";
      item.dataset.key = key;
      item.innerHTML = `<span>${escapeHtml(key)}</span><strong>${escapeHtml(String(value))}</strong>`;
      telemetryStatsEl.appendChild(item);
    });
  }

  function readTelemetryValue(key) {
    const node = telemetryStatsEl.querySelector(`[data-key="${key}"] strong`);
    return node ? node.textContent : "";
  }

  function renderCurrentTool(tool) {
    const shortEntries = [
      ["name", tool.name],
      ["status", tool.status],
      ["iteration", tool.iteration],
      ["task_ref", tool.task_ref],
      ["duration", tool.duration],
      ["summary", tool.summary],
      ["args", tool.args],
    ].filter(([, value]) => value);

    currentToolEl.innerHTML = "";
    if (!shortEntries.length) {
      currentToolEl.innerHTML = '<div class="kv-empty">等待工具执行...</div>';
      return;
    }
    shortEntries.forEach(([key, value]) => {
      const item = document.createElement("div");
      item.className = "kv-item";
      item.innerHTML = `<span>${escapeHtml(key)}</span><strong>${escapeHtml(String(value))}</strong>`;
      currentToolEl.appendChild(item);
    });
    if (tool.raw) {
      const details = document.createElement("details");
      details.className = "tool-raw-details";
      details.innerHTML = `<summary>展开原始输出 (${tool.raw.length} chars)</summary><pre class="tool-raw-pre">${escapeHtml(tool.raw)}</pre>`;
      currentToolEl.appendChild(details);
    }
  }

  function renderCapabilities(list) {
    capabilitiesEl.innerHTML = "";
    if (!list.length) {
      capabilitiesEl.innerHTML = '<span class="capability capability-missing">未检测到外部工具适配器</span>';
      return;
    }
    list.forEach((cap) => {
      const badge = document.createElement("div");
      badge.className = `capability ${cap.enabled ? "capability-ok" : "capability-missing"}`;
      const status = cap.enabled ? "enabled" : cap.installed ? "installed but disabled" : "missing";
      badge.innerHTML = `
        <strong>${escapeHtml(cap.name)}</strong>
        <span>${escapeHtml(status)}</span>
        <code>${escapeHtml(cap.binary || "-")}</code>
      `;
      capabilitiesEl.appendChild(badge);
    });
  }

  function mergeFindings(list) {
    const keyIndex = new Map();
    state.findings.forEach((f, idx) => keyIndex.set(findingKey(f), idx));
    list.forEach((finding) => {
      const key = findingKey(finding);
      if (keyIndex.has(key)) {
        state.findings[keyIndex.get(key)] = finding;
      } else {
        keyIndex.set(key, state.findings.length);
        state.findings.push(finding);
      }
    });
    renderFindings(state.findings);
  }

  function findingKey(finding) {
    return `${finding.title || ""}|${finding.url || ""}|${finding.parameter || ""}`;
  }

  function renderFindings(list) {
    findingsBody.innerHTML = "";
    if (!list.length) {
      findingsCard.hidden = true;
      return;
    }
    findingsCard.hidden = false;
    list.forEach((f, i) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${i + 1}</td>
        <td class="sev-${(f.severity || "").toUpperCase()}">${escapeHtml(f.severity || "-")}</td>
        <td>${escapeHtml(f.status || "-")}</td>
        <td>${escapeHtml(f.title)}</td>
        <td><code>${escapeHtml(f.url || "-")}</code></td>
        <td><code>${escapeHtml(f.parameter || "-")}</code></td>
      `;
      findingsBody.appendChild(tr);
    });
  }

  function renderPhaseTasks() {
    const phases = Object.entries(state.phaseTasks);
    phaseTasksEl.innerHTML = "";
    if (!phases.length) {
      phaseTasksEl.innerHTML = '<div class="kv-empty">等待阶段任务规划...</div>';
      return;
    }
    phases.forEach(([phase, tasks]) => {
      const block = document.createElement("div");
      block.className = "task-phase";
      block.innerHTML = `<strong>${escapeHtml(phase)}</strong>`;
      (tasks || []).forEach((task) => {
        const item = document.createElement("div");
        item.className = "task-item";
        const status = task.status || "todo";
        item.innerHTML = `
          <span>${escapeHtml(task.title || task.tool)}</span>
          <code data-status="${escapeHtml(status)}">${escapeHtml(status)}</code>
        `;
        block.appendChild(item);
      });
      phaseTasksEl.appendChild(block);
    });
  }

  function addArtifact(artifact) {
    if (!artifact) return;
    const exists = state.artifacts.some((item) => item.artifact_id === artifact.artifact_id);
    if (!exists) {
      state.artifacts.push(artifact);
    }
    renderArtifacts();
  }

  function renderArtifacts() {
    artifactListEl.innerHTML = "";
    if (!state.artifacts.length) {
      artifactListEl.innerHTML = '<div class="kv-empty">尚无证据产物</div>';
      return;
    }
    state.artifacts.slice(-20).forEach((artifact) => {
      const item = document.createElement("div");
      item.className = "artifact-item";
      item.innerHTML = `
        <strong>${escapeHtml(artifact.tool || "-")}</strong>
        <span>${escapeHtml(artifact.kind || "-")}</span>
        <code>${escapeHtml(artifact.summary || "-")}</code>
      `;
      artifactListEl.appendChild(item);
    });
  }

  async function ensureApprovalToken(payload) {
    const scopes = collectRequestedScopes(payload);
    if (!scopes.length || (scopes.length === 1 && scopes[0] === "passive")) {
      approvalStatusEl.className = "inline-note";
      approvalStatusEl.textContent = "当前仅申请 passive 能力，不生成额外审批令牌。";
      state.approvalToken = null;
      return null;
    }
    approvalStatusEl.className = "inline-note";
    approvalStatusEl.textContent = `正在申请审批令牌：${scopes.join(", ")}`;
    const data = await fetchJson("/api/approvals", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: payload.target,
        scopes,
      }),
    });
    state.approvalToken = data.token;
    approvalStatusEl.className = "inline-note ok";
    approvalStatusEl.textContent = `审批令牌已签发，范围：${(data.scopes || []).join(", ")}，到期时间：${data.expires_at}`;
    return data.token;
  }

  function collectRequestedScopes(payload) {
    const selected = [];
    if (el("scope-passive").checked) selected.push("passive");
    if (el("scope-active").checked || payload.scan_mode === "active" || payload.allow_external_tools) selected.push("active_scan");
    if (el("scope-auth").checked) selected.push("auth_required");
    if (el("scope-exploit").checked || payload.exploit_enabled) selected.push("exploit");
    return Array.from(new Set(selected));
  }

  function renderLLMMessage(ev) {
    if (llmChatEl.querySelector(".kv-empty")) {
      llmChatEl.innerHTML = "";
    }
    const phase = ev.state || "";
    const iter = ev.iteration || "";
    const reasoning = (ev.reasoning_content || "").trim();
    const content = (ev.content || "").trim();
    const tools = ev.tool_calls || [];
    const usage = ev.usage || {};

    if (reasoning) {
      const block = document.createElement("div");
      block.className = "llm-msg llm-msg-thinking";
      block.innerHTML =
        `<div class="llm-msg-header"><span class="llm-tag">思考摘要</span><span>${escapeHtml(phase)} #${iter}</span></div>` +
        `<div class="llm-msg-body">${escapeHtml(reasoning)}</div>`;
      llmChatEl.appendChild(block);
    }

    if (content || tools.length) {
      const block = document.createElement("div");
      block.className = "llm-msg llm-msg-content";
      let html =
        `<div class="llm-msg-header"><span class="llm-tag">ASSISTANT</span><span>${escapeHtml(phase)} #${iter}</span></div>`;
      if (content) {
        html += `<div class="llm-msg-body">${escapeHtml(content)}</div>`;
      }
      if (tools.length) {
        const toolHtml = tools.map((tc) =>
          `<code>${escapeHtml(tc.name)}</code>`
        ).join(" ");
        html += `<div class="llm-msg-tools">调用工具: ${toolHtml}</div>`;
      }
      if (usage.prompt_tokens || usage.completion_tokens) {
        html += `<div class="llm-msg-usage">tokens: ${usage.prompt_tokens || 0} → ${usage.completion_tokens || 0}</div>`;
      }
      block.innerHTML = html;
      llmChatEl.appendChild(block);
    }

    llmChatEl.scrollTop = llmChatEl.scrollHeight;
  }

  function appendLog(cls, msg) {
    const line = document.createElement("span");
    line.className = cls || "";
    line.textContent = msg + "\n";
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
  }

  async function fetchJson(url, options) {
    const res = await fetch(url, options);
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    return res.json();
  }

  function escapeHtml(value) {
    return String(value || "").replace(/[&<>\"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[c]));
  }

  // ─── CTF Mode ───────────────────────────────────────────────────────────────

  const ctfState = {
    uploadedFiles: [],
    tools: [],
    enabledTools: [],
    jobId: null,
    eventSource: null,
  };

  // Initialize CTF mode
  initCTF();

  async function initCTF() {
    setupDropzone();
    await loadCTFTools();
  }

  function setupDropzone() {
    const dropzone = document.getElementById("ctf-dropzone");
    const fileInput = document.getElementById("ctf-file-input");
    if (!dropzone || !fileInput) return;

    dropzone.addEventListener("click", () => fileInput.click());

    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => {
      dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      const files = e.dataTransfer.files;
      if (files.length) uploadFiles(files);
    });

    fileInput.addEventListener("change", () => {
      if (fileInput.files.length) uploadFiles(fileInput.files);
      fileInput.value = "";
    });
  }

  async function uploadFiles(files) {
    for (const file of files) {
      const formData = new FormData();
      formData.append("file", file);
      try {
        const res = await fetch("/api/ctf/upload", { method: "POST", body: formData });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        ctfState.uploadedFiles.push(data);
        renderCTFFiles();
      } catch (err) {
        ctfAppendLog("error", `上传失败: ${file.name} - ${err}`);
      }
    }
  }

  function renderCTFFiles() {
    const container = document.getElementById("ctf-file-list");
    if (!container) return;
    container.innerHTML = "";
    ctfState.uploadedFiles.forEach((f, idx) => {
      const item = document.createElement("div");
      item.className = "ctf-file-item";
      item.innerHTML = `
        <div class="ctf-file-info">
          <span class="ctf-file-type">${escapeHtml(f.file_type)}</span>
          <span>${escapeHtml(f.filename)}</span>
          <span class="ctf-file-size">${formatSize(f.size)}</span>
        </div>
        <span class="ctf-file-remove" onclick="window.removeCTFFile(${idx})">✕</span>
      `;
      container.appendChild(item);
    });
  }

  window.removeCTFFile = function (idx) {
    ctfState.uploadedFiles.splice(idx, 1);
    renderCTFFiles();
  };

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }

  async function loadCTFTools() {
    const panel = document.getElementById("ctf-tools-panel");
    if (!panel) return;
    panel.innerHTML = '<span class="inline-note">正在加载工具列表...</span>';
    try {
      const res = await fetch("/api/ctf/tools");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      ctfState.tools = data.tools || [];
      // Default: enable all available tools
      ctfState.enabledTools = ctfState.tools.filter((t) => t.available).map((t) => t.name);
      renderCTFTools();
    } catch (err) {
      panel.innerHTML = `<span class="inline-note err">工具加载失败: ${escapeHtml(String(err))}</span><br><button class="btn btn-secondary" onclick="window.reloadCTFTools()">重试</button>`;
    }
  }

  window.reloadCTFTools = function() {
    loadCTFTools();
  };

  function renderCTFTools() {
    const panel = document.getElementById("ctf-tools-panel");
    if (!panel) return;
    panel.innerHTML = "";

    // Group by category
    const categories = {};
    ctfState.tools.forEach((tool) => {
      if (!categories[tool.category]) categories[tool.category] = [];
      categories[tool.category].push(tool);
    });

    Object.entries(categories).forEach(([category, tools]) => {
      const catDiv = document.createElement("div");
      catDiv.className = "ctf-tool-category";
      catDiv.innerHTML = `<div class="ctf-tool-category-header">${escapeHtml(category)}</div>`;

      const grid = document.createElement("div");
      grid.className = "ctf-tool-grid";

      tools.forEach((tool) => {
        const checked = ctfState.enabledTools.includes(tool.name);
        const item = document.createElement("label");
        item.className = "ctf-tool-item";
        item.innerHTML = `
          <input type="checkbox" ${checked ? "checked" : ""} data-tool="${escapeHtml(tool.name)}" onchange="window.toggleCTFTool('${escapeHtml(tool.name)}', this.checked)" />
          <span class="ctf-tool-status ${tool.available ? "available" : "unavailable"}"></span>
          <span class="ctf-tool-name">${escapeHtml(tool.name)}</span>
          <span class="ctf-tool-desc">${escapeHtml(tool.description)}</span>
        `;
        grid.appendChild(item);
      });

      catDiv.appendChild(grid);
      panel.appendChild(catDiv);
    });
  }

  window.toggleCTFTool = function (name, enabled) {
    if (enabled && !ctfState.enabledTools.includes(name)) {
      ctfState.enabledTools.push(name);
    } else if (!enabled) {
      ctfState.enabledTools = ctfState.enabledTools.filter((t) => t !== name);
    }
  };

  window.startCTFSolve = async function () {
    const target = (document.getElementById("ctf-target") || {}).value || "";
    if (!target.trim()) {
      alert("请输入目标地址");
      return;
    }

    const solveBtn = document.getElementById("ctf-solve-btn");
    solveBtn.disabled = true;
    solveBtn.textContent = "解题中…";

    // Show results area
    const resultsArea = document.getElementById("ctf-results");
    resultsArea.hidden = false;

    // Reset results
    const flagResult = document.getElementById("ctf-flag-result");
    flagResult.hidden = true;
    document.getElementById("ctf-thinking-content").textContent = "";
    document.getElementById("ctf-solve-log").innerHTML = "";
    document.getElementById("ctf-progress-fill").style.width = "10%";
    document.getElementById("ctf-progress-text").textContent = "正在连接 LLM，开始解题…";

    const challengeType = document.getElementById("ctf-challenge-type").value;
    const flagFormat = document.getElementById("ctf-flag-format").value || "flag{...}";
    const maxAttempts = parseInt(document.getElementById("ctf-max-attempts").value, 10) || 10;
    const timeout = parseInt(document.getElementById("ctf-timeout").value, 10) || 600;
    const thinkingMode = document.getElementById("ctf-thinking-mode").checked;

    const payload = {
      target: target.trim().startsWith("http") ? target.trim() : "http://" + target.trim(),
      challenge_type: challengeType === "auto" ? null : challengeType,
      flag_format: flagFormat,
      files: ctfState.uploadedFiles.map((f) => f.path),
      enabled_tools: ctfState.enabledTools,
      max_attempts: maxAttempts,
      timeout: timeout,
      thinking_mode: thinkingMode,
      scan_mode: (state.settings && state.settings.scan_mode) || "active",
      allow_external_tools: !!(state.settings && state.settings.allow_external_tools),
      allow_local_targets: !!(state.settings && state.settings.allow_local_targets),
      exploit_enabled: !!(state.settings && state.settings.exploit_enabled),
    };

    ctfAppendLog("info", "正在调用 DeepSeek v4-pro (Thinking Max)...");
    ctfAppendLog("info", "目标: " + target.trim());
    document.getElementById("ctf-progress-fill").style.width = "20%";
    document.getElementById("ctf-progress-text").textContent = "LLM 推理中（可能需要 1-3 分钟）…";

    try {
      const approvalToken = await ensureApprovalToken(payload);
      if (approvalToken) {
        payload.approval_token = approvalToken;
      }
      const data = await streamCTFSolve(payload);

      // Handle the direct result from the synchronous API
      document.getElementById("ctf-progress-fill").style.width = "100%";

      if (data.success && data.flag) {
        flagResult.hidden = false;
        flagResult.className = "ctf-flag-result success";
        flagResult.textContent = "🎉 Flag: " + data.flag;
        document.getElementById("ctf-progress-text").textContent = "解题成功!";
        ctfAppendLog("success", "成功! Flag: " + data.flag);
        incrementStat("ctfSolved");
        showToast("success", "CTF 解题成功！");
      } else {
        flagResult.hidden = false;
        flagResult.className = "ctf-flag-result failure";
        flagResult.textContent = "❌ 未找到 Flag" + (data.error ? " (" + data.error + ")" : "");
        document.getElementById("ctf-progress-text").textContent = "解题结束 (" + (data.error || "未找到flag") + ")";
        ctfAppendLog("error", "失败: " + (data.error || "未找到flag"));
      }

      // Show reasoning
      if (data.reasoning) {
        document.getElementById("ctf-thinking-content").textContent = data.reasoning;
      }

      // Show steps
      if (data.steps && data.steps.length > 0) {
        data.steps.forEach(function(step, idx) {
          var tool = step.tool || "N/A";
          var args = JSON.stringify(step.args || {}).substring(0, 100);
          var preview = (step.result_preview || "").substring(0, 150);
          ctfAppendLog("info", "[" + (idx+1) + "] " + tool + "(" + args + ")");
          if (preview) ctfAppendLog("info", "    → " + preview);
        });
      }

      // Show duration
      if (data.duration_ms) {
        ctfAppendLog("info", "耗时: " + (data.duration_ms / 1000).toFixed(1) + "s, 迭代: " + (data.iterations || 0) + " 步");
      }

    } catch (err) {
      document.getElementById("ctf-progress-fill").style.width = "100%";
      document.getElementById("ctf-progress-text").textContent = "出错";
      ctfAppendLog("error", "请求失败: " + err);
      flagResult.hidden = false;
      flagResult.className = "ctf-flag-result failure";
      flagResult.textContent = "❌ 请求失败: " + err.message;
    }

    solveBtn.disabled = false;
    solveBtn.textContent = "🏁 开始解题";
  };

  async function streamCTFSolve(payload) {
    const res = await fetch("/api/ctf/solve/events", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`HTTP ${res.status}: ${errText}`);
    }
    if (!res.body) {
      throw new Error("浏览器不支持流式响应");
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";
    let finalResult = null;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() || "";
      for (const part of parts) {
        const dataLine = part.split("\n").find((line) => line.startsWith("data: "));
        if (!dataLine) continue;
        const ev = JSON.parse(dataLine.slice(6));
        const result = handleCTFStreamEvent(ev);
        if (result) finalResult = result;
      }
    }
    return finalResult || { success: false, error: "流式解题结束但没有返回结果", steps: [] };
  }

  function handleCTFStreamEvent(ev) {
    if (ev.event === "ctf_start") {
      ctfAppendLog("info", `🚀 启动 CTF Agent，工具: ${(ev.enabled_tools || []).join(", ")}`);
      document.getElementById("ctf-progress-fill").style.width = "10%";
      document.getElementById("ctf-progress-text").textContent = "已启动，正在分析目标…";
    } else if (ev.event === "ctf_iteration_start") {
      const phase = ev.phase || "";
      const phaseLabel = phase === "deterministic" ? "🔧 状态机探测" : "🧠 AI 推理";
      ctfAppendLog("info", `${phaseLabel} 第 ${ev.iteration}/${ev.max_iterations} 轮`);
      const pct = Math.min(90, 15 + Math.round((ev.iteration / Math.max(ev.max_iterations || 1, 1)) * 70));
      document.getElementById("ctf-progress-fill").style.width = pct + "%";
      document.getElementById("ctf-progress-text").textContent = `${phaseLabel}：第 ${ev.iteration} 轮`;
    } else if (ev.event === "ctf_llm_response") {
      if (ev.reasoning_content) {
        const thinking = document.getElementById("ctf-thinking-content");
        thinking.textContent += `\n\n[第 ${ev.iteration} 轮思考摘要]\n${ev.reasoning_content}`;
        thinking.scrollTop = thinking.scrollHeight;
        document.getElementById("ctf-thinking-section").removeAttribute("hidden");
      }
      if (ev.content) {
        ctfAppendLog("info", `💭 [第 ${ev.iteration} 轮分析] ${ev.content.slice(0, 400)}`);
      }
      (ev.tool_calls || []).forEach((call) => {
        ctfAppendLog("info", `📋 计划调用: ${call.name}(${String(call.arguments || "").slice(0, 150)})`);
      });
    } else if (ev.event === "ctf_tool_start") {
      ctfAppendLog("info", `🔧 执行: ${ev.tool}(${JSON.stringify(ev.arguments || {}).slice(0, 200)})`);
    } else if (ev.event === "ctf_tool_finish") {
      const preview = String(ev.result_preview || "").slice(0, 400);
      const hasFlag = preview.toLowerCase().includes("flag{");
      ctfAppendLog(hasFlag ? "success" : "info", `${hasFlag ? "🎯" : "📄"} ${ev.tool} → ${preview}`);
    } else if (ev.event === "ctf_evidence_card") {
      ctfAppendLog("info", `📊 证据: ${ev.summary || ev.route || ""} (score=${ev.score || "?"})`);
    } else if (ev.event === "ctf_helper_triggered") {
      ctfAppendLog("info", `⚡ 辅助工具: ${ev.helper} @ ${(ev.url || "").slice(0, 60)}`);
    } else if (ev.event === "ctf_fuse_triggered") {
      ctfAppendLog("info", `⚠️ 熔断: ${ev.level} — ${(ev.reason || "").slice(0, 80)}`);
    } else if (ev.event === "ctf_phase_transition") {
      const phaseNames = { phase1: "状态机探测", phase2: "并行AI攻击", phase3: "深度推理" };
      ctfAppendLog("info", `🔄 阶段切换: ${phaseNames[ev.to_phase] || ev.to_phase} — ${ev.reason || ""}`);
      document.getElementById("ctf-progress-text").textContent = `${phaseNames[ev.to_phase] || ev.to_phase}`;
    } else if (ev.event === "ctf_scan_result") {
      ctfAppendLog("info", `🔎 并行扫描完成: ${ev.routes_scanned || 0} 路线, ${ev.above_threshold || 0} 可行`);
      if (ev.top_routes) {
        ev.top_routes.forEach(r => {
          ctfAppendLog("info", `   📊 ${r.route}: score=${r.score}`);
        });
      }
    } else if (ev.event === "ctf_worker_assigned") {
      ctfAppendLog("info", `👷 Worker ${ev.worker_id}: ${ev.route}${ev.variant !== "default" ? " (" + ev.variant + ")" : ""}`);
    } else if (ev.event === "ctf_tool_unlocked") {
      ctfAppendLog("info", `🔓 动态解锁: ${ev.tool} (Worker ${ev.worker_id})`);
    } else if (ev.event === "ctf_knowledge_match") {
      ctfAppendLog("info", `💡 历史经验匹配: ${ev.route} — ${ev.scenario || ""}`);
    } else if (ev.event === "ctf_flag_candidate") {
      ctfAppendLog("success", `🏁 发现 Flag 候选: ${ev.flag}`);
    } else if (ev.event === "ctf_done") {
      return ev;
    } else if (ev.event === "ctf_complete") {
      return ev.result;
    } else if (ev.event === "ctf_error") {
      ctfAppendLog("error", `❌ ${ev.error || "CTF 解题出错"}`);
      return { success: false, error: ev.error, steps: [] };
    }
    return null;
  }

  function ctfAppendLog(type, msg) {
    const log = document.getElementById("ctf-solve-log");
    if (!log) return;
    const entry = document.createElement("div");
    let cls = "ctf-log-entry";
    if (type === "success") cls += " ctf-log-success";
    if (type === "error") cls += " ctf-log-error";
    entry.className = cls;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
  }

  // ─── Browser Login Helper ──────────────────────────────────────────────────

  // Global state for captured login cookies
  const loginState = {
    cookies: [],
    sessionCookie: "",
    allHeaders: {},
    loggedIn: false,
  };

  window.browserLogin = async function (section) {
    // Determine which target input to use
    let targetInput;
    let btn;
    if (section === "ctf") {
      targetInput = document.getElementById("ctf-target");
      btn = document.getElementById("ctf-browser-login-btn");
    } else {
      targetInput = document.getElementById("target");
      btn = document.getElementById("scan-browser-login-btn");
    }

    const targetUrl = (targetInput && targetInput.value || "").trim();
    if (!targetUrl) {
      alert("请先输入目标 URL");
      return;
    }

    // Validate URL
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      alert("目标 URL 必须以 http:// 或 https:// 开头");
      return;
    }

    // Update button state
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = "⏳ 等待登录…";

    try {
      const res = await fetch("/api/browser-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: targetUrl,
          wait_timeout: 300,
        }),
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const data = await res.json();

      if (data.success) {
        loginState.cookies = data.cookies || [];
        loginState.sessionCookie = data.session_cookie || "";
        loginState.allHeaders = data.all_headers || {};
        loginState.loggedIn = true;

        const cookieCount = data.cookie_count || (data.cookies || []).length;
        btn.textContent = `✅ 已登录 (${cookieCount} cookies)`;
        btn.classList.add("btn-success");

        // Show brief notification
        const elapsed = data.elapsed_seconds || 0;
        alert(`登录成功！\n捕获 ${cookieCount} 个 Cookie\n耗时 ${elapsed} 秒\n\n后续扫描/解题将自动携带这些 Cookie。`);
      } else {
        btn.textContent = originalText;
        alert(`登录失败: ${data.error || "未知错误"}`);
      }
    } catch (err) {
      btn.textContent = originalText;
      alert(`浏览器登录请求失败: ${err}`);
    } finally {
      btn.disabled = false;
    }
  };

  // Expose login state for other parts of the app
  window.getLoginCookies = function () {
    return loginState;
  };

  // ─── Theme Toggle ──────────────────────────────────────────────────────────

  function initTheme() {
    const saved = localStorage.getItem("autopenx-theme") || "dark";
    document.documentElement.setAttribute("data-theme", saved);
    updateThemeIcon(saved);
  }

  function updateThemeIcon(theme) {
    const btn = document.getElementById("theme-toggle");
    if (btn) btn.textContent = theme === "dark" ? "🌙" : "☀️";
  }

  window.toggleTheme = function () {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("autopenx-theme", next);
    updateThemeIcon(next);
    showToast("info", `已切换为${next === "dark" ? "深色" : "浅色"}主题`);
  };

  initTheme();

  // ─── Keyboard Shortcuts ────────────────────────────────────────────────────

  document.addEventListener("keydown", function (e) {
    // Ctrl+Enter: start scan
    if (e.ctrlKey && e.key === "Enter") {
      e.preventDefault();
      const scanBtn = scanForm.querySelector("button[type='submit']");
      if (scanBtn && !scanBtn.disabled) scanBtn.click();
    }
    // Ctrl+K: focus target input
    if (e.ctrlKey && e.key === "k") {
      e.preventDefault();
      const target = el("target");
      if (target) target.focus();
    }
    // Escape: close any open details
    if (e.key === "Escape") {
      document.querySelectorAll("details[open]").forEach((d) => d.removeAttribute("open"));
    }
  });

})();
