const scanForm = document.querySelector("#scanForm");
const scheduleForm = document.querySelector("#scheduleForm");
const targetInput = document.querySelector("#target");
const profileInput = document.querySelector("#profile");
const intervalInput = document.querySelector("#interval");
const runNowInput = document.querySelector("#runNow");
const consoleEl = document.querySelector("#console");
const activeScan = document.querySelector("#activeScan");
const scanStatus = document.querySelector("#scanStatus");
const serviceStatus = document.querySelector("#serviceStatus");
const reportsEl = document.querySelector("#reports");
const schedulesEl = document.querySelector("#schedules");
const refreshReports = document.querySelector("#refreshReports");
const reportSubtitle = document.querySelector("#reportSubtitle");
const reportStatus = document.querySelector("#reportStatus");
const reportContent = document.querySelector("#reportContent");
const tabButtons = document.querySelectorAll("[data-tab]");
const dashboardTab = document.querySelector("#dashboardTab");
const badAgentTab = document.querySelector("#badAgentTab");
const performanceTab = document.querySelector("#performanceTab");
const websiteSecurityTab = document.querySelector("#websiteSecurityTab");
const badAgentForm = document.querySelector("#badAgentForm");
const badAgentTarget = document.querySelector("#badAgentTarget");
const aiEndpoint = document.querySelector("#aiEndpoint");
const aiModel = document.querySelector("#aiModel");
const aiApiKey = document.querySelector("#aiApiKey");
const loadAiModels = document.querySelector("#loadAiModels");
const aiModelStatus = document.querySelector("#aiModelStatus");
const captureRtspFrame = document.querySelector("#captureRtspFrame");
const badAgentActive = document.querySelector("#badAgentActive");
const badAgentStatus = document.querySelector("#badAgentStatus");
const badAgentConsole = document.querySelector("#badAgentConsole");
const badHostsCount = document.querySelector("#badHostsCount");
const badEvidenceCount = document.querySelector("#badEvidenceCount");
const badHighCount = document.querySelector("#badHighCount");
const badOverallStatus = document.querySelector("#badOverallStatus");
const badAgentSubtitle = document.querySelector("#badAgentSubtitle");
const badAgentReportStatus = document.querySelector("#badAgentReportStatus");
const badAgentReport = document.querySelector("#badAgentReport");
const performanceForm = document.querySelector("#performanceForm");
const perfInterface = document.querySelector("#perfInterface");
const perfSampleSeconds = document.querySelector("#perfSampleSeconds");
const runSpeedtest = document.querySelector("#runSpeedtest");
const perfAiEndpoint = document.querySelector("#perfAiEndpoint");
const perfAiModel = document.querySelector("#perfAiModel");
const perfAiApiKey = document.querySelector("#perfAiApiKey");
const loadPerfAiModels = document.querySelector("#loadPerfAiModels");
const perfAiModelStatus = document.querySelector("#perfAiModelStatus");
const performanceActive = document.querySelector("#performanceActive");
const performanceStatus = document.querySelector("#performanceStatus");
const performanceConsole = document.querySelector("#performanceConsole");
const perfBroadcastPps = document.querySelector("#perfBroadcastPps");
const perfTalkers = document.querySelector("#perfTalkers");
const perfDownload = document.querySelector("#perfDownload");
const perfOverallStatus = document.querySelector("#perfOverallStatus");
const performanceSubtitle = document.querySelector("#performanceSubtitle");
const performanceReportStatus = document.querySelector("#performanceReportStatus");
const performanceReport = document.querySelector("#performanceReport");
const websiteSecurityForm = document.querySelector("#websiteSecurityForm");
const websiteUrl = document.querySelector("#websiteUrl");
const websiteAuthorized = document.querySelector("#websiteAuthorized");
const websiteSensitivePaths = document.querySelector("#websiteSensitivePaths");
const webAiEndpoint = document.querySelector("#webAiEndpoint");
const webAiModel = document.querySelector("#webAiModel");
const webAiApiKey = document.querySelector("#webAiApiKey");
const loadWebAiModels = document.querySelector("#loadWebAiModels");
const webAiModelStatus = document.querySelector("#webAiModelStatus");
const websiteActive = document.querySelector("#websiteActive");
const websiteStatus = document.querySelector("#websiteStatus");
const websiteConsole = document.querySelector("#websiteConsole");
const webFindingsCount = document.querySelector("#webFindingsCount");
const webHighCount = document.querySelector("#webHighCount");
const webHttpStatus = document.querySelector("#webHttpStatus");
const webOverallStatus = document.querySelector("#webOverallStatus");
const websiteSubtitle = document.querySelector("#websiteSubtitle");
const websiteReportStatus = document.querySelector("#websiteReportStatus");
const websiteReport = document.querySelector("#websiteReport");
const hostsCount = document.querySelector("#hostsCount");
const portsCount = document.querySelector("#portsCount");
const highCount = document.querySelector("#highCount");
const overallStatus = document.querySelector("#overallStatus");

let activeSource = null;
let activeBadSource = null;
let activePerformanceSource = null;
let activeWebsiteSource = null;

/* ── Severity helpers ───────────────────────────────────── */

const SEV_LABELS = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function sevLabel(sev) {
  return SEV_LABELS[sev] || sev;
}

/* ── Tab switching ──────────────────────────────────────── */

tabButtons.forEach((button) => {
  button.addEventListener("click", () => switchTab(button.dataset.tab));
});

function switchTab(tabName) {
  tabButtons.forEach((button) => button.classList.toggle("active", button.dataset.tab === tabName));
  dashboardTab.classList.toggle("active", tabName === "dashboard");
  badAgentTab.classList.toggle("active", tabName === "badAgent");
  performanceTab.classList.toggle("active", tabName === "performance");
  websiteSecurityTab.classList.toggle("active", tabName === "websiteSecurity");
}

/* ── Event listeners ────────────────────────────────────── */

scanForm.addEventListener("submit", async (event) => { event.preventDefault(); await startScan(); });
scheduleForm.addEventListener("submit", async (event) => { event.preventDefault(); await createSchedule(); });
badAgentForm.addEventListener("submit", async (event) => { event.preventDefault(); await startBadAgent(); });
performanceForm.addEventListener("submit", async (event) => { event.preventDefault(); await startPerformanceAnalysis(); });
websiteSecurityForm.addEventListener("submit", async (event) => { event.preventDefault(); await startWebsiteSecurity(); });
loadAiModels.addEventListener("click", async () => { await loadAvailableAiModels(aiEndpoint, aiApiKey, aiModel, aiModelStatus); });
loadPerfAiModels.addEventListener("click", async () => { await loadAvailableAiModels(perfAiEndpoint, perfAiApiKey, perfAiModel, perfAiModelStatus); });
loadWebAiModels.addEventListener("click", async () => { await loadAvailableAiModels(webAiEndpoint, webAiApiKey, webAiModel, webAiModelStatus); });
refreshReports.addEventListener("click", () => { loadReports(); loadSchedules(); });

/* ── Scan ───────────────────────────────────────────────── */

async function startScan() {
  resetLive();
  setStatus("rodando", "warn");

  const response = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: targetInput.value.trim(), profile: profileInput.value }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Erro desconhecido" }));
    setStatus("erro", "bad");
    addLine("erro", error.detail || "Não foi possível iniciar o scan.");
    return;
  }

  const data = await response.json();
  activeScan.textContent = `Scan ${data.scan_id} em ${targetInput.value.trim()}`;
  streamScan(data.scan_id);
}

function streamScan(scanId) {
  if (activeSource) activeSource.close();
  activeSource = new EventSource(`/api/scans/${scanId}/events`);
  activeSource.onmessage = (event) => handleEvent(JSON.parse(event.data), scanId);
  activeSource.onerror = () => { addLine("stream", "Conexão de eventos encerrada."); activeSource.close(); };
}

function handleEvent(payload, scanId) {
  const event = payload.event || "info";
  const message = payload.message || "";
  addLine(event, message);

  if (event === "host_found") hostsCount.textContent = String(Number(hostsCount.textContent) + 1);

  if (event === "host_scanned" && payload.data?.host) {
    portsCount.textContent = String(Number(portsCount.textContent) + (payload.data.host.open_ports || []).length);
  }

  if (event === "finished") {
    const report = payload.data;
    applySummary(report.summary || {});
    setStatus("concluído", statusClass(report.summary?.overall_status));
    renderReport(report);
    addLine("relatorio", "Relatório visual atualizado.");
    loadReports();
  }

  if (event === "failed") setStatus("falhou", "bad");
}

/* ── Bad Agent ──────────────────────────────────────────── */

async function startBadAgent() {
  resetBadAgent();
  setBadStatus("rodando", "warn");

  const tests = Array.from(document.querySelectorAll('input[name="badTest"]:checked')).map((item) => item.value);
  const response = await fetch("/api/bad-agent", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target: badAgentTarget.value.trim(),
      tests,
      capture_rtsp_frame: captureRtspFrame.checked,
      ai_endpoint: aiEndpoint.value.trim(),
      ai_model: aiModel.value.trim(),
      ai_api_key: aiApiKey.value.trim() || null,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Erro desconhecido" }));
    setBadStatus("erro", "bad");
    addBadLine("erro", error.detail || "Não foi possível iniciar o test_bad_agent.");
    return;
  }

  const data = await response.json();
  badAgentActive.textContent = `Agente ${data.agent_id} em ${badAgentTarget.value.trim()}`;
  streamBadAgent(data.agent_id);
}

function streamBadAgent(agentId) {
  if (activeBadSource) activeBadSource.close();
  activeBadSource = new EventSource(`/api/bad-agent/${agentId}/events`);
  activeBadSource.onmessage = (event) => handleBadAgentEvent(JSON.parse(event.data));
  activeBadSource.onerror = () => { addBadLine("stream", "Conexão de eventos encerrada."); activeBadSource.close(); };
}

function handleBadAgentEvent(payload) {
  const event = payload.event || "info";
  addBadLine(event, payload.message || "");

  if (event === "host_found") badHostsCount.textContent = String(Number(badHostsCount.textContent) + 1);

  if (event === "finished") {
    renderBadAgentReport(payload.data);
    setBadStatus("concluído", statusClass(payload.data.summary?.overall_status));
  }

  if (event === "failed") setBadStatus("falhou", "bad");
}

/* ── Performance ────────────────────────────────────────── */

async function startPerformanceAnalysis() {
  resetPerformance();
  setPerformanceStatus("rodando", "warn");

  const response = await fetch("/api/performance", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      interface: perfInterface.value.trim() || null,
      sample_seconds: Number(perfSampleSeconds.value),
      run_speedtest: runSpeedtest.checked,
      ai_endpoint: perfAiEndpoint.value.trim(),
      ai_model: perfAiModel.value.trim(),
      ai_api_key: perfAiApiKey.value.trim() || null,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Erro desconhecido" }));
    setPerformanceStatus("erro", "bad");
    addPerformanceLine("erro", error.detail || "Não foi possível iniciar a análise.");
    return;
  }

  const data = await response.json();
  performanceActive.textContent = `Análise ${data.analysis_id}`;
  streamPerformance(data.analysis_id);
}

function streamPerformance(analysisId) {
  if (activePerformanceSource) activePerformanceSource.close();
  activePerformanceSource = new EventSource(`/api/performance/${analysisId}/events`);
  activePerformanceSource.onmessage = (event) => handlePerformanceEvent(JSON.parse(event.data));
  activePerformanceSource.onerror = () => { addPerformanceLine("stream", "Conexão de eventos encerrada."); activePerformanceSource.close(); };
}

function handlePerformanceEvent(payload) {
  const event = payload.event || "info";
  addPerformanceLine(event, payload.message || "");

  if (event === "broadcast_done") {
    perfBroadcastPps.textContent = payload.data.packets_per_second ?? "0";
    perfTalkers.textContent = String((payload.data.talkers || []).length);
  }

  if (event === "speedtest_done" && payload.data.status === "ok") {
    perfDownload.textContent = `${payload.data.download_mbps} Mbps`;
  }

  if (event === "finished") {
    renderPerformanceReport(payload.data);
    setPerformanceStatus("concluído", statusClass(payload.data.summary?.overall_status));
  }

  if (event === "failed") setPerformanceStatus("falhou", "bad");
}

/* ── Website Security ──────────────────────────────────── */

async function startWebsiteSecurity() {
  resetWebsiteSecurity();
  setWebsiteStatus("rodando", "warn");

  const response = await fetch("/api/website-security", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: websiteUrl.value.trim(),
      confirm_authorized: websiteAuthorized.checked,
      include_sensitive_paths: websiteSensitivePaths.checked,
      ai_endpoint: webAiEndpoint.value.trim(),
      ai_model: webAiModel.value.trim(),
      ai_api_key: webAiApiKey.value.trim() || null,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Erro desconhecido" }));
    setWebsiteStatus("erro", "bad");
    addWebsiteLine("erro", error.detail || "Não foi possível iniciar o teste de website.");
    return;
  }

  const data = await response.json();
  websiteActive.textContent = `Website scan ${data.scan_id}`;
  streamWebsiteSecurity(data.scan_id);
}

function streamWebsiteSecurity(scanId) {
  if (activeWebsiteSource) activeWebsiteSource.close();
  activeWebsiteSource = new EventSource(`/api/website-security/${scanId}/events`);
  activeWebsiteSource.onmessage = (event) => handleWebsiteEvent(JSON.parse(event.data));
  activeWebsiteSource.onerror = () => { addWebsiteLine("stream", "Conexão de eventos encerrada."); activeWebsiteSource.close(); };
}

function handleWebsiteEvent(payload) {
  const event = payload.event || "info";
  addWebsiteLine(event, payload.message || "");

  if (event === "http_done") {
    webHttpStatus.textContent = payload.data.status || "—";
  }

  if (event === "finished") {
    renderWebsiteReport(payload.data);
    setWebsiteStatus("concluído", statusClass(payload.data.summary?.overall_status));
  }

  if (event === "failed") setWebsiteStatus("falhou", "bad");
}

/* ── AI models ──────────────────────────────────────────── */

async function loadAvailableAiModels(endpointInput, keyInput, modelSelect, statusElement) {
  statusElement.textContent = "Carregando modelos da API…";
  const response = await fetch("/api/ai/models", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ai_endpoint: endpointInput.value.trim(), ai_api_key: keyInput.value.trim() || null }),
  });

  if (!response.ok) {
    const detail = await response.text();
    statusElement.textContent = `Não foi possível carregar. HTTP ${response.status}${detail ? `: ${detail.slice(0, 120)}` : ""}`;
    return;
  }

  const data = await response.json();
  statusElement.textContent = data.message || "Modelos carregados.";
  if (!data.models?.length) return;

  const current = modelSelect.value;
  modelSelect.innerHTML = "";
  for (const model of data.models) {
    const option = document.createElement("option");
    option.value = model;
    option.textContent = model;
    option.selected = model === current;
    modelSelect.appendChild(option);
  }
  if (!modelSelect.value && data.models.includes("gpt-4.1-mini")) modelSelect.value = "gpt-4.1-mini";
}

/* ── Schedules ──────────────────────────────────────────── */

async function createSchedule() {
  const response = await fetch("/api/schedules", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target: targetInput.value.trim(),
      profile: profileInput.value,
      interval_minutes: Number(intervalInput.value),
      run_now: runNowInput.checked,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Erro desconhecido" }));
    addLine("erro", error.detail || "Não foi possível criar agendamento.");
    return;
  }

  const schedule = await response.json();
  addLine("agenda", `Agendamento criado: ${schedule.id}`);
  await loadSchedules();
}

async function loadSchedules() {
  const response = await fetch("/api/schedules");
  if (!response.ok) return;
  const schedules = await response.json();
  schedulesEl.innerHTML = "";

  if (!schedules.length) {
    schedulesEl.innerHTML = '<div class="item"><p>Nenhum agendamento ativo.</p></div>';
    return;
  }

  for (const schedule of schedules) {
    const item = document.createElement("div");
    item.className = "item";
    item.innerHTML = `
      <strong>${escapeHtml(schedule.target)} a cada ${schedule.interval_minutes} min</strong>
      <p>Último scan: ${schedule.last_scan_id || "—"}<br />Próximo: ${formatDate(schedule.next_run_at)}</p>
      <div class="item-actions">
        <button class="secondary" data-remove="${schedule.id}" style="width:auto;padding:5px 10px;font-size:12px">Remover</button>
      </div>
    `;
    schedulesEl.appendChild(item);
  }

  schedulesEl.querySelectorAll("[data-remove]").forEach((button) => {
    button.addEventListener("click", async () => {
      await fetch(`/api/schedules/${button.dataset.remove}`, { method: "DELETE" });
      await loadSchedules();
    });
  });
}

/* ── Reports list ───────────────────────────────────────── */

async function loadReports() {
  const response = await fetch("/api/reports");
  if (!response.ok) {
    reportsEl.innerHTML = '<div class="item"><p>Não foi possível carregar relatórios.</p></div>';
    return;
  }

  const reports = await response.json();
  reportsEl.innerHTML = "";

  if (!reports.length) {
    reportsEl.innerHTML = '<div class="item"><p>Nenhum relatório gerado ainda.</p></div>';
    return;
  }

  for (const report of reports) {
    const counts = report.findings || {};
    const highs = (counts.critical || 0) + (counts.high || 0);
    const item = document.createElement("div");
    item.className = "item";
    item.innerHTML = `
      <strong>${escapeHtml(report.target || "—")} · ${escapeHtml(report.status || "—")}</strong>
      <p>${formatDate(report.finished_at)} · hosts: ${report.hosts ?? 0} · críticos/altos: ${highs}</p>
      <div class="item-actions">
        <button class="secondary" data-view-report="${report.id}" style="width:auto;padding:5px 10px;font-size:12px">Ver painel</button>
        <a href="${report.markdown_url}">Markdown</a>
        <a href="${report.json_url}">JSON</a>
      </div>
    `;
    reportsEl.appendChild(item);
  }

  reportsEl.querySelectorAll("[data-view-report]").forEach((button) => {
    button.addEventListener("click", async () => { await openSavedReport(button.dataset.viewReport); });
  });
}

async function openSavedReport(scanId) {
  const response = await fetch(`/api/scans/${scanId}/report.json`);
  if (!response.ok) {
    reportContent.className = "empty-state";
    reportContent.textContent = "Não foi possível abrir este relatório.";
    return;
  }
  renderReport(await response.json());
  document.querySelector("#visualReport").scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ── Report renderers ───────────────────────────────────── */

function renderReport(report) {
  const summary = report.summary || {};
  const counts = summary.findings_by_severity || {};
  const highTotal = (counts.critical || 0) + (counts.high || 0);
  const status = summary.overall_status || "ok";
  reportSubtitle.textContent = `${report.target} · ${formatDate(report.finished_at)} · ${summary.hosts_found || 0} hosts`;
  reportStatus.textContent = status;
  reportStatus.className = `status-pill ${statusClass(status)}`;
  reportContent.className = "report-body";

  const findings = report.findings || [];
  const hosts = report.hosts || [];
  const hostMap = new Map(hosts.map((h) => [h.ip, h]));

  reportContent.innerHTML = `
    <div class="report-metrics">
      ${metricCard("Status", status)}
      ${metricCard("Hosts ativos", summary.hosts_found || 0)}
      ${metricCard("Portas abertas", summary.open_ports || 0)}
      ${metricCard("Críticos/Altos", highTotal)}
    </div>

    ${exportControls("scan", report.id)}

    ${buildSection("Prioridade de correção", findings.length, `
      ${buildFilterBar(findings)}
      <div class="finding-list">
        ${findings.length ? findings.map((f) => findingCard(f, hostMap)).join("") : '<div class="empty-state">Nenhum achado relevante nos testes automáticos.</div>'}
      </div>
    `)}

    ${buildSection("Acertos encontrados", 0, `
      <div class="pass-grid">${passCards(report).join("")}</div>
    `)}

    ${buildSection("Dispositivos e atalhos", hosts.length, `
      <div class="host-grid">
        ${hosts.length ? hosts.map(hostCard).join("") : '<div class="empty-state">Nenhum host ativo encontrado.</div>'}
      </div>
    `)}

    ${buildSection("Checklist manual", (report.manual_checklist || []).length, `
      <div class="checklist">${(report.manual_checklist || []).map(checkItem).join("")}</div>
    `, true)}
  `;

  setupInteractivity(reportContent);
}

function renderBadAgentReport(report) {
  const summary = report.summary || {};
  const counts = summary.by_severity || {};
  const highTotal = (counts.critical || 0) + (counts.high || 0);
  badHostsCount.textContent = summary.hosts_found ?? badHostsCount.textContent;
  badEvidenceCount.textContent = summary.total_evidence ?? "0";
  badHighCount.textContent = String(highTotal);
  badOverallStatus.textContent = summary.overall_status || "—";
  badAgentSubtitle.textContent = `${report.target} · ${formatDate(report.finished_at)} · ${summary.total_evidence || 0} evidências`;
  badAgentReportStatus.textContent = summary.overall_status || "ok";
  badAgentReportStatus.className = `status-pill ${statusClass(summary.overall_status)}`;
  badAgentReport.className = "report-body";

  const evidence = report.evidence || [];
  const aiAnalysis = normalizeAiAnalysis(report.ai_analysis);
  const tokens = aiAnalysis.token_usage || {};

  badAgentReport.innerHTML = `
    <div class="report-metrics">
      ${metricCard("Status", summary.overall_status || "ok")}
      ${metricCard("Hosts", summary.hosts_found || 0)}
      ${metricCard("Evidências", summary.total_evidence || 0)}
      ${metricCard("Críticos/Altos", highTotal)}
    </div>

    ${exportControls("bad-agent", report.id)}

    <div class="agent-safety">
      <strong>Limites de segurança ativos</strong>
      <span>Sem senhas</span>
      <span>Sem exploits</span>
      <span>Sem reset/reboot</span>
      <span>Frame RTSP só se marcado</span>
    </div>

    ${buildSection("Evidências adversárias controladas", evidence.length, `
      ${buildFilterBar(evidence)}
      <div class="finding-list">
        ${evidence.length ? evidence.map(agentEvidenceCard).join("") : '<div class="empty-state">Nenhuma evidência encontrada nos testes selecionados.</div>'}
      </div>
    `)}

    ${buildSection("Análise da IA", 0, `
      <div class="ai-usage">
        <span>${aiAnalysis.used_api ? "IA usada" : "Análise local"}</span>
        <span>Modelo: ${escapeHtml(aiAnalysis.model || "—")}</span>
        <span>Prompt: ${tokens.prompt_tokens || 0}</span>
        <span>Resposta: ${tokens.completion_tokens || 0}</span>
        <span>Total: ${tokens.total_tokens || 0}</span>
      </div>
      ${aiAnalysis.fallback_reason ? `<p class="ai-note">${escapeHtml(aiAnalysis.fallback_reason)}</p>` : ""}
      <pre class="ai-analysis">${escapeHtml(aiAnalysis.content || "Sem análise disponível.")}</pre>
    `, true)}
  `;

  setupInteractivity(badAgentReport);
}

function renderPerformanceReport(report) {
  const summary = report.summary || {};
  const broadcast = report.broadcast_sample || {};
  const speed = report.speedtest || {};
  const aiAnalysis = normalizeAiAnalysis(report.ai_analysis);
  const tokens = aiAnalysis.token_usage || {};
  performanceSubtitle.textContent = `${report.interface || "auto"} · ${formatDate(report.finished_at)} · ${broadcast.total_packets || 0} pacotes`;
  performanceReportStatus.textContent = summary.overall_status || "ok";
  performanceReportStatus.className = `status-pill ${statusClass(summary.overall_status)}`;
  perfBroadcastPps.textContent = summary.broadcast_pps ?? "0";
  perfTalkers.textContent = summary.top_talkers ?? "0";
  perfDownload.textContent = speed.status === "ok" ? `${speed.download_mbps} Mbps` : "—";
  perfOverallStatus.textContent = summary.overall_status || "—";
  performanceReport.className = "report-body";

  const findings = report.findings || [];
  const talkers = broadcast.talkers || [];

  performanceReport.innerHTML = `
    <div class="report-metrics">
      ${metricCard("Status", summary.overall_status || "ok")}
      ${metricCard("Broadcast/s", summary.broadcast_pps || 0)}
      ${metricCard("Talkers", summary.top_talkers || 0)}
      ${metricCard("Speed", speed.status === "ok" ? `${speed.download_mbps} Mbps` : speed.status || "—")}
    </div>

    ${exportControls("performance", report.id)}

    ${buildSection("Maiores emissores broadcast/multicast", talkers.length, `
      <div class="host-grid">
        ${talkers.length ? talkers.map(talkerCard).join("") : `<div class="empty-state">${escapeHtml(broadcast.message || "Nenhum pacote capturado na amostra.")}</div>`}
      </div>
    `)}

    ${buildSection("Speed test", 0, speedCard(speed))}

    ${buildSection("Achados de performance", findings.length, `
      ${buildFilterBar(findings)}
      <div class="finding-list">
        ${findings.length ? findings.map(performanceFindingCard).join("") : '<div class="empty-state">Nenhum achado de performance.</div>'}
      </div>
    `)}

    ${buildSection("Análise da IA", 0, `
      <div class="ai-usage">
        <span>${aiAnalysis.used_api ? "IA usada" : "Análise local"}</span>
        <span>Modelo: ${escapeHtml(aiAnalysis.model || "—")}</span>
        <span>Prompt: ${tokens.prompt_tokens || 0}</span>
        <span>Resposta: ${tokens.completion_tokens || 0}</span>
        <span>Total: ${tokens.total_tokens || 0}</span>
      </div>
      ${aiAnalysis.fallback_reason ? `<p class="ai-note">${escapeHtml(aiAnalysis.fallback_reason)}</p>` : ""}
      <pre class="ai-analysis">${escapeHtml(aiAnalysis.content || "Sem análise disponível.")}</pre>
    `, true)}
  `;

  setupInteractivity(performanceReport);
}

function renderWebsiteReport(report) {
  const summary = report.summary || {};
  const counts = summary.by_severity || {};
  const highTotal = (counts.critical || 0) + (counts.high || 0);
  const page = report.page || {};
  const tls = report.tls || {};
  const sensitive = report.sensitive_paths || {};
  const aiAnalysis = normalizeAiAnalysis(report.ai_analysis);
  const tokens = aiAnalysis.token_usage || {};

  webFindingsCount.textContent = summary.total_findings || 0;
  webHighCount.textContent = String(highTotal);
  webHttpStatus.textContent = page.status || "—";
  webOverallStatus.textContent = summary.overall_status || "—";
  websiteSubtitle.textContent = `${report.final_url || report.target} · ${formatDate(report.finished_at)} · ${summary.total_findings || 0} achados`;
  websiteReportStatus.textContent = summary.overall_status || "ok";
  websiteReportStatus.className = `status-pill ${statusClass(summary.overall_status)}`;
  websiteReport.className = "report-body";

  const findings = report.findings || [];
  websiteReport.innerHTML = `
    <div class="report-metrics">
      ${metricCard("Status", summary.overall_status || "ok")}
      ${metricCard("HTTP", page.status || "—")}
      ${metricCard("Achados", summary.total_findings || 0)}
      ${metricCard("Críticos/Altos", highTotal)}
    </div>

    ${exportControls("website", report.id)}

    <div class="agent-safety">
      <strong>Limites de segurança ativos</strong>
      <span>Sem login</span>
      <span>Sem força bruta</span>
      <span>Sem payload ofensivo</span>
      <span>Sem fuzzing pesado</span>
    </div>

    ${buildSection("Achados de segurança web", findings.length, `
      ${buildFilterBar(findings)}
      <div class="finding-list">
        ${findings.length ? findings.map(websiteFindingCard).join("") : '<div class="empty-state">Nenhum achado relevante nos testes seguros.</div>'}
      </div>
    `)}

    ${buildSection("TLS e certificado", 0, tlsCard(tls))}

    ${buildSection("Arquivos sensíveis checados", (sensitive.checked || []).length, sensitivePathsTable(sensitive), true)}

    ${buildSection("Análise da IA", 0, `
      <div class="ai-usage">
        <span>${aiAnalysis.used_api ? "IA usada" : "Análise local"}</span>
        <span>Modelo: ${escapeHtml(aiAnalysis.model || "—")}</span>
        <span>Prompt: ${tokens.prompt_tokens || 0}</span>
        <span>Resposta: ${tokens.completion_tokens || 0}</span>
        <span>Total: ${tokens.total_tokens || 0}</span>
      </div>
      ${aiAnalysis.fallback_reason ? `<p class="ai-note">${escapeHtml(aiAnalysis.fallback_reason)}</p>` : ""}
      <pre class="ai-analysis">${escapeHtml(aiAnalysis.content || "Sem análise disponível.")}</pre>
    `, true)}
  `;

  setupInteractivity(websiteReport);
}

/* ── Section & filter builders ──────────────────────────── */

function buildSection(title, count, body, collapsedByDefault = false) {
  const countBadge = count > 0 ? `<span class="section-count">${count}</span>` : "";
  const collapsed = collapsedByDefault ? "collapsed" : "";
  return `
    <div class="report-section ${collapsed}">
      <div class="section-header">
        <div class="section-header-left">
          <h3>${escapeHtml(title)}</h3>${countBadge}
        </div>
        <span class="toggle-icon">▾</span>
      </div>
      <div class="section-body">
        ${body || '<div class="empty-state">Sem itens.</div>'}
      </div>
    </div>
  `;
}

function buildFilterBar(items) {
  if (!items.length) return "";
  const counts = {};
  items.forEach((item) => {
    const s = item.severity || "info";
    counts[s] = (counts[s] || 0) + 1;
  });
  const hasSeverities = SEV_ORDER.some((s) => counts[s]);
  if (!hasSeverities) return "";

  const buttons = SEV_ORDER
    .filter((s) => counts[s] > 0)
    .map((s) => `<button class="filter-btn sev-${s}" type="button" data-filter="${s}">${sevLabel(s)} <span class="badge">${counts[s]}</span></button>`)
    .join("");

  return `
    <div class="filter-bar">
      <button class="filter-btn active" type="button" data-filter="all">Todos <span class="badge">${items.length}</span></button>
      ${buttons}
    </div>
  `;
}

function exportControls(reportType, reportId) {
  if (!reportId) return "";
  const safeType = escapeHtml(reportType);
  const safeId = escapeHtml(reportId);
  return `
    <div class="export-bar" data-report-type="${safeType}" data-report-id="${safeId}">
      <div>
        <strong>Exportar relatório</strong>
        <span>Escolha o formato para baixar este resultado.</span>
      </div>
      <label>
        Formato
        <select class="export-format">
          <option value="md">Markdown</option>
          <option value="json">JSON</option>
          <option value="pdf">PDF</option>
          <option value="csv">Planilha CSV</option>
        </select>
      </label>
      <button type="button" class="secondary export-button">Exportar</button>
    </div>
  `;
}

function setupInteractivity(container) {
  container.querySelectorAll(".section-header").forEach((header) => {
    header.addEventListener("click", () => {
      header.closest(".report-section").classList.toggle("collapsed");
    });
  });

  container.querySelectorAll(".filter-bar").forEach((bar) => {
    bar.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-filter]");
      if (!btn) return;
      const filter = btn.dataset.filter;
      bar.querySelectorAll(".filter-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const body = bar.closest(".section-body");
      if (!body) return;
      body.querySelectorAll(".finding[data-severity]").forEach((el) => {
        el.style.display = filter === "all" || el.dataset.severity === filter ? "" : "none";
      });
    });
  });

  container.querySelectorAll(".export-button").forEach((button) => {
    button.addEventListener("click", () => {
      const bar = button.closest(".export-bar");
      if (!bar) return;
      const format = bar.querySelector(".export-format")?.value || "md";
      const type = encodeURIComponent(bar.dataset.reportType);
      const id = encodeURIComponent(bar.dataset.reportId);
      window.location.href = `/api/exports/${type}/${id}.${format}`;
    });
  });
}

/* ── Card builders ──────────────────────────────────────── */

function metricCard(label, value) {
  return `<div><span>${escapeHtml(String(label))}</span><strong>${escapeHtml(String(value))}</strong></div>`;
}

function findingCard(finding, hostMap) {
  const targetLink = linkForFinding(finding, hostMap);
  return `
    <article class="finding" data-severity="${escapeHtml(finding.severity)}">
      <div class="finding-header">
        <span class="severity ${escapeHtml(finding.severity)}">${sevLabel(finding.severity)}</span>
        <h4>${escapeHtml(finding.title)}</h4>
      </div>
      <p><strong>Alvo:</strong> ${targetLink}</p>
      <p>${escapeHtml(finding.detail)}</p>
      <p><strong>Correção:</strong> ${escapeHtml(finding.correction)}</p>
    </article>
  `;
}

function agentEvidenceCard(item) {
  const links = (item.links || [])
    .map((link) => `<a href="${escapeHtml(link.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(link.label)}</a>`)
    .join("");
  const media = item.media
    ? `<figure class="agent-media"><img src="${escapeHtml(item.media.url)}" alt="${escapeHtml(item.media.caption || "Frame RTSP")}" /><figcaption>${escapeHtml(item.media.caption || "")}</figcaption></figure>`
    : "";
  return `
    <article class="finding" data-severity="${escapeHtml(item.severity)}">
      <div class="finding-header">
        <span class="severity ${escapeHtml(item.severity)}">${sevLabel(item.severity)}</span>
        <h4>${escapeHtml(item.title)}</h4>
      </div>
      <p><strong>Alvo:</strong> <code>${escapeHtml(item.target)}</code></p>
      <p>${escapeHtml(item.detail)}</p>
      <p><strong>Prova segura:</strong> ${escapeHtml(item.proof)}</p>
      <p><strong>Correção:</strong> ${escapeHtml(item.correction)}</p>
      <div class="device-links">${links || "<span>Sem link direto.</span>"}</div>
      ${media}
    </article>
  `;
}

function performanceFindingCard(finding) {
  return `
    <article class="finding" data-severity="${escapeHtml(finding.severity)}">
      <div class="finding-header">
        <span class="severity ${escapeHtml(finding.severity)}">${sevLabel(finding.severity)}</span>
        <h4>${escapeHtml(finding.title)}</h4>
      </div>
      <p>${escapeHtml(finding.detail)}</p>
      <p><strong>Recomendação:</strong> ${escapeHtml(finding.recommendation)}</p>
    </article>
  `;
}

function websiteFindingCard(finding) {
  const link = finding.url ? `<div class="device-links"><a href="${escapeHtml(finding.url)}" target="_blank" rel="noopener noreferrer">Abrir evidência</a></div>` : "";
  return `
    <article class="finding" data-severity="${escapeHtml(finding.severity)}">
      <div class="finding-header">
        <span class="severity ${escapeHtml(finding.severity)}">${sevLabel(finding.severity)}</span>
        <h4>${escapeHtml(finding.title)}</h4>
      </div>
      <p><strong>Categoria:</strong> ${escapeHtml(finding.category || "web")}</p>
      <p>${escapeHtml(finding.detail)}</p>
      <p><strong>Recomendação:</strong> ${escapeHtml(finding.recommendation)}</p>
      ${link}
    </article>
  `;
}

function tlsCard(tls) {
  if (!tls || tls.status === "skipped") {
    return `<div class="empty-state">${escapeHtml(tls?.message || "TLS não avaliado.")}</div>`;
  }
  if (tls.status !== "ok") {
    return `<div class="empty-state">${escapeHtml(tls.message || "Falha ao validar TLS.")}</div>`;
  }
  return `
    <div class="pass-grid">
      ${metricCard("Versão", tls.version || "—")}
      ${metricCard("Expira em", typeof tls.days_remaining === "number" ? `${tls.days_remaining} dias` : "—")}
      ${metricCard("Válido até", tls.expires_at || "—")}
      ${metricCard("Cipher", Array.isArray(tls.cipher) ? tls.cipher[0] : "—")}
    </div>
  `;
}

function sensitivePathsTable(sensitive) {
  const checked = sensitive?.checked || [];
  if (!checked.length) return '<div class="empty-state">Checagem de caminhos sensíveis não executada.</div>';
  return `
    <div class="finding-list">
      ${checked.map((item) => `
        <article class="finding" data-severity="${item.exposed ? "medium" : "info"}">
          <div class="finding-header">
            <span class="severity ${item.exposed ? "medium" : "info"}">${item.exposed ? "Revisar" : "OK"}</span>
            <h4>${escapeHtml(item.path)}</h4>
          </div>
          <p>Status HTTP: ${escapeHtml(item.status || "sem resposta")}</p>
        </article>
      `).join("")}
    </div>
  `;
}

function talkerCard(talker) {
  const protocols = Object.entries(talker.protocols || {})
    .map(([name, count]) => `<span class="port-chip medium">${escapeHtml(name)}: ${count}</span>`)
    .join("");
  return `
    <article class="talker-card">
      <div class="host-head">
        <div>
          <strong>${escapeHtml(talker.mac)}</strong>
          <p>${talker.packets} pacotes · ${talker.packets_per_second}/s</p>
        </div>
      </div>
      <div class="port-list">${protocols || "<span>Sem protocolo classificado.</span>"}</div>
    </article>
  `;
}

function speedCard(speed) {
  if (!speed || speed.status !== "ok") {
    return `<div class="empty-state">${escapeHtml(speed?.message || "Speed test não executado.")}</div>`;
  }
  return `
    <div class="pass-grid">
      ${metricCard("Download", `${speed.download_mbps} Mbps`)}
      ${metricCard("Upload", `${speed.upload_mbps} Mbps`)}
      ${metricCard("Ping", `${speed.ping_ms} ms`)}
      ${metricCard("Servidor", `${speed.server?.sponsor || "—"} ${speed.server?.name || ""}`)}
    </div>
  `;
}

function passCards(report) {
  const hosts = report.hosts || [];
  const allPorts = hosts.flatMap((h) => h.open_ports || []);
  const findings = report.findings || [];
  const hasSeverity = (s) => findings.some((f) => f.severity === s);
  const hasPort = (p) => allPorts.some((item) => item.port === p);
  return [
    passCard(!hasSeverity("critical"), "Sem crítico automático", "Nenhum achado crítico detectado pelos testes leves."),
    passCard(!hasPort(23), "Telnet não detectado", "Porta Telnet não apareceu aberta nos hosts testados."),
    passCard(!hasPort(21), "FTP não detectado", "FTP não apareceu aberto nos hosts testados."),
    passCard(!hasPort(3389), "RDP não detectado", "RDP não apareceu aberto nos hosts testados."),
  ];
}

function passCard(ok, title, text) {
  return `
    <div class="pass-card ${ok ? "ok" : "warn"}">
      <strong>${ok ? "Passou" : "Revisar"}</strong>
      <h4>${escapeHtml(title)}</h4>
      <p>${escapeHtml(text)}</p>
    </div>
  `;
}

function hostCard(host) {
  const ports = host.open_ports || [];
  const links = webPorts(host);
  return `
    <article class="host-card">
      <div class="host-head">
        <div>
          <strong>${escapeHtml(host.ip)}</strong>
          <p>${escapeHtml(host.hostname || host.mac || "Dispositivo sem nome")}</p>
        </div>
        <span>${ports.length} porta(s)</span>
      </div>
      <div class="role-list">
        ${(host.role_hints || []).map((r) => `<code>${escapeHtml(r)}</code>`).join("") || "<code>sem perfil claro</code>"}
      </div>
      <div class="port-list">
        ${ports.length ? ports.map(portChip).join("") : "<span>Nenhuma porta comum aberta.</span>"}
      </div>
      <div class="device-links">
        ${links.length ? links.map((item) => `<a href="${deviceUrl(host.ip, item.port)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.label)}</a>`).join("") : "<span>Sem painel web detectado.</span>"}
      </div>
    </article>
  `;
}

function portChip(port) {
  return `<span class="port-chip ${escapeHtml(port.severity)}">${escapeHtml(`${port.port}/${port.service}`)}</span>`;
}

function checkItem(item) {
  return `
    <div class="check-item">
      <strong>${escapeHtml(item.item)}</strong>
      <p>${escapeHtml(item.why)}</p>
      <p><strong>Ação:</strong> ${escapeHtml(item.action)}</p>
    </div>
  `;
}

/* ── Link helpers ───────────────────────────────────────── */

function linkForFinding(finding, hostMap) {
  const target = finding.target || "";
  const match = target.match(/^(\d+\.\d+\.\d+\.\d+)(?::(\d+))?$/);
  if (!match) return `<code>${escapeHtml(target)}</code>`;
  const ip = match[1];
  const port = Number(match[2]);
  if (port && isWebPort(port)) return `<a href="${deviceUrl(ip, port)}" target="_blank" rel="noopener noreferrer">${escapeHtml(target)} — abrir painel</a>`;
  const host = hostMap.get(ip);
  const firstPanel = host ? webPorts(host)[0] : null;
  if (firstPanel) return `<code>${escapeHtml(target)}</code> · <a href="${deviceUrl(ip, firstPanel.port)}" target="_blank" rel="noopener noreferrer">abrir dispositivo</a>`;
  return `<code>${escapeHtml(target)}</code>`;
}

function webPorts(host) {
  return (host.open_ports || [])
    .filter((p) => isWebPort(p.port))
    .map((p) => ({ port: p.port, label: `${schemeForPort(p.port).toUpperCase()} ${p.port}` }));
}

function isWebPort(port) {
  return [80, 443, 5000, 5001, 8000, 8080, 8443, 8888, 9000].includes(Number(port));
}

function schemeForPort(port) {
  return [443, 5001, 8443].includes(Number(port)) ? "https" : "http";
}

function deviceUrl(ip, port) {
  const scheme = schemeForPort(port);
  const def = (scheme === "http" && Number(port) === 80) || (scheme === "https" && Number(port) === 443);
  return `${scheme}://${ip}${def ? "" : `:${port}`}`;
}

/* ── Status helpers ─────────────────────────────────────── */

function applySummary(summary) {
  hostsCount.textContent = summary.hosts_found ?? hostsCount.textContent;
  portsCount.textContent = summary.open_ports ?? portsCount.textContent;
  const counts = summary.findings_by_severity || {};
  highCount.textContent = String((counts.critical || 0) + (counts.high || 0));
  overallStatus.textContent = summary.overall_status || "—";
}

function setStatus(text, cls) { scanStatus.textContent = text; scanStatus.className = `status-pill ${cls || "idle"}`; }
function setBadStatus(text, cls) { badAgentStatus.textContent = text; badAgentStatus.className = `status-pill ${cls || "idle"}`; }
function setPerformanceStatus(text, cls) { performanceStatus.textContent = text; performanceStatus.className = `status-pill ${cls || "idle"}`; }
function setWebsiteStatus(text, cls) { websiteStatus.textContent = text; websiteStatus.className = `status-pill ${cls || "idle"}`; }

function statusClass(status) {
  if (status === "critical" || status === "attention") return "bad";
  if (status === "review") return "warn";
  return "ok";
}

/* ── Resets ─────────────────────────────────────────────── */

function resetLive() {
  consoleEl.innerHTML = "";
  hostsCount.textContent = "0";
  portsCount.textContent = "0";
  highCount.textContent = "0";
  overallStatus.textContent = "—";
}

function resetBadAgent() {
  badAgentConsole.innerHTML = "";
  badHostsCount.textContent = "0";
  badEvidenceCount.textContent = "0";
  badHighCount.textContent = "0";
  badOverallStatus.textContent = "—";
  badAgentReport.className = "empty-state";
  badAgentReport.textContent = "Aguardando resultado do test_bad_agent.";
  badAgentReportStatus.textContent = "rodando";
}

function resetPerformance() {
  performanceConsole.innerHTML = "";
  perfBroadcastPps.textContent = "0";
  perfTalkers.textContent = "0";
  perfDownload.textContent = "—";
  perfOverallStatus.textContent = "—";
  performanceReport.className = "empty-state";
  performanceReport.textContent = "Aguardando resultado da análise.";
  performanceReportStatus.textContent = "rodando";
}

function resetWebsiteSecurity() {
  websiteConsole.innerHTML = "";
  webFindingsCount.textContent = "0";
  webHighCount.textContent = "0";
  webHttpStatus.textContent = "—";
  webOverallStatus.textContent = "—";
  websiteReport.className = "empty-state";
  websiteReport.textContent = "Aguardando resultado da análise web.";
  websiteReportStatus.textContent = "rodando";
}

/* ── Console lines ──────────────────────────────────────── */

function addConsoleLine(targetEl, kind, message) {
  const line = document.createElement("div");
  line.className = "console-line";
  const now = new Date().toLocaleTimeString("pt-BR", { hour12: false });
  line.innerHTML = `<time>${now}</time><span class="console-tag ${escapeHtml(kind)}">${escapeHtml(kind)}</span><span class="console-msg">${escapeHtml(message)}</span>`;
  targetEl.appendChild(line);
  targetEl.scrollTop = targetEl.scrollHeight;
}

function addLine(kind, message) { addConsoleLine(consoleEl, kind, message); }
function addBadLine(kind, message) { addConsoleLine(badAgentConsole, kind, message); }
function addPerformanceLine(kind, message) { addConsoleLine(performanceConsole, kind, message); }
function addWebsiteLine(kind, message) { addConsoleLine(websiteConsole, kind, message); }

/* ── Misc utils ─────────────────────────────────────────── */

function normalizeAiAnalysis(value) {
  if (value && typeof value === "object") {
    return {
      content: value.content || "",
      used_api: Boolean(value.used_api),
      provider: value.provider || "unknown",
      model: value.model || "—",
      token_usage: value.token_usage || { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      fallback_reason: value.fallback_reason || null,
    };
  }
  return {
    content: value || "",
    used_api: false,
    provider: "legacy",
    model: "local",
    token_usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
    fallback_reason: "Relatório antigo ou análise local sem metadados de tokens.",
  };
}

function formatDate(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString("pt-BR");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* ── Init ───────────────────────────────────────────────── */

serviceStatus.textContent = "online";
loadReports();
loadSchedules();
