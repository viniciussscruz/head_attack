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
const badAgentForm = document.querySelector("#badAgentForm");
const badAgentTarget = document.querySelector("#badAgentTarget");
const aiEndpoint = document.querySelector("#aiEndpoint");
const aiModel = document.querySelector("#aiModel");
const aiApiKey = document.querySelector("#aiApiKey");
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

const hostsCount = document.querySelector("#hostsCount");
const portsCount = document.querySelector("#portsCount");
const highCount = document.querySelector("#highCount");
const overallStatus = document.querySelector("#overallStatus");

let activeSource = null;
let activeBadSource = null;

tabButtons.forEach((button) => {
  button.addEventListener("click", () => switchTab(button.dataset.tab));
});

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await startScan();
});

scheduleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await createSchedule();
});

badAgentForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await startBadAgent();
});

refreshReports.addEventListener("click", () => {
  loadReports();
  loadSchedules();
});

function switchTab(tabName) {
  tabButtons.forEach((button) => button.classList.toggle("active", button.dataset.tab === tabName));
  dashboardTab.classList.toggle("active", tabName === "dashboard");
  badAgentTab.classList.toggle("active", tabName === "badAgent");
}

async function startScan() {
  resetLive();
  setStatus("rodando", "warn");

  const response = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target: targetInput.value.trim(),
      profile: profileInput.value,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Erro desconhecido" }));
    setStatus("erro", "bad");
    addLine("erro", error.detail || "Nao foi possivel iniciar o scan.");
    return;
  }

  const data = await response.json();
  activeScan.textContent = `Scan ${data.scan_id} em ${targetInput.value.trim()}`;
  streamScan(data.scan_id);
}

function streamScan(scanId) {
  if (activeSource) {
    activeSource.close();
  }

  activeSource = new EventSource(`/api/scans/${scanId}/events`);
  activeSource.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    handleEvent(payload, scanId);
  };
  activeSource.onerror = () => {
    addLine("stream", "Conexao de eventos encerrada.");
    activeSource.close();
  };
}

function handleEvent(payload, scanId) {
  const event = payload.event || "info";
  const message = payload.message || "";
  addLine(event, message);

  if (event === "host_found") {
    hostsCount.textContent = String(Number(hostsCount.textContent) + 1);
  }

  if (event === "host_scanned" && payload.data && payload.data.host) {
    const openPorts = payload.data.host.open_ports || [];
    portsCount.textContent = String(Number(portsCount.textContent) + openPorts.length);
  }

  if (event === "finished") {
    const report = payload.data;
    applySummary(report.summary || {});
    setStatus("concluido", statusClass(report.summary?.overall_status));
    renderReport(report);
    addLine("relatorio", "Relatorio visual atualizado no painel.");
    loadReports();
  }

  if (event === "failed") {
    setStatus("falhou", "bad");
  }
}

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
    addBadLine("erro", error.detail || "Nao foi possivel iniciar o test_bad_agent.");
    return;
  }

  const data = await response.json();
  badAgentActive.textContent = `Agente ${data.agent_id} em ${badAgentTarget.value.trim()}`;
  streamBadAgent(data.agent_id);
}

function streamBadAgent(agentId) {
  if (activeBadSource) {
    activeBadSource.close();
  }

  activeBadSource = new EventSource(`/api/bad-agent/${agentId}/events`);
  activeBadSource.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    handleBadAgentEvent(payload);
  };
  activeBadSource.onerror = () => {
    addBadLine("stream", "Conexao de eventos encerrada.");
    activeBadSource.close();
  };
}

function handleBadAgentEvent(payload) {
  const event = payload.event || "info";
  const message = payload.message || "";
  addBadLine(event, message);

  if (event === "host_found") {
    badHostsCount.textContent = String(Number(badHostsCount.textContent) + 1);
  }

  if (event === "finished") {
    const report = payload.data;
    renderBadAgentReport(report);
    setBadStatus("concluido", statusClass(report.summary?.overall_status));
  }

  if (event === "failed") {
    setBadStatus("falhou", "bad");
  }
}

function renderBadAgentReport(report) {
  const summary = report.summary || {};
  const counts = summary.by_severity || {};
  const highTotal = (counts.critical || 0) + (counts.high || 0);
  badHostsCount.textContent = summary.hosts_found ?? badHostsCount.textContent;
  badEvidenceCount.textContent = summary.total_evidence ?? "0";
  badHighCount.textContent = String(highTotal);
  badOverallStatus.textContent = summary.overall_status || "-";
  badAgentSubtitle.textContent = `${report.target} · ${formatDate(report.finished_at)} · ${summary.total_evidence || 0} evidências`;
  badAgentReportStatus.textContent = summary.overall_status || "ok";
  badAgentReportStatus.className = `status-pill ${statusClass(summary.overall_status)}`;
  badAgentReport.className = "report-body";

  const evidence = report.evidence || [];
  badAgentReport.innerHTML = `
    <div class="report-metrics">
      ${metricCard("Status", summary.overall_status || "ok")}
      ${metricCard("Hosts", summary.hosts_found || 0)}
      ${metricCard("Evidências", summary.total_evidence || 0)}
      ${metricCard("Críticos/altos", highTotal)}
    </div>

    <div class="agent-safety">
      <strong>Testes executados com limites de segurança</strong>
      <span>Não tentou senhas</span>
      <span>Não executou exploit</span>
      <span>Não acionou reset/reboot</span>
      <span>Frame RTSP só quando marcado</span>
    </div>

    <div class="report-section">
      <h3>Evidências adversárias controladas</h3>
      <div class="finding-list">
        ${evidence.length ? evidence.map(agentEvidenceCard).join("") : '<div class="empty-state">Nenhuma evidência encontrada nos testes selecionados.</div>'}
      </div>
    </div>

    <div class="report-section">
      <h3>Análise da IA</h3>
      <pre class="ai-analysis">${escapeHtml(report.ai_analysis || "Sem análise disponível.")}</pre>
    </div>
  `;
}

function agentEvidenceCard(item) {
  const links = (item.links || []).map((link) => `<a href="${escapeHtml(link.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(link.label)}</a>`).join("");
  const media = item.media ? `<figure class="agent-media"><img src="${escapeHtml(item.media.url)}" alt="${escapeHtml(item.media.caption || "Frame RTSP capturado")}" /><figcaption>${escapeHtml(item.media.caption || "")}</figcaption></figure>` : "";
  return `
    <article class="finding ${escapeHtml(item.severity)}">
      <span class="severity">${escapeHtml(item.severity)}</span>
      <h4>${escapeHtml(item.title)}</h4>
      <p><strong>Alvo:</strong> <code>${escapeHtml(item.target)}</code></p>
      <p>${escapeHtml(item.detail)}</p>
      <p><strong>Prova segura:</strong> ${escapeHtml(item.proof)}</p>
      <p><strong>Correção:</strong> ${escapeHtml(item.correction)}</p>
      <div class="device-links">${links || '<span>Sem link direto.</span>'}</div>
      ${media}
    </article>
  `;
}

function applySummary(summary) {
  hostsCount.textContent = summary.hosts_found ?? hostsCount.textContent;
  portsCount.textContent = summary.open_ports ?? portsCount.textContent;
  const counts = summary.findings_by_severity || {};
  highCount.textContent = String((counts.critical || 0) + (counts.high || 0));
  overallStatus.textContent = summary.overall_status || "-";
}

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
    addLine("erro", error.detail || "Nao foi possivel criar agendamento.");
    return;
  }

  const schedule = await response.json();
  addLine("agenda", `Agendamento criado: ${schedule.id}`);
  await loadSchedules();
}

async function loadSchedules() {
  const response = await fetch("/api/schedules");
  if (!response.ok) {
    return;
  }

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
      <p>Ultimo scan: ${schedule.last_scan_id || "-"}<br />Proximo: ${formatDate(schedule.next_run_at)}</p>
      <button class="secondary" data-remove="${schedule.id}">Remover</button>
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

async function loadReports() {
  const response = await fetch("/api/reports");
  if (!response.ok) {
    reportsEl.innerHTML = '<div class="item"><p>Nao foi possivel carregar relatorios.</p></div>';
    return;
  }

  const reports = await response.json();
  reportsEl.innerHTML = "";
  if (!reports.length) {
    reportsEl.innerHTML = '<div class="item"><p>Nenhum relatorio gerado ainda.</p></div>';
    return;
  }

  for (const report of reports) {
    const counts = report.findings || {};
    const item = document.createElement("div");
    item.className = "item";
    item.innerHTML = `
      <strong>${escapeHtml(report.target || "-")} · ${escapeHtml(report.status || "-")}</strong>
      <p>${formatDate(report.finished_at)} · hosts: ${report.hosts ?? 0} · altos: ${(counts.critical || 0) + (counts.high || 0)}</p>
      <button class="secondary" data-view-report="${report.id}">Ver painel</button>
      <a href="${report.markdown_url}">Markdown</a>
      <a href="${report.json_url}">JSON</a>
    `;
    reportsEl.appendChild(item);
  }

  reportsEl.querySelectorAll("[data-view-report]").forEach((button) => {
    button.addEventListener("click", async () => {
      await openSavedReport(button.dataset.viewReport);
    });
  });
}

async function openSavedReport(scanId) {
  const response = await fetch(`/api/scans/${scanId}/report.json`);
  if (!response.ok) {
    reportContent.className = "empty-state";
    reportContent.textContent = "Nao foi possivel abrir este relatorio.";
    return;
  }

  const report = await response.json();
  renderReport(report);
  document.querySelector("#visualReport").scrollIntoView({ behavior: "smooth", block: "start" });
}

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
  const hostMap = new Map(hosts.map((host) => [host.ip, host]));

  reportContent.innerHTML = `
    <div class="report-metrics">
      ${metricCard("Status", status)}
      ${metricCard("Hosts ativos", summary.hosts_found || 0)}
      ${metricCard("Portas abertas", summary.open_ports || 0)}
      ${metricCard("Criticos/altos", highTotal)}
    </div>

    <div class="report-section">
      <h3>Prioridade de correção</h3>
      <div class="finding-list">
        ${findings.length ? findings.map((finding) => findingCard(finding, hostMap)).join("") : '<div class="empty-state">Nenhum achado relevante nos testes automaticos.</div>'}
      </div>
    </div>

    <div class="report-section">
      <h3>Acertos encontrados</h3>
      <div class="pass-grid">
        ${passCards(report).join("")}
      </div>
    </div>

    <div class="report-section">
      <h3>Dispositivos e atalhos</h3>
      <div class="host-grid">
        ${hosts.length ? hosts.map(hostCard).join("") : '<div class="empty-state">Nenhum host ativo encontrado.</div>'}
      </div>
    </div>

    <div class="report-section">
      <h3>Checklist manual</h3>
      <div class="checklist">
        ${(report.manual_checklist || []).map(checkItem).join("")}
      </div>
    </div>
  `;
}

function metricCard(label, value) {
  return `
    <div>
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </div>
  `;
}

function findingCard(finding, hostMap) {
  const targetLink = linkForFinding(finding, hostMap);
  return `
    <article class="finding ${escapeHtml(finding.severity)}">
      <div>
        <span class="severity">${escapeHtml(finding.severity)}</span>
        <h4>${escapeHtml(finding.title)}</h4>
        <p><strong>Alvo:</strong> ${targetLink}</p>
        <p>${escapeHtml(finding.detail)}</p>
        <p><strong>Correção:</strong> ${escapeHtml(finding.correction)}</p>
      </div>
    </article>
  `;
}

function linkForFinding(finding, hostMap) {
  const target = finding.target || "";
  const match = target.match(/^(\d+\.\d+\.\d+\.\d+)(?::(\d+))?$/);
  if (!match) {
    return `<code>${escapeHtml(target)}</code>`;
  }

  const ip = match[1];
  const port = Number(match[2]);
  if (port && isWebPort(port)) {
    return `<a href="${deviceUrl(ip, port)}" target="_blank" rel="noopener noreferrer">${escapeHtml(target)} abrir painel</a>`;
  }

  const host = hostMap.get(ip);
  const firstPanel = host ? webPorts(host)[0] : null;
  if (firstPanel) {
    return `<code>${escapeHtml(target)}</code> · <a href="${deviceUrl(ip, firstPanel.port)}" target="_blank" rel="noopener noreferrer">abrir dispositivo</a>`;
  }

  return `<code>${escapeHtml(target)}</code>`;
}

function passCards(report) {
  const hosts = report.hosts || [];
  const allPorts = hosts.flatMap((host) => host.open_ports || []);
  const findings = report.findings || [];
  const hasSeverity = (severity) => findings.some((finding) => finding.severity === severity);
  const hasPort = (port) => allPorts.some((item) => item.port === port);
  const cards = [
    passCard(!hasSeverity("critical"), "Sem crítico automático", "Nenhum achado crítico foi detectado pelos testes leves."),
    passCard(!hasPort(23), "Telnet não detectado", "Boa notícia: a porta Telnet não apareceu aberta nos hosts testados."),
    passCard(!hasPort(21), "FTP não detectado", "FTP não apareceu aberto nos hosts testados."),
    passCard(!hasPort(3389), "RDP não detectado", "RDP não apareceu aberto nos hosts testados."),
  ];
  return cards;
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
        ${(host.role_hints || []).map((role) => `<code>${escapeHtml(role)}</code>`).join("") || "<code>sem perfil claro</code>"}
      </div>
      <div class="port-list">
        ${ports.length ? ports.map(portChip).join("") : "<span>Nenhuma porta comum aberta.</span>"}
      </div>
      <div class="device-links">
        ${links.length ? links.map((item) => `<a href="${deviceUrl(host.ip, item.port)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.label)}</a>`).join("") : '<span>Sem painel web detectado.</span>'}
      </div>
    </article>
  `;
}

function portChip(port) {
  const label = `${port.port}/${port.service}`;
  return `<span class="port-chip ${escapeHtml(port.severity)}">${escapeHtml(label)}</span>`;
}

function webPorts(host) {
  return (host.open_ports || [])
    .filter((port) => isWebPort(port.port))
    .map((port) => ({ port: port.port, label: `${schemeForPort(port.port).toUpperCase()} ${port.port}` }));
}

function isWebPort(port) {
  return [80, 443, 5000, 5001, 8000, 8080, 8443, 8888, 9000].includes(Number(port));
}

function schemeForPort(port) {
  return [443, 5001, 8443].includes(Number(port)) ? "https" : "http";
}

function deviceUrl(ip, port) {
  const scheme = schemeForPort(port);
  const defaultPort = (scheme === "http" && Number(port) === 80) || (scheme === "https" && Number(port) === 443);
  return `${scheme}://${ip}${defaultPort ? "" : `:${port}`}`;
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

function resetLive() {
  consoleEl.innerHTML = "";
  hostsCount.textContent = "0";
  portsCount.textContent = "0";
  highCount.textContent = "0";
  overallStatus.textContent = "-";
}

function resetBadAgent() {
  badAgentConsole.innerHTML = "";
  badHostsCount.textContent = "0";
  badEvidenceCount.textContent = "0";
  badHighCount.textContent = "0";
  badOverallStatus.textContent = "-";
  badAgentReport.className = "empty-state";
  badAgentReport.textContent = "Aguardando resultado do test_bad_agent.";
  badAgentReportStatus.textContent = "rodando";
}

function setStatus(text, className) {
  scanStatus.textContent = text;
  scanStatus.className = `status-pill ${className || "idle"}`;
}

function setBadStatus(text, className) {
  badAgentStatus.textContent = text;
  badAgentStatus.className = `status-pill ${className || "idle"}`;
}

function statusClass(status) {
  if (status === "critical" || status === "attention") {
    return "bad";
  }
  if (status === "review") {
    return "warn";
  }
  return "ok";
}

function addLine(kind, message) {
  const line = document.createElement("div");
  line.className = "console-line";
  const now = new Date().toLocaleTimeString("pt-BR", { hour12: false });
  line.innerHTML = `<time>${now}</time><span><strong class="${kind}">${escapeHtml(kind)}</strong> ${escapeHtml(message)}</span>`;
  consoleEl.appendChild(line);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function addBadLine(kind, message) {
  const line = document.createElement("div");
  line.className = "console-line";
  const now = new Date().toLocaleTimeString("pt-BR", { hour12: false });
  line.innerHTML = `<time>${now}</time><span><strong class="${kind}">${escapeHtml(kind)}</strong> ${escapeHtml(message)}</span>`;
  badAgentConsole.appendChild(line);
  badAgentConsole.scrollTop = badAgentConsole.scrollHeight;
}

function formatDate(value) {
  if (!value) {
    return "-";
  }
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

serviceStatus.textContent = "online";
loadReports();
loadSchedules();
