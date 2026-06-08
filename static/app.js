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

const hostsCount = document.querySelector("#hostsCount");
const portsCount = document.querySelector("#portsCount");
const highCount = document.querySelector("#highCount");
const overallStatus = document.querySelector("#overallStatus");

let activeSource = null;

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await startScan();
});

scheduleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await createSchedule();
});

refreshReports.addEventListener("click", () => {
  loadReports();
  loadSchedules();
});

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
    addLine("relatorio", `Markdown: /api/scans/${scanId}/report.md`);
    loadReports();
  }

  if (event === "failed") {
    setStatus("falhou", "bad");
  }
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
      <a href="${report.markdown_url}">Markdown</a>
      <a href="${report.json_url}">JSON</a>
    `;
    reportsEl.appendChild(item);
  }
}

function resetLive() {
  consoleEl.innerHTML = "";
  hostsCount.textContent = "0";
  portsCount.textContent = "0";
  highCount.textContent = "0";
  overallStatus.textContent = "-";
}

function setStatus(text, className) {
  scanStatus.textContent = text;
  scanStatus.className = `status-pill ${className || "idle"}`;
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
