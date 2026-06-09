/* ── DOM helpers (hoisted function declarations usable from line 1) ───────── */

function qs(selector) {
  const el = document.querySelector(selector);
  if (!el) throw new Error(`Missing DOM element: ${selector}`);
  return el;
}

function openEventStream(url, onMessage, onError) {
  const source = new EventSource(url);
  source.onmessage = (event) => onMessage(JSON.parse(event.data));
  source.onerror = () => { onError(); source.close(); };
  return source;
}

/* ── i18n ───────────────────────────────────────────────── */

const TRANSLATIONS = {
  pt: {
    eyebrow: "Auditoria defensiva de rede",
    tabDashboard: "Dashboard", tabBadAgent: "Bad Agent", tabPerformance: "Performance", tabWebsite: "Website Security",
    newTest: "Novo teste", authorizedNetwork: "Rede autorizada", profile: "Perfil",
    profileQuick: "Rápido e leve", profileFull: "Completo controlado",
    btnRun: "Rodar agora", btnRefresh: "Atualizar",
    schedule: "Agendamento", interval: "Intervalo",
    int30m: "30 minutos", int1h: "1 hora", int6h: "6 horas", int1d: "1 dia",
    runFirstNow: "Executar a primeira checagem agora", btnCreateSchedule: "Criar agendamento",
    liveTitle: "Execução em tempo real", noScanRunning: "Nenhum teste em execução.",
    labelHosts: "Hosts", labelPorts: "Portas", labelCritHigh: "Críticos/Altos", labelStatus: "Status",
    savedReports: "Relatórios salvos", savedReportsHint: "Abra para ver riscos, acertos e links de correção.",
    visualReport: "Relatório visual", runOrOpenReport: "Execute um teste ou abra um relatório salvo.",
    noReportSelected: "Nenhum relatório selecionado ainda.",
    aiEndpoint: "Endpoint da IA", aiModel: "Modelo", aiApiKey: "API key da IA",
    apiKeyPlaceholder: "Opcional — não é salva", btnLoadModels: "Carregar modelos disponíveis",
    enterKeyHint: "Informe a API key para carregar modelos.",
    safeEvidencesHint: "Evidências seguras — sem senhas, resets ou exploits.",
    testAdminPanels: "Painéis admin HTTP/HTTPS", testInsecureServices: "Serviços inseguros",
    testCameraRtsp: "Câmeras / DVR RTSP", testSegmentation: "Segmentação fraca",
    testBruteforce: "Alvo para força bruta", testResetExposure: "Reset / reboot expostos",
    testUpnp: "UPnP / SSDP ativo",
    captureRtsp: "Capturar 1 frame RTSP sem credenciais quando o fluxo estiver aberto",
    btnRunBadAgent: "Rodar test_bad_agent",
    badAgentLiveTitle: "Execução adversária controlada", noAgentRunning: "Nenhum agente em execução.",
    labelEvidence: "Evidências", badAgentReportTitle: "Resultado do test_bad_agent",
    aiOnlyExplains: "IA usada apenas para explicar achados; testes continuam controlados.",
    noResultYet: "Nenhum resultado ainda.",
    networkInterface: "Interface de rede", interfacePlaceholder: "Auto, ex: wlan0",
    broadcastSample: "Amostra de broadcast",
    s10: "10 segundos", s15: "15 segundos", s30: "30 segundos", s60: "60 segundos",
    runSpeedtest: "Rodar speed test de internet", btnAnalyze: "Analisar performance",
    perfLiveTitle: "Execução da análise", noAnalysisRunning: "Nenhuma análise em execução.",
    labelBroadcast: "Broadcast/s", labelTalkers: "Talkers", labelDownload: "Download",
    perfReportTitle: "Network Performance Report", perfReportHint: "Dados locais, amostra passiva e speed test.",
    authorizedUrl: "URL autorizada", urlPlaceholder: "https://example.com",
    confirmAuthorized: "Confirmo que tenho autorização para testar este site",
    checkSensitivePaths: "Checar arquivos sensíveis comuns com requisições leves",
    btnTestWebsite: "Testar website", webLiveTitle: "Execução da análise web",
    noWebTestRunning: "Nenhum teste em execução.", labelFindings: "Achados", labelHttpStatus: "Status HTTP",
    webReportTitle: "Website Security Report",
    webReportHint: "Headers, TLS, cookies, formulários, CORS e exposição de arquivos.",
    statusWaiting: "aguardando", statusEmpty: "vazio", statusRunning: "rodando",
    statusDone: "concluído", statusError: "erro", statusFailed: "falhou",
    awaitingBadAgent: "Aguardando resultado do test_bad_agent.",
    awaitingPerformance: "Aguardando resultado da análise.",
    awaitingWebsite: "Aguardando resultado da análise web.",
    noSchedules: "Nenhum agendamento ativo.", scheduleEvery: "a cada",
    lastScan: "Último scan", next: "Próximo", btnRemove: "Remover",
    loadReportsFailed: "Não foi possível carregar relatórios.",
    noReportsYet: "Nenhum relatório gerado ainda.",
    btnViewPanel: "Ver painel", critHighLabel: "críticos/altos",
    openReportFailed: "Não foi possível abrir este relatório.",
    streamClosed: "Conexão de eventos encerrada.",
    tabCodeAnalysis: "Análise de Código",
    codePath: "Caminho do projeto", codePathPlaceholder: "/caminho/projeto ou requirements.txt",
    codeAnalysisHint: "Informe o diretório do projeto ou um arquivo requirements.txt para detectar vulnerabilidades conhecidas nas dependências.",
    btnAnalyzeCode: "Analisar dependências",
    codeAnalysisLiveTitle: "Análise SCA em tempo real", noCodeAnalysisRunning: "Nenhuma análise em execução.",
    labelVulns: "Vulnerabilidades", labelPackages: "Pacotes afetados",
    codeReportTitle: "Resultado da Análise SCA",
    codeReportHint: "Vulnerabilidades em dependências Python via pip-audit.",
    awaitingCodeAnalysis: "Aguardando resultado da análise SCA.",
    noVulnsFound: "Nenhuma vulnerabilidade encontrada — dependências limpas.",
    fixedIn: "Corrigido em", cveIds: "CVEs", advisoryId: "Advisory",
  },
  en: {
    eyebrow: "Defensive network audit",
    tabDashboard: "Dashboard", tabBadAgent: "Bad Agent", tabPerformance: "Performance", tabWebsite: "Website Security",
    newTest: "New test", authorizedNetwork: "Authorized network", profile: "Profile",
    profileQuick: "Quick and light", profileFull: "Full controlled",
    btnRun: "Run now", btnRefresh: "Refresh",
    schedule: "Schedule", interval: "Interval",
    int30m: "30 minutes", int1h: "1 hour", int6h: "6 hours", int1d: "1 day",
    runFirstNow: "Run first check now", btnCreateSchedule: "Create schedule",
    liveTitle: "Real-time execution", noScanRunning: "No test running.",
    labelHosts: "Hosts", labelPorts: "Ports", labelCritHigh: "Critical/High", labelStatus: "Status",
    savedReports: "Saved reports", savedReportsHint: "Open to see risks, findings and remediation links.",
    visualReport: "Visual report", runOrOpenReport: "Run a test or open a saved report.",
    noReportSelected: "No report selected yet.",
    aiEndpoint: "AI endpoint", aiModel: "Model", aiApiKey: "AI API key",
    apiKeyPlaceholder: "Optional — not saved", btnLoadModels: "Load available models",
    enterKeyHint: "Enter API key to load models.",
    safeEvidencesHint: "Safe evidence — no passwords, resets or exploits.",
    testAdminPanels: "HTTP/HTTPS admin panels", testInsecureServices: "Insecure services",
    testCameraRtsp: "Cameras / DVR RTSP", testSegmentation: "Weak segmentation",
    testBruteforce: "Brute-force target", testResetExposure: "Reset / reboot exposed",
    testUpnp: "UPnP / SSDP active",
    captureRtsp: "Capture 1 RTSP frame without credentials when stream is open",
    btnRunBadAgent: "Run test_bad_agent",
    badAgentLiveTitle: "Controlled adversarial execution", noAgentRunning: "No agent running.",
    labelEvidence: "Evidence", badAgentReportTitle: "test_bad_agent result",
    aiOnlyExplains: "AI used only to explain findings; tests remain controlled.",
    noResultYet: "No results yet.",
    networkInterface: "Network interface", interfacePlaceholder: "Auto, e.g. wlan0",
    broadcastSample: "Broadcast sample",
    s10: "10 seconds", s15: "15 seconds", s30: "30 seconds", s60: "60 seconds",
    runSpeedtest: "Run internet speed test", btnAnalyze: "Analyze performance",
    perfLiveTitle: "Analysis execution", noAnalysisRunning: "No analysis running.",
    labelBroadcast: "Broadcast/s", labelTalkers: "Talkers", labelDownload: "Download",
    perfReportTitle: "Network Performance Report", perfReportHint: "Local data, passive sample and speed test.",
    authorizedUrl: "Authorized URL", urlPlaceholder: "https://example.com",
    confirmAuthorized: "I confirm I have authorization to test this website",
    checkSensitivePaths: "Check common sensitive files with light requests",
    btnTestWebsite: "Test website", webLiveTitle: "Web analysis execution",
    noWebTestRunning: "No test running.", labelFindings: "Findings", labelHttpStatus: "HTTP status",
    webReportTitle: "Website Security Report",
    webReportHint: "Headers, TLS, cookies, forms, CORS and file exposure.",
    statusWaiting: "waiting", statusEmpty: "empty", statusRunning: "running",
    statusDone: "completed", statusError: "error", statusFailed: "failed",
    awaitingBadAgent: "Awaiting test_bad_agent result.",
    awaitingPerformance: "Awaiting analysis result.",
    awaitingWebsite: "Awaiting web analysis result.",
    noSchedules: "No active schedules.", scheduleEvery: "every",
    lastScan: "Last scan", next: "Next", btnRemove: "Remove",
    loadReportsFailed: "Could not load reports.",
    noReportsYet: "No reports generated yet.",
    btnViewPanel: "View panel", critHighLabel: "critical/high",
    openReportFailed: "Could not open this report.",
    streamClosed: "Event stream closed.",
    tabCodeAnalysis: "Code Analysis",
    codePath: "Project path", codePathPlaceholder: "/path/to/project or requirements.txt",
    codeAnalysisHint: "Enter the project directory or a requirements.txt file to detect known vulnerabilities in dependencies.",
    btnAnalyzeCode: "Analyze dependencies",
    codeAnalysisLiveTitle: "SCA analysis in real-time", noCodeAnalysisRunning: "No analysis running.",
    labelVulns: "Vulnerabilities", labelPackages: "Affected packages",
    codeReportTitle: "SCA Analysis Results",
    codeReportHint: "Python dependency vulnerabilities via pip-audit.",
    awaitingCodeAnalysis: "Awaiting SCA analysis result.",
    noVulnsFound: "No vulnerabilities found — clean dependencies.",
    fixedIn: "Fixed in", cveIds: "CVEs", advisoryId: "Advisory",
  },
  es: {
    eyebrow: "Auditoría defensiva de red",
    tabDashboard: "Dashboard", tabBadAgent: "Bad Agent", tabPerformance: "Rendimiento", tabWebsite: "Seguridad Web",
    newTest: "Nueva prueba", authorizedNetwork: "Red autorizada", profile: "Perfil",
    profileQuick: "Rápido y ligero", profileFull: "Completo controlado",
    btnRun: "Ejecutar ahora", btnRefresh: "Actualizar",
    schedule: "Programación", interval: "Intervalo",
    int30m: "30 minutos", int1h: "1 hora", int6h: "6 horas", int1d: "1 día",
    runFirstNow: "Ejecutar primera comprobación ahora", btnCreateSchedule: "Crear programación",
    liveTitle: "Ejecución en tiempo real", noScanRunning: "Ninguna prueba en ejecución.",
    labelHosts: "Hosts", labelPorts: "Puertos", labelCritHigh: "Críticos/Altos", labelStatus: "Estado",
    savedReports: "Informes guardados", savedReportsHint: "Abre para ver riesgos, hallazgos y enlaces de corrección.",
    visualReport: "Informe visual", runOrOpenReport: "Ejecuta una prueba o abre un informe guardado.",
    noReportSelected: "Ningún informe seleccionado aún.",
    aiEndpoint: "Endpoint de IA", aiModel: "Modelo", aiApiKey: "Clave API de IA",
    apiKeyPlaceholder: "Opcional — no se guarda", btnLoadModels: "Cargar modelos disponibles",
    enterKeyHint: "Introduce la clave API para cargar modelos.",
    safeEvidencesHint: "Evidencias seguras — sin contraseñas, resets ni exploits.",
    testAdminPanels: "Paneles admin HTTP/HTTPS", testInsecureServices: "Servicios inseguros",
    testCameraRtsp: "Cámaras / DVR RTSP", testSegmentation: "Segmentación débil",
    testBruteforce: "Objetivo de fuerza bruta", testResetExposure: "Reset / reboot expuestos",
    testUpnp: "UPnP / SSDP activo",
    captureRtsp: "Capturar 1 fotograma RTSP sin credenciales cuando el flujo esté abierto",
    btnRunBadAgent: "Ejecutar test_bad_agent",
    badAgentLiveTitle: "Ejecución adversarial controlada", noAgentRunning: "Ningún agente en ejecución.",
    labelEvidence: "Evidencias", badAgentReportTitle: "Resultado de test_bad_agent",
    aiOnlyExplains: "IA usada solo para explicar hallazgos; las pruebas siguen controladas.",
    noResultYet: "Sin resultados aún.",
    networkInterface: "Interfaz de red", interfacePlaceholder: "Auto, ej. wlan0",
    broadcastSample: "Muestra de broadcast",
    s10: "10 segundos", s15: "15 segundos", s30: "30 segundos", s60: "60 segundos",
    runSpeedtest: "Ejecutar test de velocidad", btnAnalyze: "Analizar rendimiento",
    perfLiveTitle: "Ejecución del análisis", noAnalysisRunning: "Ningún análisis en ejecución.",
    labelBroadcast: "Broadcast/s", labelTalkers: "Talkers", labelDownload: "Descarga",
    perfReportTitle: "Network Performance Report", perfReportHint: "Datos locales, muestra pasiva y test de velocidad.",
    authorizedUrl: "URL autorizada", urlPlaceholder: "https://example.com",
    confirmAuthorized: "Confirmo que tengo autorización para probar este sitio web",
    checkSensitivePaths: "Verificar archivos sensibles comunes con solicitudes ligeras",
    btnTestWebsite: "Probar sitio web", webLiveTitle: "Ejecución del análisis web",
    noWebTestRunning: "Ninguna prueba en ejecución.", labelFindings: "Hallazgos", labelHttpStatus: "Estado HTTP",
    webReportTitle: "Website Security Report",
    webReportHint: "Headers, TLS, cookies, formularios, CORS y exposición de archivos.",
    statusWaiting: "esperando", statusEmpty: "vacío", statusRunning: "ejecutando",
    statusDone: "completado", statusError: "error", statusFailed: "fallido",
    awaitingBadAgent: "Esperando resultado de test_bad_agent.",
    awaitingPerformance: "Esperando resultado del análisis.",
    awaitingWebsite: "Esperando resultado del análisis web.",
    noSchedules: "Ninguna programación activa.", scheduleEvery: "cada",
    lastScan: "Último escaneo", next: "Próximo", btnRemove: "Eliminar",
    loadReportsFailed: "No se pudieron cargar los informes.",
    noReportsYet: "Ningún informe generado aún.",
    btnViewPanel: "Ver panel", critHighLabel: "críticos/altos",
    openReportFailed: "No se pudo abrir este informe.",
    streamClosed: "Conexión de eventos cerrada.",
    tabCodeAnalysis: "Análisis de Código",
    codePath: "Ruta del proyecto", codePathPlaceholder: "/ruta/proyecto o requirements.txt",
    codeAnalysisHint: "Ingrese el directorio del proyecto o un archivo requirements.txt para detectar vulnerabilidades conocidas.",
    btnAnalyzeCode: "Analizar dependencias",
    codeAnalysisLiveTitle: "Análisis SCA en tiempo real", noCodeAnalysisRunning: "Ningún análisis en ejecución.",
    labelVulns: "Vulnerabilidades", labelPackages: "Paquetes afectados",
    codeReportTitle: "Resultados del Análisis SCA",
    codeReportHint: "Vulnerabilidades en dependencias Python vía pip-audit.",
    awaitingCodeAnalysis: "Esperando resultado del análisis SCA.",
    noVulnsFound: "No se encontraron vulnerabilidades — dependencias limpias.",
    fixedIn: "Corregido en", cveIds: "CVEs", advisoryId: "Advisory",
  },
  fr: {
    eyebrow: "Audit réseau défensif",
    tabDashboard: "Dashboard", tabBadAgent: "Bad Agent", tabPerformance: "Performance", tabWebsite: "Sécurité Web",
    newTest: "Nouveau test", authorizedNetwork: "Réseau autorisé", profile: "Profil",
    profileQuick: "Rapide et léger", profileFull: "Complet contrôlé",
    btnRun: "Lancer maintenant", btnRefresh: "Actualiser",
    schedule: "Planification", interval: "Intervalle",
    int30m: "30 minutes", int1h: "1 heure", int6h: "6 heures", int1d: "1 jour",
    runFirstNow: "Effectuer la première vérification maintenant", btnCreateSchedule: "Créer une planification",
    liveTitle: "Exécution en temps réel", noScanRunning: "Aucun test en cours.",
    labelHosts: "Hôtes", labelPorts: "Ports", labelCritHigh: "Critiques/Hauts", labelStatus: "Statut",
    savedReports: "Rapports sauvegardés", savedReportsHint: "Ouvrir pour voir les risques et liens de correction.",
    visualReport: "Rapport visuel", runOrOpenReport: "Lancez un test ou ouvrez un rapport sauvegardé.",
    noReportSelected: "Aucun rapport sélectionné.",
    aiEndpoint: "Endpoint IA", aiModel: "Modèle", aiApiKey: "Clé API IA",
    apiKeyPlaceholder: "Optionnel — non sauvegardé", btnLoadModels: "Charger les modèles disponibles",
    enterKeyHint: "Entrez la clé API pour charger les modèles.",
    safeEvidencesHint: "Preuves sécurisées — sans mots de passe, resets ni exploits.",
    testAdminPanels: "Panneaux admin HTTP/HTTPS", testInsecureServices: "Services non sécurisés",
    testCameraRtsp: "Caméras / DVR RTSP", testSegmentation: "Segmentation faible",
    testBruteforce: "Cible de force brute", testResetExposure: "Reset / reboot exposés",
    testUpnp: "UPnP / SSDP actif",
    captureRtsp: "Capturer 1 image RTSP sans identifiants quand le flux est ouvert",
    btnRunBadAgent: "Lancer test_bad_agent",
    badAgentLiveTitle: "Exécution adversariale contrôlée", noAgentRunning: "Aucun agent en cours.",
    labelEvidence: "Preuves", badAgentReportTitle: "Résultat de test_bad_agent",
    aiOnlyExplains: "IA utilisée uniquement pour expliquer les résultats ; tests restent contrôlés.",
    noResultYet: "Aucun résultat pour l'instant.",
    networkInterface: "Interface réseau", interfacePlaceholder: "Auto, ex. wlan0",
    broadcastSample: "Échantillon broadcast",
    s10: "10 secondes", s15: "15 secondes", s30: "30 secondes", s60: "60 secondes",
    runSpeedtest: "Lancer le test de vitesse", btnAnalyze: "Analyser les performances",
    perfLiveTitle: "Exécution de l'analyse", noAnalysisRunning: "Aucune analyse en cours.",
    labelBroadcast: "Broadcast/s", labelTalkers: "Talkers", labelDownload: "Téléchargement",
    perfReportTitle: "Network Performance Report", perfReportHint: "Données locales, échantillon passif et test de vitesse.",
    authorizedUrl: "URL autorisée", urlPlaceholder: "https://example.com",
    confirmAuthorized: "Je confirme avoir l'autorisation de tester ce site",
    checkSensitivePaths: "Vérifier les fichiers sensibles courants avec des requêtes légères",
    btnTestWebsite: "Tester le site web", webLiveTitle: "Exécution de l'analyse web",
    noWebTestRunning: "Aucun test en cours.", labelFindings: "Résultats", labelHttpStatus: "Statut HTTP",
    webReportTitle: "Website Security Report",
    webReportHint: "Headers, TLS, cookies, formulaires, CORS et exposition de fichiers.",
    statusWaiting: "en attente", statusEmpty: "vide", statusRunning: "en cours",
    statusDone: "terminé", statusError: "erreur", statusFailed: "échoué",
    awaitingBadAgent: "En attente du résultat de test_bad_agent.",
    awaitingPerformance: "En attente du résultat de l'analyse.",
    awaitingWebsite: "En attente du résultat de l'analyse web.",
    noSchedules: "Aucune planification active.", scheduleEvery: "toutes les",
    lastScan: "Dernier scan", next: "Prochain", btnRemove: "Supprimer",
    loadReportsFailed: "Impossible de charger les rapports.",
    noReportsYet: "Aucun rapport généré pour l'instant.",
    btnViewPanel: "Voir le panneau", critHighLabel: "critiques/hauts",
    openReportFailed: "Impossible d'ouvrir ce rapport.",
    streamClosed: "Flux d'événements fermé.",
    tabCodeAnalysis: "Analyse de Code",
    codePath: "Chemin du projet", codePathPlaceholder: "/chemin/projet ou requirements.txt",
    codeAnalysisHint: "Entrez le répertoire du projet ou un fichier requirements.txt pour détecter les vulnérabilités connues.",
    btnAnalyzeCode: "Analyser les dépendances",
    codeAnalysisLiveTitle: "Analyse SCA en temps réel", noCodeAnalysisRunning: "Aucune analyse en cours.",
    labelVulns: "Vulnérabilités", labelPackages: "Paquets affectés",
    codeReportTitle: "Résultats de l'Analyse SCA",
    codeReportHint: "Vulnérabilités des dépendances Python via pip-audit.",
    awaitingCodeAnalysis: "En attente du résultat de l'analyse SCA.",
    noVulnsFound: "Aucune vulnérabilité trouvée — dépendances saines.",
    fixedIn: "Corrigé en", cveIds: "CVEs", advisoryId: "Advisory",
  },
};

let currentLang = localStorage.getItem("lang") || "pt";

function t(key) {
  return (TRANSLATIONS[currentLang] || TRANSLATIONS.pt)[key] || key;
}

function setLanguage(lang) {
  if (!TRANSLATIONS[lang]) return;
  currentLang = lang;
  localStorage.setItem("lang", lang);
  document.documentElement.lang = lang === "pt" ? "pt-BR" : lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const val = t(el.dataset.i18n);
    if (val) el.textContent = val;
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const val = t(el.dataset.i18nPlaceholder);
    if (val) el.placeholder = val;
  });
  document.querySelectorAll(".lang-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.lang === lang);
  });
}

const scanForm = qs("#scanForm");
const scheduleForm = qs("#scheduleForm");
const targetInput = qs("#target");
const profileInput = qs("#profile");
const intervalInput = qs("#interval");
const runNowInput = qs("#runNow");
const consoleEl = qs("#console");
const activeScan = qs("#activeScan");
const scanStatus = qs("#scanStatus");
const serviceStatus = qs("#serviceStatus");
const reportsEl = qs("#reports");
const schedulesEl = qs("#schedules");
const refreshReports = qs("#refreshReports");
const reportSubtitle = qs("#reportSubtitle");
const reportStatus = qs("#reportStatus");
const reportContent = qs("#reportContent");
const tabButtons = document.querySelectorAll("[data-tab]");
const dashboardTab = qs("#dashboardTab");
const badAgentTab = qs("#badAgentTab");
const performanceTab = qs("#performanceTab");
const websiteSecurityTab = qs("#websiteSecurityTab");
const codeAnalysisTab = qs("#codeAnalysisTab");
const badAgentForm = qs("#badAgentForm");
const badAgentTarget = qs("#badAgentTarget");
const aiEndpoint = qs("#aiEndpoint");
const aiModel = qs("#aiModel");
const aiApiKey = qs("#aiApiKey");
const loadAiModels = qs("#loadAiModels");
const aiModelStatus = qs("#aiModelStatus");
const captureRtspFrame = qs("#captureRtspFrame");
const badAgentActive = qs("#badAgentActive");
const badAgentStatus = qs("#badAgentStatus");
const badAgentConsole = qs("#badAgentConsole");
const badHostsCount = qs("#badHostsCount");
const badEvidenceCount = qs("#badEvidenceCount");
const badHighCount = qs("#badHighCount");
const badOverallStatus = qs("#badOverallStatus");
const badAgentSubtitle = qs("#badAgentSubtitle");
const badAgentReportStatus = qs("#badAgentReportStatus");
const badAgentReport = qs("#badAgentReport");
const performanceForm = qs("#performanceForm");
const perfInterface = qs("#perfInterface");
const perfSampleSeconds = qs("#perfSampleSeconds");
const runSpeedtest = qs("#runSpeedtest");
const perfAiEndpoint = qs("#perfAiEndpoint");
const perfAiModel = qs("#perfAiModel");
const perfAiApiKey = qs("#perfAiApiKey");
const loadPerfAiModels = qs("#loadPerfAiModels");
const perfAiModelStatus = qs("#perfAiModelStatus");
const performanceActive = qs("#performanceActive");
const performanceStatus = qs("#performanceStatus");
const performanceConsole = qs("#performanceConsole");
const perfBroadcastPps = qs("#perfBroadcastPps");
const perfTalkers = qs("#perfTalkers");
const perfDownload = qs("#perfDownload");
const perfOverallStatus = qs("#perfOverallStatus");
const performanceSubtitle = qs("#performanceSubtitle");
const performanceReportStatus = qs("#performanceReportStatus");
const performanceReport = qs("#performanceReport");
const websiteSecurityForm = qs("#websiteSecurityForm");
const websiteUrl = qs("#websiteUrl");
const websiteAuthorized = qs("#websiteAuthorized");
const websiteSensitivePaths = qs("#websiteSensitivePaths");
const webAiEndpoint = qs("#webAiEndpoint");
const webAiModel = qs("#webAiModel");
const webAiApiKey = qs("#webAiApiKey");
const loadWebAiModels = qs("#loadWebAiModels");
const webAiModelStatus = qs("#webAiModelStatus");
const websiteActive = qs("#websiteActive");
const websiteStatus = qs("#websiteStatus");
const websiteConsole = qs("#websiteConsole");
const webFindingsCount = qs("#webFindingsCount");
const webHighCount = qs("#webHighCount");
const webHttpStatus = qs("#webHttpStatus");
const webOverallStatus = qs("#webOverallStatus");
const websiteSubtitle = qs("#websiteSubtitle");
const websiteReportStatus = qs("#websiteReportStatus");
const websiteReport = qs("#websiteReport");
const hostsCount = qs("#hostsCount");
const portsCount = qs("#portsCount");
const highCount = qs("#highCount");
const overallStatus = qs("#overallStatus");
const codeAnalysisForm = qs("#codeAnalysisForm");
const codeProjectPath = qs("#codeProjectPath");
const codeAnalysisActive = qs("#codeAnalysisActive");
const codeAnalysisStatus = qs("#codeAnalysisStatus");
const codeAnalysisConsole = qs("#codeAnalysisConsole");
const codeVulnsCount = qs("#codeVulnsCount");
const codePackagesCount = qs("#codePackagesCount");
const codeHighCount = qs("#codeHighCount");
const codeOverallStatus = qs("#codeOverallStatus");
const codeAnalysisSubtitle = qs("#codeAnalysisSubtitle");
const codeAnalysisReportStatus = qs("#codeAnalysisReportStatus");
const codeAnalysisReport = qs("#codeAnalysisReport");

let activeSource = null;
let activeBadSource = null;
let activePerformanceSource = null;
let activeWebsiteSource = null;
let activeCodeSource = null;

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
  codeAnalysisTab.classList.toggle("active", tabName === "codeAnalysis");
}

/* ── Event listeners ────────────────────────────────────── */

scanForm.addEventListener("submit", async (event) => { event.preventDefault(); await startScan(); });
scheduleForm.addEventListener("submit", async (event) => { event.preventDefault(); await createSchedule(); });
badAgentForm.addEventListener("submit", async (event) => { event.preventDefault(); await startBadAgent(); });
performanceForm.addEventListener("submit", async (event) => { event.preventDefault(); await startPerformanceAnalysis(); });
websiteSecurityForm.addEventListener("submit", async (event) => { event.preventDefault(); await startWebsiteSecurity(); });
codeAnalysisForm.addEventListener("submit", async (event) => { event.preventDefault(); await startCodeAnalysis(); });
loadAiModels.addEventListener("click", async () => { await loadAvailableAiModels(aiEndpoint, aiApiKey, aiModel, aiModelStatus); });
loadPerfAiModels.addEventListener("click", async () => { await loadAvailableAiModels(perfAiEndpoint, perfAiApiKey, perfAiModel, perfAiModelStatus); });
loadWebAiModels.addEventListener("click", async () => { await loadAvailableAiModels(webAiEndpoint, webAiApiKey, webAiModel, webAiModelStatus); });
refreshReports.addEventListener("click", () => { loadReports(); loadSchedules(); });

/* ── Scan ───────────────────────────────────────────────── */

async function startScan() {
  resetLive();
  setStatus(t("statusRunning"), "warn");

  const response = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: targetInput.value.trim(), profile: profileInput.value }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Erro desconhecido" }));
    setStatus(t("statusError"), "bad");
    addLine("erro", error.detail || "Não foi possível iniciar o scan.");
    return;
  }

  const data = await response.json();
  activeScan.textContent = `Scan ${data.scan_id} em ${targetInput.value.trim()}`;
  streamScan(data.scan_id);
}

function streamScan(scanId) {
  if (activeSource) activeSource.close();
  activeSource = openEventStream(
    `/api/scans/${scanId}/events`,
    (payload) => handleEvent(payload, scanId),
    () => addLine("stream", t("streamClosed"))
  );
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
    setStatus(t("statusDone"), statusClass(report.summary?.overall_status));
    renderReport(report);
    addLine("relatorio", "Relatório visual atualizado.");
    loadReports();
  }

  if (event === "failed") setStatus(t("statusFailed"), "bad");
}

/* ── Bad Agent ──────────────────────────────────────────── */

async function startBadAgent() {
  resetBadAgent();
  setBadStatus(t("statusRunning"), "warn");

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
    setBadStatus(t("statusError"), "bad");
    addBadLine("erro", error.detail || "Não foi possível iniciar o test_bad_agent.");
    return;
  }

  const data = await response.json();
  badAgentActive.textContent = `Agente ${data.agent_id} em ${badAgentTarget.value.trim()}`;
  streamBadAgent(data.agent_id);
}

function streamBadAgent(agentId) {
  if (activeBadSource) activeBadSource.close();
  activeBadSource = openEventStream(
    `/api/bad-agent/${agentId}/events`,
    handleBadAgentEvent,
    () => addBadLine("stream", t("streamClosed"))
  );
}

function handleBadAgentEvent(payload) {
  const event = payload.event || "info";
  addBadLine(event, payload.message || "");

  if (event === "host_found") badHostsCount.textContent = String(Number(badHostsCount.textContent) + 1);

  if (event === "finished") {
    renderBadAgentReport(payload.data);
    setBadStatus(t("statusDone"), statusClass(payload.data.summary?.overall_status));
  }

  if (event === "failed") setBadStatus(t("statusFailed"), "bad");
}

/* ── Performance ────────────────────────────────────────── */

async function startPerformanceAnalysis() {
  resetPerformance();
  setPerformanceStatus(t("statusRunning"), "warn");

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
    setPerformanceStatus(t("statusError"), "bad");
    addPerformanceLine("erro", error.detail || "Não foi possível iniciar a análise.");
    return;
  }

  const data = await response.json();
  performanceActive.textContent = `Análise ${data.analysis_id}`;
  streamPerformance(data.analysis_id);
}

function streamPerformance(analysisId) {
  if (activePerformanceSource) activePerformanceSource.close();
  activePerformanceSource = openEventStream(
    `/api/performance/${analysisId}/events`,
    handlePerformanceEvent,
    () => addPerformanceLine("stream", t("streamClosed"))
  );
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
    setPerformanceStatus(t("statusDone"), statusClass(payload.data.summary?.overall_status));
  }

  if (event === "failed") setPerformanceStatus(t("statusFailed"), "bad");
}

/* ── Website Security ──────────────────────────────────── */

async function startWebsiteSecurity() {
  resetWebsiteSecurity();
  setWebsiteStatus(t("statusRunning"), "warn");

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
    setWebsiteStatus(t("statusError"), "bad");
    addWebsiteLine("erro", error.detail || "Não foi possível iniciar o teste de website.");
    return;
  }

  const data = await response.json();
  websiteActive.textContent = `Website scan ${data.scan_id}`;
  streamWebsiteSecurity(data.scan_id);
}

function streamWebsiteSecurity(scanId) {
  if (activeWebsiteSource) activeWebsiteSource.close();
  activeWebsiteSource = openEventStream(
    `/api/website-security/${scanId}/events`,
    handleWebsiteEvent,
    () => addWebsiteLine("stream", t("streamClosed"))
  );
}

function handleWebsiteEvent(payload) {
  const event = payload.event || "info";
  addWebsiteLine(event, payload.message || "");

  if (event === "http_done") {
    webHttpStatus.textContent = payload.data.status || "—";
  }

  if (event === "finished") {
    renderWebsiteReport(payload.data);
    setWebsiteStatus(t("statusDone"), statusClass(payload.data.summary?.overall_status));
  }

  if (event === "failed") setWebsiteStatus(t("statusFailed"), "bad");
}

/* ── Code Analysis (SCA) ────────────────────────────────── */

async function startCodeAnalysis() {
  resetCodeAnalysis();
  setCodeAnalysisStatus(t("statusRunning"), "warn");

  const response = await fetch("/api/code-analysis", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ project_path: codeProjectPath.value.trim() }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Erro desconhecido" }));
    setCodeAnalysisStatus(t("statusError"), "bad");
    addCodeLine("erro", error.detail || "Não foi possível iniciar a análise.");
    return;
  }

  const data = await response.json();
  codeAnalysisActive.textContent = `Análise ${data.analysis_id} — ${codeProjectPath.value.trim()}`;
  streamCodeAnalysis(data.analysis_id);
}

function streamCodeAnalysis(analysisId) {
  if (activeCodeSource) activeCodeSource.close();
  activeCodeSource = openEventStream(
    `/api/code-analysis/${analysisId}/events`,
    handleCodeAnalysisEvent,
    () => addCodeLine("stream", t("streamClosed"))
  );
}

function handleCodeAnalysisEvent(payload) {
  const event = payload.event || "info";
  addCodeLine(event, payload.message || "");

  if (event === "analysis_done" && payload.data?.summary) {
    const s = payload.data.summary;
    codeVulnsCount.textContent = String(s.total_vulnerabilities || 0);
    codePackagesCount.textContent = String(s.packages_affected || 0);
    const counts = s.by_severity || {};
    codeHighCount.textContent = String((counts.critical || 0) + (counts.high || 0));
    codeOverallStatus.textContent = s.overall_status || "—";
  }

  if (event === "finished") {
    renderCodeAnalysisReport(payload.data);
    setCodeAnalysisStatus(t("statusDone"), statusClass(payload.data.summary?.overall_status));
  }

  if (event === "failed") setCodeAnalysisStatus(t("statusFailed"), "bad");
}

function renderCodeAnalysisReport(report) {
  const summary = report.summary || {};
  const counts = summary.by_severity || {};
  const highTotal = (counts.critical || 0) + (counts.high || 0);
  const vulns = report.vulnerabilities || [];

  codeVulnsCount.textContent = String(summary.total_vulnerabilities || 0);
  codePackagesCount.textContent = String(summary.packages_affected || 0);
  codeHighCount.textContent = String(highTotal);
  codeOverallStatus.textContent = summary.overall_status || "—";
  codeAnalysisSubtitle.textContent = `${report.project_path} · ${formatDate(report.finished_at)} · ${summary.total_vulnerabilities || 0} vulns`;
  codeAnalysisReportStatus.textContent = summary.overall_status || "ok";
  codeAnalysisReportStatus.className = `status-pill ${statusClass(summary.overall_status)}`;
  codeAnalysisReport.className = "report-body";

  const vulnList = vulns.length
    ? vulns.map(vulnCard).join("")
    : `<div class="empty-state">${t("noVulnsFound")}</div>`;

  codeAnalysisReport.innerHTML = `
    <div class="report-metrics">
      ${metricCard("Status", summary.overall_status || "ok")}
      ${metricCard(t("labelVulns"), summary.total_vulnerabilities || 0)}
      ${metricCard(t("labelPackages"), summary.packages_affected || 0)}
      ${metricCard(t("labelCritHigh"), highTotal)}
    </div>

    <div class="export-bar" data-report-type="code-analysis" data-report-id="${escapeHtml(report.id)}">
      <div><strong>Exportar</strong><span>Baixar relatório em JSON.</span></div>
      <a href="/api/code-analysis/${escapeHtml(report.id)}/report.json" class="secondary" style="padding:6px 12px;border-radius:6px;text-decoration:none;font-size:13px">JSON</a>
    </div>

    ${buildSection(t("codeReportTitle"), vulns.length, `
      ${buildFilterBar(vulns)}
      <div class="finding-list">${vulnList}</div>
    `)}
  `;

  setupInteractivity(codeAnalysisReport);
}

function vulnCard(vuln) {
  const sev = vuln.severity || "unknown";
  const sevDisplay = SEV_LABELS[sev] || sev;
  const cves = (vuln.cve_ids || []).map((id) => `<a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(id)}" target="_blank" rel="noopener noreferrer">${escapeHtml(id)}</a>`).join(", ");
  const fix = (vuln.fix_versions || []).length ? `<p><strong>${t("fixedIn")}:</strong> ${escapeHtml(vuln.fix_versions.join(", "))}</p>` : "";
  return `
    <article class="finding" data-severity="${escapeHtml(sev)}">
      <div class="finding-header">
        <span class="severity ${escapeHtml(sev)}">${escapeHtml(sevDisplay)}</span>
        <h4>${escapeHtml(vuln.package)} ${escapeHtml(vuln.installed_version)}</h4>
      </div>
      <p><strong>${t("advisoryId")}:</strong> <code>${escapeHtml(vuln.advisory_id)}</code>${cves ? ` · <strong>${t("cveIds")}:</strong> ${cves}` : ""}</p>
      <p>${escapeHtml(vuln.description || "")}</p>
      ${fix}
    </article>
  `;
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
    schedulesEl.innerHTML = `<div class="item"><p>${t("noSchedules")}</p></div>`;
    return;
  }

  for (const schedule of schedules) {
    const item = document.createElement("div");
    item.className = "item";
    item.innerHTML = `
      <strong>${escapeHtml(schedule.target)} ${t("scheduleEvery")} ${schedule.interval_minutes} min</strong>
      <p>${t("lastScan")}: ${schedule.last_scan_id || "—"}<br />${t("next")}: ${formatDate(schedule.next_run_at)}</p>
      <div class="item-actions">
        <button class="secondary" data-remove="${schedule.id}" style="width:auto;padding:5px 10px;font-size:12px">${t("btnRemove")}</button>
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
    reportsEl.innerHTML = `<div class="item"><p>${t("loadReportsFailed")}</p></div>`;
    return;
  }

  const reports = await response.json();
  reportsEl.innerHTML = "";

  if (!reports.length) {
    reportsEl.innerHTML = `<div class="item"><p>${t("noReportsYet")}</p></div>`;
    return;
  }

  for (const report of reports) {
    const counts = report.findings || {};
    const highs = (counts.critical || 0) + (counts.high || 0);
    const item = document.createElement("div");
    item.className = "item";
    item.innerHTML = `
      <strong>${escapeHtml(report.target || "—")} · ${escapeHtml(report.status || "—")}</strong>
      <p>${formatDate(report.finished_at)} · hosts: ${report.hosts ?? 0} · ${t("critHighLabel")}: ${highs}</p>
      <div class="item-actions">
        <button class="secondary" data-view-report="${report.id}" style="width:auto;padding:5px 10px;font-size:12px">${t("btnViewPanel")}</button>
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
    reportContent.textContent = t("openReportFailed");
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

    ${buildSection("CVEs por serviço (NVD)", cveCount(hosts), buildCveSection(hosts), true)}

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
  const cveCount = (port.cves || []).length;
  const cveBadge = cveCount ? ` <span class="cve-badge">${cveCount} CVE${cveCount > 1 ? "s" : ""}</span>` : "";
  return `<span class="port-chip ${escapeHtml(port.severity)}" title="${escapeHtml(port.note || "")}">${escapeHtml(`${port.port}/${port.service}`)}${cveBadge}</span>`;
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

function cveCount(hosts) {
  return hosts.reduce((n, h) => n + (h.open_ports || []).reduce((m, p) => m + (p.cves || []).length, 0), 0);
}

function buildCveSection(hosts) {
  const seen = new Map();
  for (const host of hosts) {
    for (const port of host.open_ports || []) {
      for (const cve of port.cves || []) {
        if (!seen.has(cve.id)) seen.set(cve.id, { ...cve, service: port.service });
      }
    }
  }
  if (!seen.size) return '<div class="empty-state">Nenhuma CVE retornada pelo NVD para os serviços detectados.</div>';
  return `<div class="finding-list">${[...seen.values()].map(cveCard).join("")}</div>`;
}

function cveCard(cve) {
  const sev = cve.severity || "unknown";
  const score = cve.score != null ? ` · Score: ${cve.score}` : "";
  return `
    <article class="finding" data-severity="${escapeHtml(sev)}">
      <div class="finding-header">
        <span class="severity ${escapeHtml(sev)}">${(SEV_LABELS[sev] || sev).toUpperCase()}</span>
        <h4>${escapeHtml(cve.id)} · ${escapeHtml(cve.service)}</h4>
      </div>
      <p>${escapeHtml(cve.description || "")}${score}</p>
      <div class="device-links"><a href="${escapeHtml(cve.url)}" target="_blank" rel="noopener noreferrer">Ver no NVD</a></div>
    </article>
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
function setCodeAnalysisStatus(text, cls) { codeAnalysisStatus.textContent = text; codeAnalysisStatus.className = `status-pill ${cls || "idle"}`; }

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
  badAgentReport.textContent = t("awaitingBadAgent");
  badAgentReportStatus.textContent = t("statusRunning");
}

function resetPerformance() {
  performanceConsole.innerHTML = "";
  perfBroadcastPps.textContent = "0";
  perfTalkers.textContent = "0";
  perfDownload.textContent = "—";
  perfOverallStatus.textContent = "—";
  performanceReport.className = "empty-state";
  performanceReport.textContent = t("awaitingPerformance");
  performanceReportStatus.textContent = t("statusRunning");
}

function resetWebsiteSecurity() {
  websiteConsole.innerHTML = "";
  webFindingsCount.textContent = "0";
  webHighCount.textContent = "0";
  webHttpStatus.textContent = "—";
  webOverallStatus.textContent = "—";
  websiteReport.className = "empty-state";
  websiteReport.textContent = t("awaitingWebsite");
  websiteReportStatus.textContent = t("statusRunning");
}

function resetCodeAnalysis() {
  codeAnalysisConsole.innerHTML = "";
  codeVulnsCount.textContent = "0";
  codePackagesCount.textContent = "0";
  codeHighCount.textContent = "0";
  codeOverallStatus.textContent = "—";
  codeAnalysisReport.className = "empty-state";
  codeAnalysisReport.textContent = t("awaitingCodeAnalysis");
  codeAnalysisReportStatus.textContent = t("statusRunning");
}

/* ── Console lines ──────────────────────────────────────── */

function addConsoleLine(targetEl, kind, message) {
  const line = document.createElement("div");
  line.className = "console-line";
  const now = new Date().toLocaleTimeString(currentLang === "pt" ? "pt-BR" : currentLang, { hour12: false });
  line.innerHTML = `<time>${now}</time><span class="console-tag ${escapeHtml(kind)}">${escapeHtml(kind)}</span><span class="console-msg">${escapeHtml(message)}</span>`;
  targetEl.appendChild(line);
  targetEl.scrollTop = targetEl.scrollHeight;
}

function addLine(kind, message) { addConsoleLine(consoleEl, kind, message); }
function addBadLine(kind, message) { addConsoleLine(badAgentConsole, kind, message); }
function addPerformanceLine(kind, message) { addConsoleLine(performanceConsole, kind, message); }
function addWebsiteLine(kind, message) { addConsoleLine(websiteConsole, kind, message); }
function addCodeLine(kind, message) { addConsoleLine(codeAnalysisConsole, kind, message); }

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
  return new Date(value).toLocaleString(currentLang === "pt" ? "pt-BR" : currentLang);
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

document.querySelectorAll(".lang-btn").forEach((btn) => {
  btn.addEventListener("click", () => setLanguage(btn.dataset.lang));
});
setLanguage(currentLang);
serviceStatus.textContent = "online";
loadReports();
loadSchedules();
