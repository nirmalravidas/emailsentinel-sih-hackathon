const api = '/api/v1';
const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const pretty = (value) => esc(JSON.stringify(value, null, 2));
let activeCaseId = null;

function setTheme(theme) {
  const isDark = theme === 'dark';
  document.documentElement.dataset.theme = isDark ? 'dark' : 'light';
  $('#themeToggle').textContent = isDark ? '☼' : '◐';
  $('#themeToggle').setAttribute('aria-label', `Switch to ${isDark ? 'light' : 'dark'} mode`);
  $('#themeToggle').title = `Switch to ${isDark ? 'light' : 'dark'} mode`;
  document.querySelectorAll('.relay-graph').forEach((graph) => graph._emailSentinelNetwork?.setOptions({ nodes: { font: { color: isDark ? '#e6f3f7' : '#17211f' } }, edges: { font: { color: isDark ? '#e6f3f7' : '#17211f' } } }));
  localStorage.setItem('emailsentinel-theme', isDark ? 'dark' : 'light');
}

async function request(path, options) {
  const response = await fetch(`${api}${path}`, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}

function riskClass(level) { return String(level || '').toLowerCase(); }
function chips(values) { return (values || []).length ? `<div class="chips">${values.map((value) => `<span class="chip">${esc(value)}</span>`).join('')}</div>` : '<span class="muted">None observed</span>'; }
function facts(items) { return `<dl class="facts">${items.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value || 'Not available')}</dd>`).join('')}</dl>`; }

function renderReport(report, caseData = {}) {
    activeCaseId = report.analysis_id || caseData.analysis_id || null;
  const threat = report.threat_assessment || {};
  const email = report.email_summary || {};
  const iocs = report.indicators_of_compromise || {};
  const auth = report.authentication || {};
  const independentAuth = auth.independent_validation || {};
  const relay = report.relay_analysis || {};
  const geolocation = report.geolocation || {};
  const urls = report.url_analysis || [];
  const domains = report.domain_intelligence || {};
  const threatIntel = report.threat_intelligence || {};
  const nlp = report.nlp_analysis || {};
  const identity = report.identity_analysis || {};
  const level = threat.risk_level || 'Unknown';
  $('#results').innerHTML = `<article class="result-card">
      <div class="result-head"><div><p class="eyebrow">FORENSIC REPORT</p><h2>${esc(email.subject || 'Untitled message')}</h2><small>${esc(report.analysis_id)} · ${esc(email.date || 'date unavailable')}</small></div><div class="report-actions"><button class="download-button" id="downloadPdf" type="button" title="Download PDF report">↓ PDF</button><div class="risk ${riskClass(level)}"><strong>${esc(threat.risk_score ?? '—')}</strong><small>${esc(level.toUpperCase())} RISK · ${esc(threat.classification || 'unknown')}</small></div></div></div>
    <nav class="tabs"><button class="tab active" data-tab="overview">Overview</button><button class="tab" data-tab="network">Network & URLs</button><button class="tab" data-tab="case">Case intelligence</button><button class="tab" data-tab="raw">Complete payload</button></nav>
    <div class="result-grid" id="tab-overview">
      <section class="result-card"><h3>MESSAGE IDENTITY</h3>${facts([['From',email.from],['To',email.to],['Reply-To',email.reply_to],['Return-Path',email.return_path],['Message ID',email.message_id]])}</section>
      <section class="result-card"><h3>DECISION SIGNALS</h3><div class="stack">${(threat.reasons || []).map((reason) => `<div class="line">${esc(reason)}</div>`).join('') || '<span class="muted">No reasons recorded</span>'}</div></section>
      <section class="result-card"><h3>INDICATORS OF COMPROMISE</h3><div class="stack"><div class="line"><b>IP addresses</b>${chips(iocs.ips)}</div><div class="line"><b>Domains</b>${chips(iocs.domains)}</div><div class="line"><b>URLs</b>${chips(iocs.urls)}</div><div class="line"><b>Attachment SHA-256</b>${chips(iocs.attachment_sha256)}</div></div></section>
      <section class="result-card"><h3>AUTHENTICATION & IDENTITY</h3>${facts([['SPF header',auth.spf],['SPF verified',independentAuth.spf?.status],['DKIM header',auth.dkim],['DKIM verified',independentAuth.dkim?.status],['DMARC header',auth.dmarc],['DMARC verified',independentAuth.dmarc?.status],['SPF aligned',independentAuth.dmarc?.spf_aligned],['DKIM aligned',independentAuth.dmarc?.dkim_aligned],['Mismatch',identity.identity_mismatch ? 'Detected' : 'Not detected'],['Lookalike',identity.matched_brand || 'None detected']])}</section>
      ${(report.warnings || []).map((warning) => `<div class="warning full">${esc(warning)}</div>`).join('')}
      <section class="result-card full"><h3>THREAT INTELLIGENCE</h3><p class="muted">${esc(threatIntel.message || threatIntel.disclaimer || 'External reputation correlation')}</p><pre class="raw-json">${pretty(threatIntel)}</pre></section>
    </div>
    <div class="result-grid" id="tab-network" hidden><section class="result-card"><h3>RELAY CHAIN</h3>${facts([['Origin IP',relay.probable_origin_ip],['Hop count',relay.hop_count],['Order',relay.chain_order],['Summary',relay.path_summary]])}<div class="stack">${(relay.relay_chain || []).map((hop) => `<div class="line">${esc(hop.from_host || 'unknown')} → ${esc(hop.by_host || 'unknown')} · ${esc(hop.from_ip || 'no IP')}</div>`).join('')}</div></section><section class="result-card"><h3>INFRASTRUCTURE GEOLOCATION</h3><p class="muted">Approximate network infrastructure location for the probable origin IP. This does not identify the attacker’s physical location.</p>${geolocation.probable_origin_ip ? facts([['IP',geolocation.probable_origin_ip.ip],['City',geolocation.probable_origin_ip.city],['Region',geolocation.probable_origin_ip.region],['Country',geolocation.probable_origin_ip.country],['ISP',geolocation.probable_origin_ip.isp],['Organization',geolocation.probable_origin_ip.organization],['ASN',geolocation.probable_origin_ip.asn],['Status',geolocation.probable_origin_ip.status]]) : facts([['Status',geolocation.status],['Message',geolocation.message]])}${geolocation.disclaimer ? `<div class="warning">${esc(geolocation.disclaimer)}</div>` : ''}</section><section class="result-card"><h3>OTHER PUBLIC RELAYS</h3>${(geolocation.other_public_ips || []).length ? geolocation.other_public_ips.map((location) => `<div class="line">${facts([['IP',location.ip],['Location',[location.city,location.region,location.country].filter(Boolean).join(', ')],['ISP',location.isp],['Organization',location.organization]])}</div>`).join('') : '<span class="muted">No additional public relay IPs</span>'}</section><section class="result-card"><h3>DOMAIN INTELLIGENCE</h3><pre class="raw-json">${pretty(domains)}</pre></section><section class="result-card full"><h3>URL ANALYSIS (${urls.length})</h3><pre class="raw-json">${pretty(urls)}</pre></section></div>
    <div class="result-grid" id="tab-case" hidden><section class="result-card"><h3>NLP ANALYSIS</h3>${facts([['Confidence',nlp.confidence],['Keywords',(nlp.keywords || []).join(', ')],['Social engineering',(nlp.social_engineering_indicators || []).join(', ')]] )}<pre class="raw-json">${pretty(nlp.class_probabilities)}</pre></section><section class="result-card"><h3>SCORE BREAKDOWN</h3><pre class="raw-json">${pretty(threat.score_breakdown)}</pre></section><section class="result-card full"><h3>TIMELINE / CORRELATION</h3><div id="caseExtras"><p class="muted">Loading case intelligence...</p></div></section></div>
    <div class="result-grid" id="tab-raw" hidden><section class="result-card full"><h3>COMPLETE BACKEND RESPONSE</h3><pre class="raw-json">${pretty(report)}</pre></section></div>
  </article>`;
    document.querySelectorAll('.tab').forEach((button) => button.addEventListener('click', () => showTab(button.dataset.tab)));
    $('#downloadPdf').addEventListener('click', () => downloadPdf(report.analysis_id));
    $('#tab-network').insertAdjacentHTML('afterbegin', '<section class="result-card full visual-card"><h3>INFRASTRUCTURE TRACE MAP</h3><p class="muted">Approximate public-IP infrastructure locations from the message relay chain. Select a marker for details.</p><div id="infrastructureMap" class="infrastructure-map"></div></section><section class="result-card full visual-card"><h3>RELAY PATH GRAPH</h3><p class="muted">Oldest observed source hop to newest receiving relay. Dashed edges show the transition between header hops.</p><div id="relayGraph" class="relay-graph"></div></section>');
    initializeNetworkVisuals(report);
  loadCaseExtras(report.analysis_id);
}

  function initializeNetworkVisuals(report) {
    const geolocation = report.geolocation || {};
    const origin = geolocation.probable_origin_ip || {};
    const relay = report.relay_analysis || {};
    const locations = [origin, ...(geolocation.other_public_ips || [])]
      .filter((location) => Number.isFinite(Number(location.latitude)) && Number.isFinite(Number(location.longitude)));
    const mapElement = $('#infrastructureMap');
    if (mapElement && window.L) {
      const map = L.map(mapElement, { scrollWheelZoom: false });
      mapElement._emailSentinelMap = map;
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { attribution: '&copy; OpenStreetMap contributors' }).addTo(map);
      const bounds = [];
      locations.forEach((location) => {
        const point = [Number(location.latitude), Number(location.longitude)];
        bounds.push(point);
        L.marker(point).addTo(map).bindPopup(`<strong>${esc(location.ip || 'Public IP')}</strong><br>${esc([location.city, location.region, location.country].filter(Boolean).join(', ') || 'Location unavailable')}<br>${esc(location.organization || location.isp || 'Infrastructure')}`);
      });
      if (bounds.length) map.fitBounds(bounds, { padding: [24, 24], maxZoom: 5 });
      else map.setView([20, 0], 2);
    } else if (mapElement) {
      mapElement.innerHTML = '<p class="muted map-fallback">Map library unavailable. Coordinates remain available in the complete payload.</p>';
    }

    const graphElement = $('#relayGraph');
    if (graphElement && window.vis && relay.relay_chain?.length) {
      const nodes = [];
      const edges = [];
      relay.relay_chain.forEach((hop, index) => {
        const from = hop.from_host || hop.from_ip || `hop-${index + 1}`;
        const to = hop.by_host || `relay-${index + 1}`;
        nodes.push({ id: `from-${index}`, label: `${from}${hop.from_ip ? `\n${hop.from_ip}` : ''}`, title: 'Received-header source hop', group: index === 0 ? 'origin' : 'relay' });
        nodes.push({ id: `by-${index}`, label: to, title: 'Receiving relay', group: 'relay' });
        edges.push({ from: `from-${index}`, to: `by-${index}`, arrows: 'to', label: hop.protocol || 'SMTP' });
        if (index < relay.relay_chain.length - 1) edges.push({ from: `by-${index}`, to: `from-${index + 1}`, arrows: 'to', dashes: true });
      });
      const graphTextColor = document.documentElement.dataset.theme === 'dark' ? '#e6f3f7' : '#17211f';
      graphElement._emailSentinelNetwork = new vis.Network(graphElement, { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) }, { autoResize: true, physics: { stabilization: true }, interaction: { hover: true }, nodes: { shape: 'dot', size: 18, font: { face: 'ui-monospace', size: 11, color: graphTextColor }, borderWidth: 2 }, groups: { origin: { color: { background: '#e67842', border: '#b44d43' } }, relay: { color: { background: '#c9e8d2', border: '#5f876b' } } }, edges: { color: '#819088', font: { face: 'ui-monospace', size: 9, color: graphTextColor } } });
    } else if (graphElement) {
      graphElement.innerHTML = '<p class="muted graph-fallback">No relay hops were available to graph.</p>';
    }
  }

  function downloadPdf(caseId) {
    const link = document.createElement('a');
    link.href = `${api}/cases/${encodeURIComponent(caseId)}/report.pdf`;
    link.download = `emailsentinel-report-${caseId}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
  }
function showTab(tab) { document.querySelectorAll('.tab').forEach((button) => button.classList.toggle('active', button.dataset.tab === tab)); ['overview','network','case','raw'].forEach((name) => { const element = $(`#tab-${name}`); if (element) element.hidden = name !== tab; }); if (tab === 'network') requestAnimationFrame(() => $('#infrastructureMap')?._emailSentinelMap?.invalidateSize()); }

async function loadCaseExtras(caseId) {
  try {
    const [timeline, iocs, correlation, alerts] = await Promise.all([request(`/cases/${caseId}/timeline`), request(`/cases/${caseId}/iocs`), request(`/cases/${caseId}/correlation`), request('/alerts?limit=50')]);
    $('#caseExtras').innerHTML = `<div class="stack"><div class="line"><b>Timeline</b><pre class="raw-json">${pretty(timeline.events)}</pre></div><div class="line"><b>Persisted IOCs</b><pre class="raw-json">${pretty(iocs.iocs)}</pre></div><div class="line"><b>Shared indicators</b><pre class="raw-json">${pretty(correlation)}</pre></div><div class="line"><b>Recorded alerts</b><pre class="raw-json">${pretty(alerts.alerts)}</pre></div></div>`;
  } catch (error) { $('#caseExtras').innerHTML = `<p class="warning">${esc(error.message)}</p>`; }
}

async function loadCase(caseId) {
  try { const data = await request(`/cases/${caseId}/report`); renderReport(data, { analysis_id: caseId }); } catch (error) { $('#uploadMessage').textContent = error.message; }
}

async function loadCases() {
  try { const data = await request('/cases?limit=20'); $('#caseList').innerHTML = data.cases.length ? data.cases.map((item) => `<div class="case-item" data-case="${esc(item.analysis_id)}"><button class="case-open" type="button"><span class="case-subject">${esc(item.subject || 'Untitled message')}</span><span class="case-meta"><span>${esc(item.classification || 'queued')} · ${esc(item.risk_score ?? '—')}</span><span class="badge ${riskClass(item.risk_level)}">${esc(item.risk_level || item.status || 'NEW')}</span></span></button><button class="delete-case" type="button" data-delete-case="${esc(item.analysis_id)}" aria-label="Delete case ${esc(item.subject || item.analysis_id)}" title="Delete case">×</button></div>`).join('') : '<p class="muted">No cases yet.</p>'; document.querySelectorAll('.case-open').forEach((button) => button.addEventListener('click', () => loadCase(button.closest('[data-case]').dataset.case))); document.querySelectorAll('[data-delete-case]').forEach((button) => button.addEventListener('click', deleteCase)); } catch (error) { $('#caseList').innerHTML = `<p class="muted">${esc(error.message)}</p>`; }
}

async function deleteCase(event) {
  const button = event.currentTarget;
  const caseId = button.dataset.deleteCase;
  if (!window.confirm('Delete this case and its forensic data? This cannot be undone.')) return;
  button.disabled = true;
  try {
    await request(`/cases/${encodeURIComponent(caseId)}`, { method: 'DELETE' });
    if (activeCaseId === caseId) {
      activeCaseId = null;
      $('#results').innerHTML = '<div class="empty-state"><div class="empty-mark">+</div><p class="eyebrow">READY FOR EVIDENCE</p><h2>Your investigation will appear here</h2><p>Upload a message to see the risk decision, identity checks, network intelligence, and indicators of compromise.</p></div>';
    }
    await loadCases();
  } catch (error) {
    button.disabled = false;
    window.alert(error.message);
  }
}

async function checkApi() { try { await fetch('/health'); $('#apiState').textContent = 'online'; $('.pulse').classList.add('ok'); } catch { $('#apiState').textContent = 'offline'; } }

$('#uploadForm').addEventListener('submit', async (event) => { event.preventDefault(); const file = $('#emailFile').files[0]; if (!file) { $('#uploadMessage').textContent = 'Choose an .eml file first.'; return; } const button = event.target.querySelector('button'); button.disabled = true; button.textContent = 'Analyzing...'; $('#uploadMessage').textContent = ''; try { const data = await request('/analyze-email', { method:'POST', body: (() => { const form = new FormData(); form.append('file', file); return form; })() }); if (data.status === 'QUEUED') { $('#uploadMessage').textContent = 'Queued. Waiting for worker...'; let result; for (let attempt = 0; attempt < 30; attempt += 1) { await new Promise((resolve) => setTimeout(resolve, 1000)); result = await request(`/analysis/${data.analysis_id}`); if (result.status === 'COMPLETED') break; } if (!result || result.status !== 'COMPLETED') throw new Error('Analysis is still queued. Check the case queue shortly.'); renderReport(result.result); } else renderReport(data); loadCases(); } catch (error) { $('#uploadMessage').textContent = error.message; } finally { button.disabled = false; button.innerHTML = 'Analyze email <span>→</span>'; } });

$('#emailFile').addEventListener('change', (event) => { $('#fileLabel').textContent = event.target.files[0]?.name || 'Choose an .eml file'; });
['dragenter','dragover'].forEach((eventName) => $('#dropzone').addEventListener(eventName, (event) => { event.preventDefault(); $('#dropzone').classList.add('drag'); }));
['dragleave','drop'].forEach((eventName) => $('#dropzone').addEventListener(eventName, (event) => { event.preventDefault(); $('#dropzone').classList.remove('drag'); }));
$('#dropzone').addEventListener('drop', (event) => { $('#emailFile').files = event.dataTransfer.files; $('#fileLabel').textContent = event.dataTransfer.files[0]?.name || 'Choose an .eml file'; });
$('#refreshCases').addEventListener('click', loadCases);
$('#themeToggle').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
const savedTheme = localStorage.getItem('emailsentinel-theme');
setTheme(savedTheme === 'dark' ? 'dark' : 'light');
checkApi(); loadCases();
