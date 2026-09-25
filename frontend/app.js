const api = '/api/v1';
const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const pretty = (value) => esc(JSON.stringify(value, null, 2));

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
  loadCaseExtras(report.analysis_id);
}

  function downloadPdf(caseId) {
    const link = document.createElement('a');
    link.href = `${api}/cases/${encodeURIComponent(caseId)}/report.pdf`;
    link.download = `emailsentinel-report-${caseId}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
  }
function showTab(tab) { document.querySelectorAll('.tab').forEach((button) => button.classList.toggle('active', button.dataset.tab === tab)); ['overview','network','case','raw'].forEach((name) => { const element = $(`#tab-${name}`); if (element) element.hidden = name !== tab; }); }

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
  try { const data = await request('/cases?limit=20'); $('#caseList').innerHTML = data.cases.length ? data.cases.map((item) => `<div class="case-item" data-case="${esc(item.analysis_id)}"><div class="case-subject">${esc(item.subject || 'Untitled message')}</div><div class="case-meta"><span>${esc(item.classification || 'queued')} · ${esc(item.risk_score ?? '—')}</span><span class="badge ${riskClass(item.risk_level)}">${esc(item.risk_level || item.status || 'NEW')}</span></div></div>`).join('') : '<p class="muted">No cases yet.</p>'; document.querySelectorAll('[data-case]').forEach((item) => item.addEventListener('click', () => loadCase(item.dataset.case))); } catch (error) { $('#caseList').innerHTML = `<p class="muted">${esc(error.message)}</p>`; }
}

async function checkApi() { try { await fetch('/health'); $('#apiState').textContent = 'online'; $('.pulse').classList.add('ok'); } catch { $('#apiState').textContent = 'offline'; } }

$('#uploadForm').addEventListener('submit', async (event) => { event.preventDefault(); const file = $('#emailFile').files[0]; if (!file) { $('#uploadMessage').textContent = 'Choose an .eml file first.'; return; } const button = event.target.querySelector('button'); button.disabled = true; button.textContent = 'Analyzing...'; $('#uploadMessage').textContent = ''; try { const data = await request('/analyze-email', { method:'POST', body: (() => { const form = new FormData(); form.append('file', file); return form; })() }); if (data.status === 'QUEUED') { $('#uploadMessage').textContent = 'Queued. Waiting for worker...'; let result; for (let attempt = 0; attempt < 30; attempt += 1) { await new Promise((resolve) => setTimeout(resolve, 1000)); result = await request(`/analysis/${data.analysis_id}`); if (result.status === 'COMPLETED') break; } if (!result || result.status !== 'COMPLETED') throw new Error('Analysis is still queued. Check the case queue shortly.'); renderReport(result.result); } else renderReport(data); loadCases(); } catch (error) { $('#uploadMessage').textContent = error.message; } finally { button.disabled = false; button.innerHTML = 'Analyze email <span>→</span>'; } });

$('#emailFile').addEventListener('change', (event) => { $('#fileLabel').textContent = event.target.files[0]?.name || 'Choose an .eml file'; });
['dragenter','dragover'].forEach((eventName) => $('#dropzone').addEventListener(eventName, (event) => { event.preventDefault(); $('#dropzone').classList.add('drag'); }));
['dragleave','drop'].forEach((eventName) => $('#dropzone').addEventListener(eventName, (event) => { event.preventDefault(); $('#dropzone').classList.remove('drag'); }));
$('#dropzone').addEventListener('drop', (event) => { $('#emailFile').files = event.dataTransfer.files; $('#fileLabel').textContent = event.dataTransfer.files[0]?.name || 'Choose an .eml file'; });
$('#refreshCases').addEventListener('click', loadCases);
checkApi(); loadCases();
