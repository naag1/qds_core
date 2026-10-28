import React, {useCallback, useEffect, useMemo, useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const CAPTURE = 'http://127.0.0.1:8765';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [page, setPage] = useState('alerts');
  const [alerts, setAlerts] = useState([]);
  const [sensors, setSensors] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [ai, setAi] = useState(null);
  const [aiTestResult, setAiTestResult] = useState('');
  const [live, setLive] = useState({available: false, active: false});
  const [notice, setNotice] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [severity, setSeverity] = useState('all');
  const [status, setStatus] = useState('all');
  const [file, setFile] = useState(null);
  const [uploadResult, setUploadResult] = useState(null);

  const auth = useMemo(() => ({Authorization: `Bearer ${token}`}), [token]);
  const request = useCallback(async (path, options = {}) => {
    const response = await fetch(`${API}${path}`, {
      ...options,
      headers: {...auth, ...options.headers},
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401) {
        localStorage.removeItem('token');
        setToken('');
      }
      throw new Error(data.detail || `Request failed (${response.status})`);
    }
    return data;
  }, [auth]);

  const loadDashboard = useCallback(async () => {
    if (!token) return;
    try {
      const [nextAlerts, nextSensors, aiStatus] = await Promise.all([
        request('/api/v1/alerts?limit=250'),
        request('/api/v1/sensors'),
        request('/api/v1/ai/status'),
      ]);
      setAlerts(nextAlerts);
      setSensors(nextSensors);
      setAi(aiStatus);
      if (selectedId) {
        const nextDetail = await request(`/api/v1/alerts/${selectedId}`);
        setDetail(nextDetail);
      }
      setError('');
    } catch (err) {
      setError(err.message);
    }
  }, [request, selectedId, token]);

  useEffect(() => {
    if (!token) return undefined;
    localStorage.setItem('token', token);
    loadDashboard();
    const refresh = window.setInterval(loadDashboard, 8000);
    return () => window.clearInterval(refresh);
  }, [loadDashboard, token]);

  useEffect(() => {
    if (!token) return undefined;
    let mounted = true;
    const pollCapture = async () => {
      try {
        const response = await fetch(`${CAPTURE}/healthz`, {signal: AbortSignal.timeout(1500)});
        const data = await response.json();
        if (mounted) setLive({available: response.ok && data.pktmon_found, active: !!data.capture_active});
      } catch {
        if (mounted) setLive({available: false, active: false});
      }
    };
    pollCapture();
    const timer = window.setInterval(pollCapture, 2500);
    return () => {mounted = false; window.clearInterval(timer);};
  }, [token]);

  const filteredAlerts = useMemo(() => alerts.filter(item =>
    (severity === 'all' || item.severity === severity) && (status === 'all' || item.status === status)
  ), [alerts, severity, status]);
  const openCount = alerts.filter(item => !['closed', 'false_positive'].includes(item.status)).length;
  const priorityCount = alerts.filter(item => ['high', 'critical'].includes(item.severity) && !['closed', 'false_positive'].includes(item.status)).length;
  const onlineSensors = sensors.filter(item => item.status === 'online').length;

  async function selectAlert(id) {
    setSelectedId(id);
    try {setDetail(await request(`/api/v1/alerts/${id}`));}
    catch (err) {setError(err.message);}
  }

  async function updateTriage(nextStatus) {
    if (!detail) return;
    setBusy('triage');
    try {
      await request(`/api/v1/alerts/${detail.id}/triage`, {
        method: 'PATCH', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({status: nextStatus}),
      });
      setNotice(`Alert #${detail.id} moved to ${nextStatus.replace('_', ' ')}.`);
      await loadDashboard();
    } catch (err) {setError(err.message);}
    finally {setBusy('');}
  }

  async function retryExplanation() {
    if (!detail) return;
    setBusy('explanation');
    try {
      await request(`/api/v1/alerts/${detail.id}/explanation`, {method: 'POST'});
      setNotice('Explanation queued. The alert will update as the analyst responds.');
      await selectAlert(detail.id);
    } catch (err) {setError(err.message);}
    finally {setBusy('');}
  }

  async function testAi() {
    setBusy('ai-test');
    setAiTestResult('');
    setError('');
    setNotice(null);
    try {
      const result = await request('/api/v1/ai/test', {method: 'POST'});
      setAiTestResult(result.response_preview || 'The model responded successfully, but returned an empty preview.');
      setNotice(`AI request completed with ${result.model}.`);
      await loadDashboard();
    } catch (err) {setError(err.message);}
    finally {setBusy('');}
  }

  async function startLive() {
    setBusy('live-start');
    try {
      const response = await fetch(`${CAPTURE}/api/session/start`, {method: 'POST', headers: auth});
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || `Capture helper failed (${response.status})`);
      setLive({available: true, active: true});
      setNotice('Live capture started on Windows network adapters. Stop it to analyze the captured flows.');
    } catch (err) {setError(err.message);}
    finally {setBusy('');}
  }

  async function stopLive() {
    setBusy('live-stop');
    try {
      const response = await fetch(`${CAPTURE}/api/session/stop`, {method: 'POST', headers: auth});
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || `Capture analysis failed (${response.status})`);
      setLive({available: true, active: false});
      setNotice(`Capture analyzed: ${data.flows} flows, ${data.alerts} alerts.`);
      setPage('alerts');
      await loadDashboard();
    } catch (err) {setError(err.message);}
    finally {setBusy('');}
  }

  function goLive() {
    setPage('alerts');
    if (live.available) return startLive();
    setNotice('Start the QDS live capture helper from an Administrator PowerShell window; it will appear here when connected.');
    window.setTimeout(() => document.getElementById('live-capture')?.scrollIntoView({behavior: 'smooth', block: 'center'}), 50);
  }

  async function uploadPcap(event) {
    event.preventDefault();
    if (!file) return;
    setBusy('upload');
    setUploadResult(null);
    const form = new FormData();
    form.append('file', file);
    try {
      const result = await request('/api/v1/analyze/pcap', {method: 'POST', body: form});
      setUploadResult(result);
      setNotice(`PCAP review complete: ${result.flows} flows analyzed and ${result.alerts} alerts found.`);
      setFile(null);
      event.target.reset();
      await loadDashboard();
      if (result.alerts) setPage('alerts');
    } catch (err) {setError(err.message);}
    finally {setBusy('');}
  }

  function signOut() {
    localStorage.removeItem('token');
    setToken(''); setAlerts([]); setSensors([]); setDetail(null); setSelectedId(null);
  }

  if (!token) return <Login onToken={setToken} />;

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#overview" onClick={event => {event.preventDefault(); setPage('alerts');}}>
        <span className="brand-mark">Q</span><span><strong>QDS</strong><small>THREAT OPERATIONS</small></span>
      </a>
      <div className="nav-label">WORKSPACE</div>
      <button className={`nav-item ${page === 'alerts' ? 'active' : ''}`} onClick={() => setPage('alerts')}><span className="nav-icon">◈</span> Alert queue <span className="nav-count">{openCount}</span></button>
      <button className={`nav-item ${page === 'pcap' ? 'active' : ''}`} onClick={() => setPage('pcap')}><span className="nav-icon">⇧</span> PCAP investigation</button>
      <div className="sidebar-bottom">
        <div className="system-card"><span className="status-dot good" /><div><strong>Detection engine</strong><small>CPU · model {"1.0.0"}</small></div></div>
        <button className="profile" onClick={signOut}><span className="avatar">A</span><span><strong>Administrator</strong><small>Sign out</small></span><span className="profile-arrow">↗</span></button>
      </div>
    </aside>

    <main className="main-area">
      <header className="topbar">
        <div className="breadcrumbs"><span>QDS</span><span className="crumb-sep">/</span><strong>{page === 'alerts' ? 'Alert queue' : 'PCAP investigation'}</strong></div>
        <div className="top-actions">
          <span className={`live-indicator ${live.active ? 'capturing' : ''}`}><span className="status-dot" />{live.active ? 'CAPTURING' : onlineSensors ? `${onlineSensors} SENSOR${onlineSensors === 1 ? '' : 'S'} ONLINE` : 'NO LIVE SENSOR'}</span>
          {live.active ? <button className="button danger" onClick={stopLive} disabled={!!busy}>{busy === 'live-stop' ? 'Analyzing…' : 'Stop & investigate'}</button> : <button className="button primary" onClick={goLive} disabled={!!busy}><span>◉</span> Go live</button>}
        </div>
      </header>

      <div className="content">
        {error && <div className="banner error-banner"><span>{error}</span><button onClick={() => setError('')} aria-label="Dismiss error">×</button></div>}
        {notice && <div className="banner notice-banner"><span>{notice}</span><button onClick={() => setNotice(null)} aria-label="Dismiss notice">×</button></div>}

        {page === 'alerts' ? <>
          <div className="page-heading">
            <div><div className="eyebrow">MONITORING / DETECTION</div><h1>Security operations</h1><p>Review detections, validate evidence, and coordinate response.</p></div>
            <div className="heading-actions"><button className="button secondary" onClick={() => setPage('pcap')}>＋ Investigate PCAP</button><button className="button primary" onClick={goLive} disabled={!!busy}><span className="pulse-dot" /> Go live</button></div>
          </div>

          <section className="metrics-grid" aria-label="Alert summary">
            <Metric label="Open alerts" value={openCount} sub="Awaiting analyst review" icon="◈" />
            <Metric label="High priority" value={priorityCount} sub="High or critical severity" icon="△" tone="amber" />
            <Metric label="Sensors online" value={onlineSensors} sub={sensors.length ? `${sensors.length} registered` : 'No capture sources connected'} icon="⌁" tone="green" />
            <Metric label="AI analyst" value={ai?.model_available ? 'Ready' : 'Offline'} sub={ai?.model || 'Checking connection'} icon="✳" tone={ai?.model_available ? 'green' : 'muted'} />
          </section>

          <section className="work-grid">
            <div className="panel alert-panel">
              <div className="panel-heading">
                <div><h2>Alert queue</h2><p>Detections from live sensors and PCAP reviews</p></div>
                <div className="filters"><label><span className="sr-only">Filter by severity</span><select value={severity} onChange={event => setSeverity(event.target.value)}><option value="all">All severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label><span className="sr-only">Filter by status</span><select value={status} onChange={event => setStatus(event.target.value)}><option value="all">All status</option><option value="new">New</option><option value="investigating">Investigating</option><option value="closed">Closed</option><option value="false_positive">False positive</option></select></label></div>
              </div>
              <div className="table-wrap">
                <table><thead><tr><th>SEVERITY</th><th>AI VERDICT</th><th>SOURCE</th><th>OBSERVED</th><th>STATUS</th></tr></thead>
                  <tbody>{filteredAlerts.map(item => <tr key={item.id} onClick={() => selectAlert(item.id)} className={selectedId === item.id ? 'selected' : ''} tabIndex="0" onKeyDown={event => event.key === 'Enter' && selectAlert(item.id)}>
                    <td><Severity value={item.severity} /></td><td><Verdict value={item.verdict} /><small className="cell-sub">ML: {item.detection?.prediction || 'Anomaly detected'}</small></td><td>{item.sensor_id}<small className="cell-sub">{item.detection?.confidence != null ? `${Math.round(item.detection.confidence * 100)}% ML confidence` : 'Flow analysis'}</small></td><td>{formatTime(item.created_at)}</td><td><Status value={item.status} /></td>
                  </tr>)}</tbody>
                </table>
                {!filteredAlerts.length && <div className="empty-state"><div className="empty-icon">⌁</div><h3>No alerts to show</h3><p>{alerts.length ? 'Change the filters to see other detections.' : 'No alerts have been created. Start a live capture or review a PCAP to begin.'}</p><button className="button secondary" onClick={() => setPage('pcap')}>Review a PCAP</button></div>}
              </div>
              <div className="table-footer"><span>Showing {filteredAlerts.length} of {alerts.length} alerts</span><button className="text-button" onClick={loadDashboard}>↻ Refresh</button></div>
            </div>

            <div className="panel detail-panel">
              {detail ? <>
                <div className="detail-head"><div><div className="eyebrow">INVESTIGATION / #{detail.id}</div><h2>Alert details</h2></div><button className="icon-button" onClick={() => {setSelectedId(null);setDetail(null);}} aria-label="Close alert details">×</button></div>
                <div className="detail-summary"><Severity value={detail.severity} /><Status value={detail.status} /><Verdict value={detail.verdict} /><span className="detail-time">{formatTime(detail.created_at)}</span></div>
                <div className="detail-section"><h3>Detection evidence</h3><div className="data-grid"><Data label="ML prediction (preliminary)" value={detail.detection?.prediction} /><Data label="AI analyst verdict" value={verdictText(detail.verdict)} /><Data label="Confidence" value={detail.detection?.confidence != null ? `${(detail.detection.confidence * 100).toFixed(1)}%` : '—'} /><Data label="Source" value={detail.flow?.src_ip} /><Data label="Destination" value={`${detail.flow?.dst_ip || '—'}:${detail.flow?.dst_port ?? '—'}`} /></div></div>
                <div className="detail-section"><h3>Evidence</h3>{detail.detection?.rule_evidence?.length ? <div className="evidence-list">{detail.detection.rule_evidence.map(rule => <div className="evidence-item" key={rule.id}><div><strong>{rule.id.replaceAll('_', ' ')}</strong><p>{rule.rationale}</p></div><span className="mitre">{rule.mitre?.join(' · ')}</span></div>)}</div> : <p className="muted-copy">No deterministic rules matched this flow.</p>}</div>
                <div className="detail-section ai-section"><div className="section-title"><h3>AI analyst assistance</h3><span className={`ai-state ${detail.explanation_status || 'unknown'}`}><span className="status-dot" />{(detail.explanation_status || 'unknown').replace('_', ' ')}</span></div>
                  {detail.explanation ? <MarkdownReport content={detail.explanation} error={detail.explanation_status === 'unavailable'} /> : <p className="muted-copy">{detail.explanation_status === 'running' || detail.explanation_status === 'queued' ? 'The analyst is reviewing this alert. This panel refreshes automatically.' : 'No analyst response is available for this alert yet.'}</p>}
                  {!ai?.model_available && <div className="inline-warning">{ai?.error || 'The configured Ollama model is not ready.'}</div>}
                  {['unavailable', 'not_queued', 'not_requested', 'review_required'].includes(detail.explanation_status) && <button className="button secondary small-button" onClick={retryExplanation} disabled={!!busy || !ai?.model_available}>{busy === 'explanation' ? 'Queueing…' : 'Retry explanation'}</button>}
                </div>
                <div className="detail-actions"><button className="button secondary" onClick={() => updateTriage('investigating')} disabled={!!busy || detail.status === 'investigating'}>Investigate</button><button className="button quiet" onClick={() => updateTriage('false_positive')} disabled={!!busy}>Mark false positive</button><button className="button primary" onClick={() => updateTriage('closed')} disabled={!!busy || detail.status === 'closed'}>Close alert</button></div>
              </> : <div className="detail-empty"><div className="empty-icon">◈</div><h3>Select an alert</h3><p>Choose a row to review its flow metrics, detection evidence, and analyst notes.</p></div>}
            </div>
          </section>
        </> : <PcapPage file={file} setFile={setFile} uploadPcap={uploadPcap} busy={busy} uploadResult={uploadResult} ai={ai} />}

        <section className="bottom-grid">
          <div className="panel live-panel" id="live-capture">
            <div className="panel-heading"><div><div className="eyebrow">LIVE COLLECTION</div><h2>Investigate live traffic</h2><p>Capture packets from this Windows host and analyze resulting flows.</p></div><span className={`status-pill ${live.available ? 'connected' : 'disconnected'}`}><span className="status-dot" />{live.available ? 'Helper connected' : 'Helper offline'}</span></div>
            {live.available ? <div className="live-control"><div className="live-copy"><strong>{live.active ? 'Capture is running' : 'Ready to capture'}</strong><span>{live.active ? 'Capture is bounded to a 64 MB circular buffer. Stop it to process the flows.' : 'Packet Monitor will capture on Windows network adapters.'}</span></div>{live.active ? <button className="button danger" onClick={stopLive} disabled={!!busy}>{busy === 'live-stop' ? 'Analyzing…' : 'Stop & investigate'}</button> : <button className="button primary" onClick={startLive} disabled={!!busy}>{busy === 'live-start' ? 'Starting…' : 'Start capture'}</button>}</div> : <div className="helper-instructions"><div><strong>Start the local capture helper as Administrator</strong><p>Windows requires administrator access for packet capture. Open an elevated PowerShell in the project folder and run:</p><code>.Start-Live-Capture.ps1</code></div><span className="step-number">01</span></div>}
          </div>
          <div className="panel ai-health-panel"><div className="panel-heading"><div><div className="eyebrow">EXPLANATION SERVICE</div><h2>AI analyst connection</h2><p>Ollama model status and request/response check.</p></div><span className={`status-pill ${ai?.model_available ? 'connected' : 'disconnected'}`}><span className="status-dot" />{ai?.model_available ? 'Ready' : 'Unavailable'}</span></div><div className="ai-health-detail"><div><small>Provider</small><strong>Ollama</strong></div><div><small>Configured model</small><strong>{ai?.model || 'Checking…'}</strong></div></div>{ai?.error && <p className="inline-warning">{ai.error}</p>}<button className="button secondary" onClick={testAi} disabled={!!busy || !ai?.model_available}>{busy === 'ai-test' ? 'Waiting for model…' : 'Send test request'}</button>{busy === 'ai-test' && <p className="ai-test-pending">The local model may take up to a minute to generate its first response.</p>}{aiTestResult && <div className="ai-test-response" role="status"><strong>Model response</strong><p>{aiTestResult}</p></div>}</div>
        </section>
        <footer className="app-footer"><span>QDS · Network threat investigation</span><span>ML detection · Ollama AI analyst</span></footer>
      </div>
    </main>
  </div>;
}

function Metric({label, value, sub, icon, tone = 'blue'}) {
  return <article className="metric-card"><div className={`metric-icon ${tone}`}>{icon}</div><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-sub">{sub}</div></article>;
}

function Severity({value = 'low'}) {return <span className={`severity severity-${value}`}><span className="severity-dot" />{value}</span>;}
function verdictText(value) {return ({pending: 'Awaiting report', benign: 'Benign', malicious: 'Malicious', unavailable: 'Unavailable', review_required: 'Needs review'})[value] || 'Awaiting report';}
function Verdict({value = 'pending'}) {return <span className={`verdict verdict-${value}`}><span className="status-dot" />{verdictText(value)}</span>;}
function MarkdownReport({content, error = false}) {
  return <div className={`markdown-report ${error ? 'ai-error-copy' : ''}`}>{markdownBlocks(content).map((block, index) => {
    if (block.type === 'heading') return React.createElement(`h${block.level}`, {key: index}, inlineMarkdown(block.text));
    if (block.type === 'paragraph') return <p key={index}>{inlineMarkdown(block.text)}</p>;
    if (block.type === 'list') {
      const List = block.ordered ? 'ol' : 'ul';
      return <List key={index}>{block.items.map((item, itemIndex) => <li key={itemIndex}>{inlineMarkdown(item)}</li>)}</List>;
    }
    if (block.type === 'code') return <pre key={index}><code>{block.text}</code></pre>;
    if (block.type === 'verdict') return <div key={index} className={`report-verdict report-verdict-${block.value.toLowerCase()}`}><span>FINAL VERDICT</span><strong>{block.value}</strong></div>;
    return null;
  })}</div>;
}
function markdownBlocks(content = '') {
  const blocks = [];
  let paragraph = [];
  let list = null;
  let code = null;
  const flushParagraph = () => {if (paragraph.length) blocks.push({type: 'paragraph', text: paragraph.join(' ')}); paragraph = [];};
  const flushList = () => {if (list) blocks.push(list); list = null;};
  for (const line of content.replace(/\r\n?/g, '\n').split('\n')) {
    if (code) {
      if (/^\s*```/.test(line)) {blocks.push({type: 'code', text: code.join('\n')}); code = null;}
      else code.push(line);
      continue;
    }
    if (/^\s*```/.test(line)) {flushParagraph(); flushList(); code = []; continue;}
    const verdict = line.match(/^\s*FINAL VERDICT:\s*(BENIGN|MALICIOUS)\s*$/i);
    if (verdict) {flushParagraph(); flushList(); blocks.push({type: 'verdict', value: verdict[1].toUpperCase()}); continue;}
    const heading = line.match(/^\s*(#{1,4})\s+(.+?)\s*#*\s*$/);
    if (heading) {flushParagraph(); flushList(); blocks.push({type: 'heading', level: Math.min(heading[1].length, 4), text: heading[2]}); continue;}
    const unordered = line.match(/^\s*[-*+]\s+(.+)$/);
    const ordered = line.match(/^\s*\d+[.)]\s+(.+)$/);
    if (unordered || ordered) {
      flushParagraph();
      const isOrdered = !!ordered;
      if (list && list.ordered !== isOrdered) flushList();
      if (!list) list = {type: 'list', ordered: isOrdered, items: []};
      list.items.push((unordered || ordered)[1]);
      continue;
    }
    if (!line.trim()) {flushParagraph(); flushList(); continue;}
    flushList(); paragraph.push(line.trim());
  }
  flushParagraph(); flushList();
  if (code) blocks.push({type: 'code', text: code.join('\n')});
  return blocks;
}
function inlineMarkdown(text) {
  const token = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g;
  return text.split(token).map((part, index) => {
    if (part.startsWith('**') && part.endsWith('**')) return <strong key={index}>{part.slice(2, -2)}</strong>;
    if (part.startsWith('`') && part.endsWith('`')) return <code key={index}>{part.slice(1, -1)}</code>;
    if (part.startsWith('*') && part.endsWith('*')) return <em key={index}>{part.slice(1, -1)}</em>;
    return part;
  });
}
function Status({value = 'new'}) {return <span className={`status status-${value}`}>{value.replace('_', ' ')}</span>;}
function Data({label, value}) {return <div className="data-point"><span>{label}</span><strong>{value || '—'}</strong></div>;}
function formatTime(value) {return value ? new Date(value).toLocaleString([], {month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit'}) : '—';}

function PcapPage({file, setFile, uploadPcap, busy, uploadResult, ai}) {
  return <>
    <div className="page-heading"><div><div className="eyebrow">OFFLINE ANALYSIS / PCAP</div><h1>PCAP investigation</h1><p>Upload a packet capture to extract flows, run detection, and add findings to the alert queue.</p></div></div>
    <section className="pcap-layout">
      <form className="panel upload-panel" onSubmit={uploadPcap}>
        <div className="eyebrow">CAPTURE FILE</div><h2>Review a packet capture</h2><p className="panel-intro">Supported formats: PCAP, PCAPNG, and CAP. Packets are parsed for flow metadata; the uploaded capture is deleted after analysis.</p>
        <label className={`dropzone ${file ? 'has-file' : ''}`} htmlFor="pcap-file"><span className="upload-icon">⇧</span><strong>{file ? file.name : 'Choose a capture file'}</strong><small>{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB · click to change` : 'Browse from this device · PCAP / PCAPNG / CAP'}</small><input id="pcap-file" type="file" accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap" onChange={event => setFile(event.target.files?.[0] || null)} /></label>
        <div className="upload-note"><span>ⓘ</span><span>Analysis stores flow features and detection evidence. It does not retain packet payloads.</span></div>
        <button className="button primary upload-button" disabled={!file || !!busy}>{busy === 'upload' ? <><span className="spinner" /> Analyzing capture…</> : 'Analyze capture'}</button>
        {uploadResult && <div className="result-card"><strong>Analysis complete</strong><span>{uploadResult.flows} flows · {uploadResult.alerts} alerts</span></div>}
      </form>
      <div className="pcap-side">
        <div className="panel process-panel"><div className="eyebrow">INVESTIGATION FLOW</div><h2>What happens to the file</h2><ol className="process-list"><li><span>1</span><div><strong>Parse packets</strong><p>Extract IPv4/IPv6 TCP and UDP conversations.</p></div></li><li><span>2</span><div><strong>Analyze flows</strong><p>Score with the detection model and versioned rules.</p></div></li><li><span>3</span><div><strong>Review findings</strong><p>Matching detections appear in the alert queue for triage.</p></div></li></ol></div>
        <div className="panel pcap-ai"><div className="ai-heading"><span className="metric-icon green">✳</span><div><strong>AI analyst assistance</strong><small>{ai?.model_available ? `${ai.model} · connected` : ai?.error || 'Model connection unavailable'}</small></div></div><p>Detections remain preliminary until the analyst report completes. The final Benign or Malicious verdict then appears in the alert queue.</p></div>
      </div>
    </section>
  </>;
}

function Login({onToken}) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const response = await fetch(`${API}/api/v1/auth/token`, {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams({username, password})});
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || 'Could not sign in. Check your credentials.');
      onToken(data.access_token);
    } catch (err) {setError(err.message);}
    finally {setBusy(false);}
  }
  return <main className="login-screen"><div className="login-card"><a className="brand login-brand"><span className="brand-mark">Q</span><span><strong>QDS</strong><small>THREAT OPERATIONS</small></span></a><div className="eyebrow">SECURE ACCESS</div><h1>Sign in to QDS</h1><p>Use your operator account to review alerts and investigate traffic.</p><form onSubmit={submit}><label>Username<input autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} required /></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>{error && <div className="login-error">{error}</div>}<button className="button primary login-submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button></form><div className="login-foot"><span className="status-dot good" />Protected local SOC console</div></div></main>;
}

createRoot(document.getElementById('root')).render(<App />);
