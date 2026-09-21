import {currentSlice, evidenceKind, queueRows, traceLayers, diffFields} from './workflow-data.js';

const runSelect = document.getElementById('workflow-run');
const hostSelect = document.getElementById('workflow-host');
const compareToggle = document.getElementById('toggle-compare');
const rail = document.getElementById('queue-rail');
const stack = document.getElementById('trace-stack');
const compareStack = document.getElementById('compare-stack');
const loading = document.getElementById('loading-state');
const view = {assessment: null, scope: null, weights: null, host: '', finding: '', layer: 'priority', compare: '', load: 0, analyses: new Map()};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text === null || text === undefined || text === '' ? 'Not recorded' : String(text);
  return node;
}

function show(node, on = true) { node.hidden = !on; }

function announce(text) { document.getElementById('workflow-announcement').textContent = text; }

async function getRecord(path) {
  const response = await fetch(path, {cache: 'no-store', credentials: 'same-origin'});
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error?.message || payload.reason || `Stored records unavailable: ${path}`);
  return payload;
}

function updateLocation() {
  const parameters = new URLSearchParams();
  if (view.finding) parameters.set('finding', view.finding);
  if (view.layer !== 'priority') parameters.set('layer', view.layer);
  if (view.compare) parameters.set('compare', view.compare);
  history.replaceState(null, '', `${location.pathname}${location.search}${parameters.size ? `#${parameters}` : ''}`);
}

function analysisFor(runId, hostIp) { return view.analyses.get(`${runId}/${hostIp}`) || null; }

function rowsList(rows, diffs = null, otherRows = null) {
  const list = element('dl', 'trace-rows');
  const otherValue = label => otherRows?.find(item => item.label === label)?.value;
  for (const row of rows) {
    const diverges = Boolean(diffs) && Boolean(otherRows)
      && String(row.value ?? 'Not recorded') !== String(otherValue(row.label) ?? 'Not recorded');
    list.append(element('dt', 'trace-label', row.label));
    const value = element('dd', diverges ? 'trace-value differs' : 'trace-value', row.value);
    if (diverges) value.title = 'Differs between the two traces';
    list.append(value);
  }
  return list;
}

function layerFigure(layer, diffs = null) {
  const details = document.createElement('details');
  details.className = `trace-layer layer-${layer.id}${layer.present ? '' : ' layer-missing'}`;
  details.open = layer.id === view.layer;
  const summary = element('summary', 'layer-summary');
  summary.append(
    element('span', 'layer-index', String(layer.order)),
    element('span', 'layer-name', layer.title),
    element('span', 'layer-state', layer.present ? 'Stored' : 'Absent — named, not zero'),
  );
  details.append(summary);
  const body = element('div', 'layer-body');
  body.append(element('p', 'layer-operation', layer.operation));
  if (!layer.present) {
    body.append(element('p', 'layer-missing-note', layer.missing));
    details.append(body);
    return details;
  }
  if (layer.rows.length) body.append(rowsList(layer.rows, diffs));
  if (layer.vector) body.append(element('p', 'trace-vector', layer.vector));
  if (layer.outputs) {
    body.append(element('p', 'layer-eyebrow', 'DOWNSTREAM ARTIFACTS'));
    body.append(rowsList(layer.outputs));
  }
  if (layer.groups) {
    for (const group of layer.groups) {
      const block = element('div', 'intel-group');
      block.append(element('h3', 'intel-title', group.title));
      body.append(block);
      if (group.rows.length) block.append(rowsList(group.rows));
      if (group.quote) {
        block.append(element('span', 'trace-label', group.quote.label));
        block.append(element('blockquote', 'trace-quote', group.quote.text));
      }
    }
  }
  if (layer.features) {
    for (const feature of layer.features) {
      const item = element('div', 'context-feature');
      item.append(element('span', 'trace-label', feature.label));
      item.append(element('strong', 'feature-value', String(feature.value).replaceAll('_', ' ')));
      item.append(element('small', 'feature-meta', `Confidence ${feature.confidence} · ${feature.source}`));
      item.append(element('blockquote', 'trace-quote', feature.quote));
    }
  }
  if (layer.quote) {
    body.append(element('span', 'trace-label', layer.quote.label));
    body.append(element('blockquote', 'trace-quote', layer.quote.text));
  }
  details.append(body);
  return details;
}

function sourcesLine(sources) {
  const line = element('p', 'trace-sources');
  line.append(element('span', 'trace-label', 'IMPORTS PRESENT'));
  for (const source of sources) {
    line.append(element('span', `source-stamp${source.recorded ? ' recorded' : ' absent'}`, source.recorded ? source.tool.toUpperCase() : `${source.tool.toUpperCase()} — NO IMPORT`));
  }
  return line;
}

function analystPanel(trace) {
  const holder = element('section', 'analyst-layer');
  holder.append(element('p', 'layer-eyebrow', 'LOCAL AI ANALYST — ADVISORY ONLY'));
  const analysis = trace.analysis;
  const status = analysis?.status;
  const button = element('button', 'analyze-button', status === 'running' ? 'Request in progress…' : 'Analyze this target');
  button.type = 'button';
  button.disabled = !trace.finding || status === 'running';
  button.addEventListener('click', () => analyzeTarget(trace.finding.host_ip));
  holder.append(button);
  holder.append(element('p', 'analyst-note', trace.finding
    ? `One explicit request runs local Ollama over every stored record for ${trace.finding.host_ip}. It never changes the scores above.`
    : 'Select a finding to enable a local analysis request.'));
  if (status === 'running') holder.append(element('p', 'analyst-note', 'Waiting for the local model. CPU inference can take minutes; nothing is replayed or faked here.'));
  if (status === 'error') holder.append(element('p', 'analyst-error', analysis.error));
  if (status === 'complete') {
    const result = analysis.result;
    holder.append(element('p', 'analyst-summary', result.analysis.summary));
    const evidenceMap = new Map(result.evidence.map(item => [item.id, item]));
    for (const action of result.analysis.recommended_actions) {
      const record = element('div', 'analyst-action');
      record.append(element('strong', '', action.action), element('p', '', action.reason));
      for (const citation of action.evidence_ids) {
        const chip = element('button', 'citation-chip', citation);
        chip.type = 'button';
        chip.title = evidenceMap.get(citation)?.text || 'Citation record';
        chip.addEventListener('click', () => {
          document.querySelector('.trace-layer.layer-evidence')?.scrollIntoView({block: 'start'});
          announce(`Citation ${citation}: ${evidenceMap.get(citation)?.text || 'record text unavailable'}`);
        });
        record.append(chip);
      }
      holder.append(record);
    }
    for (const uncertainty of result.analysis.uncertainties || []) holder.append(element('p', 'analyst-uncertainty', uncertainty));
    holder.append(element('p', 'analyst-note', `Model ${result.model} · advisory confidence ${result.analysis.confidence} · stored scores unchanged.`));
  }
  return holder;
}

function renderTrace(targetStack, findingId, diffs = null) {
  targetStack.replaceChildren();
  if (!view.assessment) return;
  const selection = {host: view.host, finding: findingId};
  const trace = traceLayers(view.assessment, view.scope, view.weights, selection, null);
  if (!trace.finding) {
    targetStack.append(element('p', 'trace-state', 'This finding is not stored in the selected assessment.'));
    return;
  }
  const header = element('header', 'trace-head');
  header.append(
    element('p', 'layer-eyebrow', `TRACE ${trace.position ? `· QUEUE POSITION ${trace.position}` : '· UNSCORED'}`),
    element('h2', 'trace-title', trace.finding.title),
    element('p', 'trace-endpoint', `${trace.finding.host_ip}${trace.finding.port ? ` : ${trace.finding.port}` : ''} · ${trace.finding.tool} · ${trace.finding.cve_ids.join(', ') || trace.finding.tool_native_id}`),
  );
  targetStack.append(header);
  targetStack.append(sourcesLine(trace.sources));
  let order = 0;
  for (const layer of trace.layers) {
    layer.order = ++order;
    const figure = layerFigure(layer, diffs);
    figure.dataset.layer = layer.id;
    figure.addEventListener('toggle', () => {
      if (figure.open) { view.layer = layer.id; updateLocation(); }
    });
    targetStack.append(figure);
  }
  targetStack.append(analystPanel(trace));
}

function renderRail() {
  rail.replaceChildren();
  if (!view.assessment) return;
  const rows = queueRows(view.assessment, view.host);
  for (const row of rows) {
    const button = element('button', `queue-mark band-${String(row.band).toLowerCase()}`);
    button.type = 'button';
    button.dataset.finding = row.finding_id;
    button.setAttribute('aria-pressed', String(row.finding_id === view.finding));
    button.setAttribute('aria-label', `Position ${row.position}: ${row.title} on ${row.host_ip}, risk ${row.risk}, band ${row.band}`);
    button.append(
      element('span', 'mark-position', String(row.position)),
      element('span', 'mark-risk', String(row.risk)),
      element('span', 'mark-band', String(row.band)),
      element('span', 'mark-label', `${row.cve_id || row.title}`),
      element('span', 'mark-host', `${row.host_ip}${row.port ? `:${row.port}` : ''}`),
    );
    button.addEventListener('click', () => selectFinding(row.finding_id));
    rail.append(button);
  }
  const unscored = view.assessment.findings.filter(finding => !view.assessment.scores.some(score => score.finding_id === finding.id) && (!view.host || finding.host_ip === view.host));
  if (unscored.length) {
    rail.append(element('p', 'rail-note', `${unscored.length} imported finding(s) have no stored score and appear nowhere above.`));
  }
}

function renderCompare() {
  show(compareStack, Boolean(view.compare));
  compareToggle.setAttribute('aria-pressed', String(Boolean(view.compare)));
  if (!view.compare) return;
  const base = view.assessment.scores.find(score => score.finding_id === view.finding) || null;
  const other = view.assessment.scores.find(score => score.finding_id === view.compare) || null;
  const diffs = diffFields(base, other);
  renderTrace(compareStack, view.compare, diffs);
}

function renderAll() {
  renderRail();
  renderTrace(stack, view.finding);
  renderCompare();
}

function selectFinding(findingId) {
  view.finding = findingId;
  updateLocation();
  renderAll();
  announce(`Tracing ${view.assessment?.findings.find(finding => finding.id === findingId)?.title || 'selected finding'}`);
}

async function analyzeTarget(hostIp) {
  if (!view.assessment) return;
  const runId = view.assessment.run.run_id;
  const key = `${runId}/${hostIp}`;
  if (view.analyses.get(key)?.status === 'running') return;
  view.analyses.set(key, {runId, hostIp, status: 'running'});
  renderAll();
  try {
    const response = await getRecord(`/api/analyst/${encodeURIComponent(runId)}/${encodeURIComponent(hostIp)}`);
    if (response.run_id !== runId || response.host_ip !== hostIp || response.canonical_scores_changed !== false) throw new Error('Analyst response does not match the score boundary.');
    view.analyses.set(key, {runId, hostIp, status: 'complete', result: response});
  } catch (error) {
    view.analyses.set(key, {runId, hostIp, status: 'error', error: error.message});
  }
  if (view.assessment?.run.run_id === runId) renderAll();
  announce(view.analyses.get(key).status === 'complete' ? 'Local analyst response received. Stored scores unchanged.' : 'Local analysis failed. No result substituted.');
}

function populateHosts() {
  hostSelect.replaceChildren(element('option', '', 'All recorded hosts'));
  hostSelect.options[0].value = '';
  for (const host of view.assessment.hosts) {
    const option = element('option', '', host.ip);
    option.value = host.ip;
    hostSelect.append(option);
  }
  if (!view.assessment.hosts.some(host => host.ip === view.host)) view.host = '';
  hostSelect.value = view.host;
  hostSelect.disabled = false;
}

async function loadTraceback() {
  const sequence = ++view.load;
  show(loading, true);
  loading.querySelector('strong').textContent = 'Opening the assessment';
  loading.querySelector('p').textContent = 'Reading local records.';
  show(document.querySelector('.trace-shell'), false);
  document.getElementById('refresh-workflow').disabled = true;
  try {
    const index = await getRecord('/api/runs');
    if (!index.runs.length) throw new Error('No stored runs. Import an authorized capture through the CLI, then refresh.');
    const requested = new URLSearchParams(location.search).get('run') || index.selected_run || index.runs[0].run_id;
    const [assessment, scope, weights] = await Promise.all([
      getRecord(`/api/run/${encodeURIComponent(requested)}`),
      getRecord('/api/scope'),
      getRecord('/api/weights'),
    ]);
    if (sequence !== view.load) return;
    view.assessment = assessment;
    view.scope = scope;
    view.weights = weights;
    runSelect.replaceChildren(...index.runs.map(run => { const option = element('option', '', run.run_id); option.value = run.run_id; return option; }));
    runSelect.value = requested;
    runSelect.disabled = false;
    const parameters = new URLSearchParams(location.hash.slice(1));
    view.host = parameters.get('host') || '';
    view.finding = parameters.get('finding') || '';
    view.layer = parameters.get('layer') || 'priority';
    view.compare = parameters.get('compare') || '';
    if (!view.assessment.scores.some(score => score.finding_id === view.finding)) {
      const first = queueRows(view.assessment, view.host)[0];
      view.finding = first?.finding_id || '';
    }
    populateHosts();
    document.getElementById('trace-caption').textContent = `Recorded assessment / ${assessment.run.run_id} / config ${assessment.run.config_hash.slice(0, 12)}`;
    document.getElementById('data-kind').textContent = evidenceKind(assessment);
    document.getElementById('assessment-link').href = `/?run=${encodeURIComponent(requested)}`;
    compareToggle.disabled = view.assessment.scores.length < 2;
    show(document.querySelector('.trace-shell'), true);
    show(loading, false);
    renderAll();
  } catch (error) {
    if (sequence !== view.load) return;
    view.assessment = null;
    loading.querySelector('strong').textContent = 'Records unavailable';
    loading.querySelector('p').textContent = error.message;
  } finally {
    if (sequence === view.load) document.getElementById('refresh-workflow').disabled = false;
  }
}

runSelect.addEventListener('change', () => { location.href = `/workflow?run=${encodeURIComponent(runSelect.value)}`; });
hostSelect.addEventListener('change', () => { view.host = hostSelect.value; view.finding = ''; loadHostRerender(); updateLocation(); });
function loadHostRerender() {
  if (!view.assessment) return;
  const first = queueRows(view.assessment, view.host)[0];
  view.finding = first?.finding_id || '';
  renderAll();
}
compareToggle.addEventListener('click', () => {
  if (view.compare) { view.compare = ''; }
  else {
    const shareHost = view.assessment.scores.find(score => score.finding_id === view.finding);
    const candidate = view.assessment.scores.find(score => score.finding_id !== view.finding && score.cve_id && score.cve_id === shareHost?.cve_id)
      || view.assessment.scores.find(score => score.finding_id !== view.finding);
    view.compare = candidate?.finding_id || '';
  }
  updateLocation();
  renderCompare();
  announce(view.compare ? 'Comparison trace opened beside the selected trace.' : 'Comparison closed.');
});
document.getElementById('refresh-workflow').addEventListener('click', loadTraceback);
document.addEventListener('keydown', event => {
  if (event.target.closest('input, select, textarea')) return;
  if (event.key === 'Escape' && view.compare) { compareToggle.click(); return; }
  if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
  const rows = [...rail.querySelectorAll('.queue-mark')];
  if (!rows.length) return;
  event.preventDefault();
  const index = rows.findIndex(row => row.dataset.finding === view.finding);
  const next = rows[Math.min(rows.length - 1, Math.max(0, (index < 0 ? 0 : index + (event.key === 'ArrowDown' ? 1 : -1))))];
  next.click();
  next.focus();
});
loadTraceback();
