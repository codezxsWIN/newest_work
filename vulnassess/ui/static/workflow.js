import {SIZE, EDGES, ICONS, buildNodes, connectedNodeIds, nodeDetails, evidenceKind} from './workflow-data.js';
import {requestAnalyst} from './analyst-client.js';

const runSelect = document.getElementById('workflow-run');
const hostSelect = document.getElementById('workflow-host');
const findingSelect = document.getElementById('workflow-finding');
const viewport = document.getElementById('viewport');
const graph = document.getElementById('graph');
const message = document.getElementById('loading-state');
const inspector = document.getElementById('node-inspector');
const content = document.getElementById('node-content');
const svgNamespace = 'http://www.w3.org/2000/svg';
const narrowViewport = matchMedia('(max-width: 960px)');
const view = {assessment: null, scope: null, weights: null, host: '', finding: '', node: '', mode: narrowViewport.matches ? 'stages' : 'canvas', modeChosen: false, scale: 1, panX: 0, panY: 0, load: 0, analyses: new Map()};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function svgElement(name, attributes = {}) {
  const node = document.createElementNS(svgNamespace, name);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  return node;
}

function icon(name) {
  const svg = svgElement('svg', {viewBox: '0 0 24 24', 'aria-hidden': 'true'});
  for (const path of ICONS[name] || ICONS.report) svg.append(svgElement('path', {d: path}));
  return svg;
}

async function getRecord(path) {
  const response = await fetch(path, {cache: 'no-store', credentials: 'same-origin'});
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error?.message || payload.reason || `Stored records unavailable: ${path}`);
  return payload;
}

function currentAnalysis() {
  return view.assessment ? view.analyses.get(`${view.assessment.run.run_id}/${view.host}`) : null;
}

function selection() { return {host: view.host, finding: view.finding}; }
function transform() {
  graph.style.transform = view.mode === 'stages' ? 'none' : `translate(${view.panX}px, ${view.panY}px) scale(${view.scale})`;
  document.getElementById('zoom-level').textContent = `${Math.round(view.scale * 100)}%`;
}

function setViewMode(mode) {
  view.mode = mode;
  viewport.dataset.view = mode;
  viewport.setAttribute('aria-label', mode === 'canvas' ? 'Assessment workflow canvas' : 'Assessment workflow stages');
  for (const button of document.querySelectorAll('[data-view-mode]')) button.setAttribute('aria-pressed', String(button.dataset.viewMode === mode));
  viewport.scrollTop = 0;
  fit();
}

function fit() {
  if (!view.assessment) return;
  const width = viewport.clientWidth;
  const height = viewport.clientHeight;
  const top = document.querySelector('.trace-controls').offsetHeight + 44;
  const bottom = document.querySelector('.canvas-footer').offsetHeight + 40;
  const availableHeight = height - top - bottom;
  view.scale = Math.max(0.18, Math.min(1, (width - 52) / SIZE.width, availableHeight / SIZE.height));
  view.panX = (width - SIZE.width * view.scale) / 2;
  view.panY = top + Math.max(0, (availableHeight - SIZE.height * view.scale) / 2);
  transform();
}

function zoom(factor, point = {x: viewport.clientWidth / 2, y: viewport.clientHeight / 2}) {
  const previous = view.scale;
  view.scale = Math.max(.18, Math.min(2.2, previous * factor));
  view.panX = point.x - (point.x - view.panX) * view.scale / previous;
  view.panY = point.y - (point.y - view.panY) * view.scale / previous;
  transform();
}

function edgePath(from, to) {
  const horizontal = Math.abs(to.x - from.x) > Math.abs(to.y - from.y) * .75;
  if (horizontal) {
    const direction = Math.sign(to.x - from.x) || 1;
    const start = {x: from.x + 50 * direction, y: from.y};
    const end = {x: to.x - 50 * direction, y: to.y};
    const middle = (start.x + end.x) / 2;
    return `M${start.x},${start.y} C${middle},${start.y} ${middle},${end.y} ${end.x},${end.y}`;
  }
  const side = Math.max(from.x, to.x) + 105;
  const start = {x: from.x + 50, y: from.y};
  const end = {x: to.x + 50, y: to.y};
  return `M${start.x},${start.y} C${side},${start.y} ${side},${end.y} ${end.x},${end.y}`;
}

function renderGraph() {
  if (!view.assessment) return;
  const nodes = buildNodes(view.assessment, view.scope, selection(), currentAnalysis());
  const nodeMap = new Map(nodes.map(node => [node.id, node]));
  const connected = view.node ? connectedNodeIds(view.node) : null;
  const paths = document.getElementById('connections');
  paths.setAttribute('viewBox', `0 0 ${SIZE.width} ${SIZE.height}`);
  paths.replaceChildren();
  const definitions = svgElement('defs');
  const arrow = svgElement('marker', {id: 'flow-arrow', markerWidth: 6, markerHeight: 6, refX: 5, refY: 3, orient: 'auto', markerUnits: 'strokeWidth'});
  arrow.append(svgElement('path', {d: 'M0,0 L6,3 L0,6', class: 'arrow-fill'}));
  definitions.append(arrow);
  paths.append(definitions);
  for (const edge of EDGES) {
    const from = nodeMap.get(edge.from);
    const to = nodeMap.get(edge.to);
    const missing = edge.optional || ['missing', 'optional'].includes(from.state) || ['missing', 'optional'].includes(to.state);
    const active = view.node === edge.from || view.node === edge.to;
    paths.append(svgElement('path', {d: edgePath(from, to), class: `connection${missing ? ' optional' : ''}${active ? ' highlighted' : ''}${view.node && !active ? ' faded' : ''}`, 'marker-end': 'url(#flow-arrow)', 'data-edge': `${edge.from}:${edge.to}`}));
    if (active) paths.append(svgElement('path', {d: edgePath(from, to), class: 'connection-trace', pathLength: 100}));
  }
  const list = document.getElementById('node-list');
  list.replaceChildren();
  for (const node of nodes) {
    const button = element('button', `flow-node group-${node.group} state-${node.state}`);
    button.type = 'button';
    button.dataset.node = node.id;
    button.style.left = `${node.x}px`;
    button.style.top = `${node.y}px`;
    button.setAttribute('aria-label', `${node.title}: ${node.status}`);
    button.title = `${node.title} / ${node.subtitle} / ${node.status}`;
    button.setAttribute('aria-pressed', String(view.node === node.id));
    if (view.node && !connected.has(node.id)) button.classList.add('muted-node');
    const disc = element('span', 'node-disc');
    disc.append(icon(node.icon));
    const stateMark = element('span', 'node-state-mark');
    stateMark.setAttribute('aria-hidden', 'true');
    stateMark.textContent = node.state === 'error' ? '!' : '';
    disc.append(stateMark);
    button.append(disc, element('strong', 'node-title', node.title), element('span', 'node-subtitle', node.subtitle), element('span', 'node-status', node.status));
    button.addEventListener('click', () => selectNode(node.id));
    list.append(button);
  }
  const lanes = document.getElementById('lanes');
  if (!lanes.children.length) {
    const labels = [
      {text: '01 / EVIDENCE', x: 65, y: 30}, {text: '02 / INTELLIGENCE', x: 585, y: 0},
      {text: '03 / RISK & PRIORITY', x: 945, y: 245}, {text: '04 / OUTPUTS', x: 1320, y: 30},
    ];
    for (const label of labels) {
      const item = element('span', 'lane-label', label.text);
      item.style.left = `${label.x}px`;
      item.style.top = `${label.y}px`;
      lanes.append(item);
    }
  }
}

function rows(items) {
  const list = element('dl', 'detail-rows');
  for (const item of items) list.append(element('dt', '', item.label), element('dd', 'evidence', item.value === null || item.value === undefined ? 'Not recorded' : String(item.value)));
  return list;
}

function appendQuotes(parent, items) {
  for (const item of items) {
    const group = element('div', 'evidence-item');
    group.append(element('span', 'detail-label', item.label));
    if (Object.hasOwn(item, 'value')) group.append(element('strong', 'feature-label', String(item.value).replaceAll('_', ' ')));
    if (item.confidence !== undefined) group.append(element('small', 'detail-hint', `Confidence ${item.confidence} · ${item.source}`));
    group.append(element('blockquote', 'evidence', item.quote));
    if (item.source) group.append(element('small', 'evidence-source', item.source));
    parent.append(group);
  }
}

function updateProjectLink() {
  if (!view.assessment) return;
  const parameters = new URLSearchParams();
  if (view.host) parameters.set('asset', view.host);
  if (view.finding) parameters.set('finding', view.finding);
  const section = view.finding ? 'project-doors' : 'project-workflow';
  document.getElementById('assessment-link').href = `/?run=${encodeURIComponent(view.assessment.run.run_id)}#${section}${parameters.size ? `?${parameters}` : ''}`;
}

function updateLocation() {
  const parameters = new URLSearchParams();
  if (view.node) parameters.set('node', view.node);
  if (view.host) parameters.set('host', view.host);
  if (view.finding) parameters.set('finding', view.finding);
  history.replaceState(null, '', `${location.pathname}${location.search}${parameters.size ? `#${parameters}` : ''}`);
  updateProjectLink();
}

function selectNode(identity) {
  view.node = identity;
  updateLocation();
  inspector.hidden = false;
  renderGraph();
  renderInspector();
  fit();
  content.querySelector('h2').focus({preventScroll: true});
  document.getElementById('workflow-announcement').textContent = `${content.querySelector('h2').textContent} selected`;
}

function renderInspector() {
  if (!view.node || !view.assessment) return;
  const nodes = buildNodes(view.assessment, view.scope, selection(), currentAnalysis());
  const node = nodes.find(item => item.id === view.node);
  const details = nodeDetails(view.node, view.assessment, view.scope, view.weights, selection(), currentAnalysis());
  content.replaceChildren();
  const heading = element('div', 'node-detail-title');
  const glyph = element('span', `inspector-glyph group-${node.group}`);
  glyph.append(icon(node.icon));
  const title = element('h2', '', node.title);
  title.tabIndex = -1;
  heading.append(glyph, title);
  content.append(heading, element('p', 'node-description', node.subtitle), element('span', `detail-status state-${node.state}`, node.status));
  const logic = element('div', 'node-operation');
  for (const [label, value] of [['INPUT', details.input], ['OPERATION', details.operation], ['OUTPUT', details.output]]) {
    const section = element('div', 'operation-row');
    section.append(element('span', 'detail-label', label), element('p', '', value));
    logic.append(section);
  }
  content.append(logic);
  if (details.rows.length) content.append(rows(details.rows));
  appendQuotes(content, details.quotes);
  if (view.node === 'analyst') renderAnalyst();
  if (details.message) content.append(element('p', 'boundary-note', details.message));
  if (details.records.length) {
    const disclosure = element('details', 'raw-records');
    disclosure.append(element('summary', '', 'Raw records'), element('pre', 'evidence', JSON.stringify(details.records, null, 2)));
    content.append(disclosure);
  }
  const module = element('div', 'module-path');
  module.append(element('span', 'detail-label', 'IMPLEMENTATION'), element('span', 'evidence', details.provenance));
  content.append(module);
  const links = element('div', 'node-neighbours');
  for (const edge of EDGES.filter(edge => edge.from === view.node || edge.to === view.node)) {
    const other = nodes.find(item => item.id === (edge.from === view.node ? edge.to : edge.from));
    const button = element('button', 'neighbour-link', `${edge.from === view.node ? 'To' : 'From'} ${other.title}`);
    button.type = 'button';
    button.addEventListener('click', () => selectNode(other.id));
    links.append(button);
  }
  content.append(links);
}

function renderAnalyst() {
  const holder = element('section', 'analyst-action');
  holder.append(element('p', 'analyst-scope', view.host ? `Target: ${view.host}` : 'Select a target above to analyze its stored evidence.'));
  const button = element('button', 'analyze-button', currentAnalysis()?.status === 'running' ? 'Request in progress' : 'Analyze target');
  button.type = 'button';
  button.id = 'workflow-analyze';
  button.disabled = !view.host || currentAnalysis()?.status === 'running';
  button.addEventListener('click', analyzeTarget);
  holder.append(button);
  const live = currentAnalysis();
  if (live?.status === 'running') holder.append(element('p', 'analysis-wait', 'Waiting for the local model response. No pipeline step is being replayed.'));
  if (live?.status === 'error') holder.append(element('p', 'analysis-error', live.error));
  if (live?.result) {
    const result = live.result;
    holder.append(element('p', 'analysis-summary', result.analysis.summary));
    const evidenceMap = new Map(result.evidence.map(item => [item.id, item]));
    for (const action of result.analysis.recommended_actions) {
      const record = element('div', 'analysis-action');
      record.append(element('h3', '', action.action), element('p', '', action.reason));
      appendQuotes(record, action.evidence_ids.map(identity => ({label: `Citation ${identity}`, quote: evidenceMap.get(identity)?.text || 'Citation not present in response', source: result.model})));
      holder.append(record);
    }
    for (const correlation of result.analysis.correlations || []) {
      const record = element('div', 'analysis-action');
      record.append(element('h3', '', 'Correlated evidence'), element('p', '', correlation.observation));
      appendQuotes(record, correlation.evidence_ids.map(identity => ({label: `Citation ${identity}`, quote: evidenceMap.get(identity)?.text || 'Citation not present in response', source: result.model})));
      holder.append(record);
    }
    for (const uncertainty of result.analysis.uncertainties) holder.append(element('p', 'boundary-note', uncertainty));
  }
  content.append(holder);
}

async function analyzeTarget() {
  if (!view.host || !view.assessment) return;
  const runId = view.assessment.run.run_id;
  const hostIp = view.host;
  const key = `${runId}/${hostIp}`;
  if (view.analyses.get(key)?.status === 'running') return;
  view.analyses.set(key, {runId, hostIp, status: 'running'});
  renderGraph();
  renderInspector();
  try {
    const response = await requestAnalyst(runId, hostIp);
    view.analyses.set(key, {runId, hostIp, status: 'complete', result: response});
  } catch (error) {
    view.analyses.set(key, {runId, hostIp, status: 'error', error: error.message});
  }
  if (view.assessment?.run.run_id === runId && view.host === hostIp) {
    renderGraph();
    renderInspector();
    document.getElementById('workflow-announcement').textContent = view.analyses.get(key).status === 'complete' ? 'Local analyst response received. Stored scores unchanged.' : 'Local analysis failed. No result substituted.';
  }
}

function populateFindings() {
  const findings = view.assessment.findings.filter(finding => !view.host || finding.host_ip === view.host);
  findingSelect.replaceChildren(element('option', '', 'All findings'));
  findingSelect.options[0].value = '';
  for (const finding of findings) {
    const option = element('option', '', `${finding.host_ip} / ${finding.title}`);
    option.value = finding.id;
    findingSelect.append(option);
  }
  if (!findings.some(finding => finding.id === view.finding)) view.finding = '';
  findingSelect.value = view.finding;
  findingSelect.disabled = false;
}

function populateSelection() {
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
  populateFindings();
}

async function loadWorkflow() {
  const sequence = ++view.load;
  message.hidden = false;
  message.querySelector('strong').textContent = 'Opening the assessment';
  message.querySelector('p').textContent = 'Reading local records.';
  graph.hidden = true;
  document.getElementById('refresh-workflow').disabled = true;
  try {
    const index = await getRecord('/api/runs');
    if (!index.runs.length) throw new Error('No stored runs. Import an authorized capture through the CLI, then refresh.');
    const requested = new URLSearchParams(location.search).get('run') || index.selected_run || index.runs[0].run_id;
    const [assessment, scope, weights] = await Promise.all([getRecord(`/api/run/${encodeURIComponent(requested)}`), getRecord('/api/scope'), getRecord('/api/weights')]);
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
    populateSelection();
    document.getElementById('canvas-caption').textContent = `Recorded assessment / ${assessment.run.run_id}`;
    document.getElementById('record-summary').textContent = `${assessment.hosts.length} assets / ${assessment.findings.length} findings / ${assessment.scores.length} scored`;
    document.getElementById('run-hash').textContent = `config ${assessment.run.config_hash}`;
    document.getElementById('data-kind').textContent = evidenceKind(assessment);
    updateProjectLink();
    graph.hidden = false;
    message.hidden = true;
    renderGraph();
    if (buildNodes(assessment, scope).some(node => node.id === parameters.get('node'))) selectNode(parameters.get('node'));
    fit();
  } catch (error) {
    if (sequence !== view.load) return;
    view.assessment = null;
    inspector.hidden = true;
    hostSelect.disabled = true;
    findingSelect.disabled = true;
    message.querySelector('strong').textContent = 'Records unavailable';
    message.querySelector('p').textContent = error.message;
    document.getElementById('canvas-caption').textContent = 'The stored assessment could not be loaded.';
    document.getElementById('record-summary').textContent = '';
  } finally {
    if (sequence === view.load) document.getElementById('refresh-workflow').disabled = false;
  }
}

document.getElementById('refresh-workflow').addEventListener('click', loadWorkflow);
runSelect.addEventListener('change', () => { location.href = `/workflow?run=${encodeURIComponent(runSelect.value)}`; });
hostSelect.addEventListener('change', () => { view.host = hostSelect.value; view.finding = ''; populateFindings(); updateLocation(); renderGraph(); renderInspector(); });
findingSelect.addEventListener('change', () => {
  view.finding = findingSelect.value;
  if (view.finding) {
    view.host = view.assessment.findings.find(finding => finding.id === view.finding).host_ip;
    hostSelect.value = view.host;
    populateFindings();
  }
  updateLocation();
  renderGraph();
  renderInspector();
});
document.getElementById('close-node').addEventListener('click', () => {
  const identity = view.node;
  view.node = '';
  inspector.hidden = true;
  updateLocation();
  renderGraph();
  fit();
  document.querySelector(`[data-node="${identity}"]`)?.focus({preventScroll: true});
});
for (const button of document.querySelectorAll('[data-view-mode]')) button.addEventListener('click', () => {
  view.modeChosen = true;
  setViewMode(button.dataset.viewMode);
});
narrowViewport.addEventListener('change', event => { if (!view.modeChosen) setViewMode(event.matches ? 'stages' : 'canvas'); });
document.getElementById('fit-workflow').addEventListener('click', fit);
document.getElementById('zoom-in').addEventListener('click', () => zoom(1.2));
document.getElementById('zoom-out').addEventListener('click', () => zoom(1 / 1.2));
let drag = null;
viewport.addEventListener('pointerdown', event => {
  if (view.mode !== 'canvas' || event.button !== 0 || event.target.closest('button, a, select, input')) return;
  drag = {pointer: event.pointerId, x: event.clientX, y: event.clientY, panX: view.panX, panY: view.panY};
  viewport.setPointerCapture(event.pointerId);
  viewport.classList.add('panning');
});
viewport.addEventListener('pointermove', event => {
  if (!drag || drag.pointer !== event.pointerId) return;
  view.panX = drag.panX + event.clientX - drag.x;
  view.panY = drag.panY + event.clientY - drag.y;
  transform();
});
function stopDrag() { drag = null; viewport.classList.remove('panning'); }
viewport.addEventListener('pointerup', stopDrag);
viewport.addEventListener('pointercancel', stopDrag);
viewport.addEventListener('wheel', event => {
  if (view.mode !== 'canvas' || event.target.closest('select')) return;
  event.preventDefault();
  if (event.ctrlKey || event.metaKey) {
    const rect = viewport.getBoundingClientRect();
    zoom(event.deltaY < 0 ? 1.1 : 1 / 1.1, {x: event.clientX - rect.left, y: event.clientY - rect.top});
  } else { view.panX -= event.deltaX; view.panY -= event.deltaY; transform(); }
}, {passive: false});
viewport.addEventListener('keydown', event => {
  if (view.mode !== 'canvas' || event.target !== viewport) return;
  const offsets = {ArrowLeft: [60, 0], ArrowRight: [-60, 0], ArrowUp: [0, 60], ArrowDown: [0, -60]};
  if (offsets[event.key]) { event.preventDefault(); view.panX += offsets[event.key][0]; view.panY += offsets[event.key][1]; transform(); }
  if (event.key === '+' || event.key === '=') { event.preventDefault(); zoom(1.2); }
  if (event.key === '-') { event.preventDefault(); zoom(1 / 1.2); }
  if (event.key === '0') { event.preventDefault(); fit(); }
});
document.addEventListener('keydown', event => { if (event.key === 'Escape' && !inspector.hidden) document.getElementById('close-node').click(); });
window.addEventListener('resize', fit);
setViewMode(view.mode);
loadWorkflow();