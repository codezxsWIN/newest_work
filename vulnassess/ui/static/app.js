import { scoreVector, sandbox } from './cvss31.js';

const embedded = document.getElementById('assessment-data');
const bootstrap = JSON.parse(embedded.textContent);
const workflowLink = document.getElementById('open-workflow');
if (workflowLink && !bootstrap.offline) {
  workflowLink.hidden = false;
  workflowLink.href = bootstrap.assessment ? `/workflow?run=${encodeURIComponent(bootstrap.assessment.run.run_id)}` : '/workflow';
}
const panels = [...document.querySelectorAll('[data-panel]')];
const dialog = document.getElementById('inspector');
const stageNames = new Set(['evidence', 'context', 'risk', 'priorities']);
let lastTrigger = null;
let tourStep = -1;

function state() {
  const [section, query = ''] = location.hash.slice(1).split('?');
  const stage = section.startsWith('stage-') ? section.slice(6) : 'evidence';
  return {stage: stageNames.has(stage) ? stage : 'evidence', parameters: new URLSearchParams(query)};
}

function setState(stage, parameters = new URLSearchParams()) {
  const suffix = parameters.toString();
  location.hash = `stage-${stage}${suffix ? `?${suffix}` : ''}`;
}

function openInspector(identity, trigger = null) {
  if (!dialog) return;
  const selected = [...dialog.querySelectorAll('[data-inspection]')].find(item => item.dataset.inspection === identity);
  if (!selected) return;
  for (const item of dialog.querySelectorAll('[data-inspection]')) item.hidden = item !== selected;
  if (trigger) lastTrigger = trigger;
  if (!dialog.open) dialog.showModal();
  dialog.scrollTop = 0;
  document.getElementById('close-inspector').focus();
}

function restoreView() {
  const current = state();
  for (const panel of panels) panel.hidden = panel.dataset.panel !== current.stage;
  for (const link of document.querySelectorAll('[data-stage]')) {
    const active = link.dataset.stage === current.stage;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  for (const select of document.querySelectorAll('[data-facet]')) {
    const value = current.parameters.get(select.dataset.facet) || '';
    select.value = [...select.options].some(option => option.value === value) ? value : '';
  }
  const selectors = [...document.querySelectorAll('[data-facet]')];
  let visible = false;
  for (const row of document.querySelectorAll('.queue-row')) {
    row.hidden = selectors.some(select => select.value && row.dataset[select.dataset.facet] !== select.value);
    visible ||= !row.hidden;
  }
  const empty = document.getElementById('no-results');
  if (empty) empty.hidden = visible;
  const identity = current.parameters.get('finding');
  if (identity) openInspector(identity);
  else if (dialog?.open) dialog.close();
  document.title = `VulnAssess / ${current.stage[0].toUpperCase()}${current.stage.slice(1)}`;
}

for (const link of document.querySelectorAll('[data-stage]')) {
  link.addEventListener('click', event => {
    event.preventDefault();
    if (dialog?.open) dialog.close();
    setState(link.dataset.stage);
  });
}
for (const button of document.querySelectorAll('[data-inspect]')) {
  button.addEventListener('click', () => {
    const current = state();
    current.parameters.set('finding', button.dataset.inspect);
    lastTrigger = button;
    setState(current.stage, current.parameters);
    openInspector(button.dataset.inspect, button);
  });
}
document.getElementById('close-inspector')?.addEventListener('click', () => dialog.close());
dialog?.addEventListener('close', () => {
  const current = state();
  current.parameters.delete('finding');
  history.replaceState(null, '', `#stage-${current.stage}${current.parameters.size ? `?${current.parameters}` : ''}`);
  if (lastTrigger?.isConnected && !lastTrigger.closest('[hidden]')) lastTrigger.focus();
});
dialog?.addEventListener('click', event => { if (event.target === dialog && event.clientX < dialog.getBoundingClientRect().left) dialog.close(); });
for (const select of document.querySelectorAll('[data-facet]')) {
  select.addEventListener('change', () => {
    const parameters = new URLSearchParams();
    for (const item of document.querySelectorAll('[data-facet]')) if (item.value) parameters.set(item.dataset.facet, item.value);
    setState('priorities', parameters);
  });
}
document.getElementById('clear-filters')?.addEventListener('click', () => { setState('priorities'); restoreView(); });
document.getElementById('refresh').disabled = Boolean(bootstrap.offline);
document.getElementById('refresh').title = bootstrap.offline ? 'Offline snapshot; export again to refresh' : 'Refresh stored records';
document.getElementById('refresh').addEventListener('click', async () => {
  if (bootstrap.offline) return;
  const run = bootstrap.assessment?.run.run_id;
  try {
    if (run) {
      const response = await fetch(`/api/run/${encodeURIComponent(run)}`, {cache: 'no-store', credentials: 'same-origin'});
      if (!response.ok) throw new Error('The stored run is unavailable.');
    }
    location.reload();
  } catch (error) { document.getElementById('app-status').textContent = `Refresh failed: ${error.message}`; }
});
document.getElementById('select-run')?.addEventListener('change', event => {
  if (event.target.value) location.href = `/?run=${encodeURIComponent(event.target.value)}`;
});

const modelHost = document.getElementById('model-host');
const modelOutput = document.getElementById('model-output');
const runModel = document.getElementById('run-model');

function analystSection(label, items, render) {
  const section = document.createElement('section');
  section.className = 'analyst-section';
  const heading = document.createElement('h3');
  heading.textContent = label;
  section.append(heading);
  const list = document.createElement('ol');
  for (const item of items) list.append(render(item));
  section.append(list);
  return section;
}

runModel?.addEventListener('click', () => {
  const host = bootstrap.assessment?.context?.find(item => item.host_ip === modelHost?.value);
  if (!host || !modelOutput) return;
  runModel.disabled = true;
  modelOutput.replaceChildren();
  const progress = document.createElement('div');
  progress.className = 'analyst-progress';
  progress.setAttribute('role', 'status');
  const pulse = document.createElement('span');
  pulse.className = 'analyst-pulse';
  const progressCopy = document.createElement('div');
  const progressTitle = document.createElement('strong');
  progressTitle.textContent = 'Local model is analyzing the complete target';
  const progressDetail = document.createElement('p');
  progressDetail.textContent = 'Correlating services, scanner findings, context, CVSS, EPSS and KEV locally. CPU inference can take one to three minutes.';
  progressCopy.append(progressTitle, progressDetail);
  progress.append(pulse, progressCopy);
  modelOutput.append(progress);
  fetch(`/api/analyst/${encodeURIComponent(bootstrap.assessment.run.run_id)}/${encodeURIComponent(host.host_ip)}`)
    .then(async response => {
      const body = await response.json();
      if (!response.ok) throw new Error(body.error?.message || 'Local analyst request failed.');
      return body;
    })
    .then(result => {
      const analysis = result.analysis;
      const evidence = new Map(result.evidence.map(item => [item.id, item]));
      modelOutput.replaceChildren();
      const header = document.createElement('div');
      header.className = 'analyst-header';
      const title = document.createElement('div');
      const eyebrow = document.createElement('span');
      eyebrow.className = 'eyebrow';
      eyebrow.textContent = `${result.model} · LOCAL OLLAMA`;
      const summary = document.createElement('strong');
      summary.textContent = analysis.summary;
      title.append(eyebrow, summary);
      const confidence = document.createElement('div');
      confidence.className = 'analyst-confidence';
      const confidenceLabel = document.createElement('span');
      confidenceLabel.textContent = 'Analysis confidence';
      const confidenceValue = document.createElement('strong');
      confidenceValue.textContent = analysis.confidence;
      confidence.append(confidenceLabel, confidenceValue);
      header.append(title, confidence);
      modelOutput.append(header);

      modelOutput.append(analystSection('Recommended remediation sequence', analysis.recommended_actions, item => {
        const row = document.createElement('li');
        const action = document.createElement('strong');
        action.textContent = `${item.order}. ${item.action}`;
        const reason = document.createElement('p');
        reason.textContent = item.reason;
        const citations = document.createElement('small');
        citations.textContent = item.evidence_ids.map(id => `${id}: ${evidence.get(id)?.text || 'validated record'}`).join(' · ');
        row.append(action, reason, citations);
        return row;
      }));

      if (analysis.correlations.length) modelOutput.append(analystSection('Correlations', analysis.correlations, item => {
        const row = document.createElement('li');
        const observation = document.createElement('p');
        observation.textContent = item.observation;
        const citations = document.createElement('small');
        citations.textContent = item.evidence_ids.join(', ');
        row.append(observation, citations);
        return row;
      }));

      if (analysis.uncertainties.length) modelOutput.append(analystSection('What is still unknown', analysis.uncertainties, item => {
        const row = document.createElement('li');
        row.textContent = item;
        return row;
      }));
    })
    .catch(error => { modelOutput.textContent = error.message; })
    .finally(() => { runModel.disabled = false; });
});

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  document.getElementById('theme').setAttribute('aria-pressed', String(theme === 'dark'));
  try { localStorage.setItem('vulnassess-theme', theme); } catch { document.getElementById('app-status').textContent = 'Theme preference applies to this page only.'; }
}
let theme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
try { theme = localStorage.getItem('vulnassess-theme') || theme; } catch { theme = 'light'; }
const requestedTheme = state().parameters.get('theme');
if (requestedTheme === 'light' || requestedTheme === 'dark') theme = requestedTheme;
setTheme(theme === 'dark' ? 'dark' : 'light');
document.getElementById('theme').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));

const tourSteps = [
  {stage: 'evidence', target: '.asset-grid', title: 'Begin with the scanner.', copy: 'These are the hosts in this recorded assessment. Select a finding to see its original evidence and recorded score.'},
  {stage: 'evidence', target: '.feed-grid', title: 'Intelligence has a date.', copy: 'The vulnerability, EPSS and KEV facts came from local snapshots. Their dates and digests stay visible.'},
  {stage: 'context', target: '.context-grid', title: 'A role needs a clue.', copy: 'Compare the role with its quoted evidence. A MySQL banner supports the database role; the confidence is a separate question.'},
  {stage: 'risk', target: '#comparison', title: 'One weakness, two priorities.', copy: 'The base severity is shared. The recorded environment and context differ. The highlighted rows show where.'},
  {stage: 'priorities', target: '#ranked-list', title: 'The finding reaches the queue.', copy: 'The list uses stored risk and band values. Selecting a finding opens its reason, score inputs and provenance.'},
  {stage: 'priorities', target: '.evaluation', title: 'A demonstration is not a result.', copy: 'Synthetic records can demonstrate the workflow. Real captures and independent expert judgments are still needed to evaluate the method.'}
];
const followedScore = bootstrap.assessment?.scores.find(score => score.finding_id === bootstrap.tour_finding);
if (followedScore) {
  tourSteps[0].target = `[id="host-${followedScore.host_ip}"]`;
  tourSteps[0].copy = `Follow ${followedScore.cve_id} on ${followedScore.host_ip}. The finding starts with a scanner record, not a model's guess.`;
  tourSteps[2].target = `[id="context-${followedScore.host_ip}"]`;
  tourSteps[2].copy = `The stored role for ${followedScore.host_ip} has a confidence and an exact evidence quote. Manual tags are marked separately.`;
  tourSteps[4].target = `#ranked-list [data-inspect="${followedScore.finding_id}"]`;
  tourSteps[4].copy = `The same finding now has stored risk ${followedScore.risk} and band ${followedScore.band}. Open it to inspect the score inputs and original source.`;
}

function showTour() {
  document.querySelector('.tour-target')?.classList.remove('tour-target');
  const tour = document.getElementById('tour');
  tour.hidden = tourStep < 0;
  if (tourStep < 0) return;
  if (dialog?.open) dialog.close();
  const step = tourSteps[tourStep];
  setState(step.stage);
  restoreView();
  document.getElementById('tour-position').textContent = `TRACE ONE FINDING / ${tourStep + 1} OF ${tourSteps.length}`;
  document.getElementById('tour-title').textContent = step.title;
  document.getElementById('tour-copy').textContent = step.copy;
  document.getElementById('tour-back').disabled = tourStep === 0;
  document.getElementById('tour-next').textContent = tourStep === tourSteps.length - 1 ? 'Finish' : 'Next';
  const target = document.querySelector(step.target);
  if (target) { target.classList.add('tour-target'); target.scrollIntoView({block: 'nearest', behavior: 'instant'}); }
}
document.getElementById('start-tour').disabled = !bootstrap.assessment;
document.getElementById('start-tour').addEventListener('click', () => { tourStep = 0; showTour(); });
document.getElementById('tour-next').addEventListener('click', () => { tourStep = tourStep === tourSteps.length - 1 ? -1 : tourStep + 1; showTour(); });
document.getElementById('tour-back').addEventListener('click', () => { tourStep = Math.max(0, tourStep - 1); showTour(); });
document.getElementById('tour-close').addEventListener('click', () => { tourStep = -1; showTour(); });
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  if (document.getElementById('palette')?.open) return;
  if (dialog?.open) {
    event.preventDefault();
    dialog.close();
  }
  if (tourStep >= 0) {
    tourStep = -1;
    showTour();
    document.getElementById('start-tour').focus();
  }
});
const sandboxForm = document.getElementById('sandbox-form');
let sandboxProfile = null;
function sandboxResult() {
  const selected = bootstrap.assessment?.scores.find(score => score.finding_id === sandboxForm?.elements.finding.value);
  if (!selected || !sandboxProfile) return;
  const elements = sandboxForm.elements;
  const errorBox = document.getElementById('sandbox-error');
  const missing = elements['epss-missing'].checked;
  elements.epss.disabled = missing;
  document.getElementById('sandbox-epss').textContent = missing ? 'Absent' : elements.epss.value;
  try {
    const result = sandbox(selected.base_vector, sandboxProfile, {
      role: elements.role.value, exposure: elements.exposure.value, environment: elements.environment.value,
      waf: elements.waf.checked, kev: elements.kev.checked, epss: missing ? null : Number(elements.epss.value)
    }, bootstrap.configuration.weights.values);
    document.getElementById('sandbox-environmental').textContent = String(result.environmental);
    document.getElementById('sandbox-threat').textContent = result.multiplier === null ? 'Unscored' : String(result.multiplier);
    document.getElementById('sandbox-risk').textContent = String(result.risk);
    document.getElementById('sandbox-band').textContent = result.band;
    document.getElementById('sandbox-vector').textContent = result.vector;
    errorBox.hidden = true;
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.hidden = false;
    for (const name of ['environmental', 'threat', 'risk', 'band']) document.getElementById(`sandbox-${name}`).textContent = 'Unavailable';
  }
}
function resetSandbox() {
  const selected = bootstrap.assessment?.scores.find(score => score.finding_id === sandboxForm?.elements.finding.value);
  if (!selected) return;
  sandboxProfile = JSON.parse(JSON.stringify(selected.inputs));
  const elements = sandboxForm.elements;
  elements.role.value = selected.inputs.role.value;
  elements.exposure.value = selected.inputs.exposure.value;
  elements.environment.value = selected.inputs.manual?.environment?.value || 'prod';
  elements.waf.checked = Boolean(selected.inputs.controls?.waf?.value);
  elements.kev.checked = selected.kev;
  elements['epss-missing'].checked = selected.epss_percentile === null;
  elements.epss.value = selected.epss_percentile === null ? '0' : String(selected.epss_percentile);
  sandboxResult();
}
if (sandboxForm) {
  if (bootstrap.tour_finding) sandboxForm.elements.finding.value = bootstrap.tour_finding;
  sandboxForm.addEventListener('submit', event => event.preventDefault());
  sandboxForm.addEventListener('input', event => event.target.name === 'finding' ? resetSandbox() : sandboxResult());
  document.getElementById('sandbox-reset').addEventListener('click', resetSandbox);
  resetSandbox();
}
document.getElementById('selfcheck')?.addEventListener('click', async () => {
  const result = document.getElementById('selfcheck-result');
  try {
    let fixture = bootstrap.cvss_fixture;
    if (!fixture) {
      const response = await fetch('/api/cvss-fixture', {cache: 'no-store', credentials: 'same-origin'});
      if (!response.ok) throw new Error('CVSS regression fixture is unavailable.');
      fixture = await response.json();
    }
    const failures = fixture.vectors.filter(row => {
      const scored = scoreVector(row.vector);
      return scored.base !== row.base || scored.environmental !== row.environmental;
    });
    const scenarioFailures = fixture.sandbox_cases.filter(row => {
      const scored = sandbox(row.vector, row.profile, row.changes, fixture.sandbox_weights);
      return Object.keys(row.expected).some(key => scored[key] !== row.expected[key]);
    });
    result.textContent = `${fixture.vectors.length - failures.length} of ${fixture.vectors.length} CVSS vectors match Python. ${fixture.sandbox_cases.length - scenarioFailures.length} of ${fixture.sandbox_cases.length} sandbox cases match; ${failures.length + scenarioFailures.length} failed.`;
  } catch (error) { result.textContent = `Not run: ${error.message}`; }
});

window.addEventListener('hashchange', restoreView);
restoreView();
if (state().parameters.get('tour') === '1' && bootstrap.tour_finding) {
  tourStep = 0;
  showTour();
}

const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
function fillDials(scope) {
  for (const dial of scope.querySelectorAll('[data-dial]')) {
    dial.querySelector('.dial-value')?.setAttribute('stroke-dasharray', `${dial.dataset.dial} 100`);
  }
}
const revealables = [...document.querySelectorAll('[data-reveal]')];
if (revealables.length && 'IntersectionObserver' in window && !reduceMotion) {
  const revealer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add('revealed');
      fillDials(entry.target);
      revealer.unobserve(entry.target);
    }
  }, {threshold: 0.15});
  for (const item of revealables) revealer.observe(item);
} else {
  for (const item of revealables) {
    item.classList.add('revealed');
    fillDials(item);
  }
}

function countUp(element) {
  const target = Number(element.dataset.count);
  if (!Number.isFinite(target) || reduceMotion || target === 0) { element.textContent = String(target); return; }
  const started = performance.now();
  const duration = 700;
  function tick(now) {
    const share = Math.min((now - started) / duration, 1);
    element.textContent = String(Math.round(target * (1 - Math.pow(1 - share, 3))));
    if (share < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}
for (const value of document.querySelectorAll('[data-count]')) {
  if ('IntersectionObserver' in window && !reduceMotion) {
    const counter = new IntersectionObserver(entries => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        countUp(entry.target);
        counter.unobserve(entry.target);
      }
    }, {threshold: 0.5});
    counter.observe(value);
  } else countUp(value);
}

const palette = document.getElementById('palette');
const paletteInput = document.getElementById('palette-input');
const paletteResults = document.getElementById('palette-results');
const paletteCount = document.getElementById('palette-count');
const paletteEntries = [];
let paletteMatches = [];
let paletteActive = 0;

function buildPalette() {
  const stageDetail = {
    evidence: 'What the scanners observed',
    context: 'What the clues imply',
    risk: 'Why urgency changes',
    priorities: 'What to examine first'
  };
  for (const stage of stageNames) {
    paletteEntries.push({kind: 'Stage', label: stage[0].toUpperCase() + stage.slice(1), detail: stageDetail[stage], stage});
  }
  const assessment = bootstrap.assessment;
  if (!assessment) return;
  const scored = new Map(assessment.scores.map(score => [score.finding_id, score]));
  for (const host of assessment.hosts) {
    paletteEntries.push({
      kind: 'Host',
      label: host.ip,
      detail: `${host.services.length} stored services`,
      stage: 'evidence',
      anchor: `host-${host.ip}`
    });
  }
  for (const finding of assessment.findings) {
    const score = scored.get(finding.id) || {};
    const identity = score.cve_id || finding.cve_ids.join(' ') || finding.tool_native_id;
    paletteEntries.push({
      kind: 'Finding',
      label: finding.title,
      detail: `${score.band || 'Unscored'} \u00b7 ${finding.host_ip} \u00b7 ${identity}`,
      terms: `${finding.tool} ${identity} ${finding.host_ip} ${score.risk ?? ''}`,
      finding: finding.id
    });
  }
}

function choosePalette(entry) {
  palette.close();
  const current = state();
  if (entry.finding) {
    const parameters = current.parameters;
    parameters.set('finding', entry.finding);
    setState(current.stage, parameters);
    restoreView();
    openInspector(entry.finding);
    return;
  }
  setState(entry.stage);
  restoreView();
  if (entry.anchor) document.getElementById(entry.anchor)?.scrollIntoView({block: 'start'});
}

function renderPalette() {
  const terms = paletteInput.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  paletteMatches = paletteEntries.filter(entry => {
    const haystack = `${entry.kind} ${entry.label} ${entry.detail} ${entry.terms || ''}`.toLowerCase();
    return terms.every(term => haystack.includes(term));
  }).slice(0, 40);
  if (paletteActive >= paletteMatches.length) paletteActive = 0;
  paletteResults.replaceChildren();
  paletteMatches.forEach((entry, index) => {
    const item = document.createElement('li');
    item.className = index === paletteActive ? 'palette-item active' : 'palette-item';
    item.id = `palette-option-${index}`;
    item.setAttribute('role', 'option');
    item.setAttribute('aria-selected', String(index === paletteActive));
    for (const [className, text] of [['palette-kind', entry.kind], ['palette-label', entry.label], ['palette-detail', entry.detail]]) {
      const part = document.createElement('span');
      part.className = className;
      part.textContent = text;
      item.append(part);
    }
    item.addEventListener('click', () => choosePalette(entry));
    paletteResults.append(item);
  });
  if (!paletteMatches.length) {
    const empty = document.createElement('li');
    empty.className = 'palette-empty';
    empty.textContent = 'Nothing stored matches that search.';
    paletteResults.append(empty);
  }
  paletteCount.textContent = `${paletteMatches.length} of ${paletteEntries.length}`;
  paletteInput.setAttribute('aria-activedescendant', paletteMatches.length ? `palette-option-${paletteActive}` : '');
}

function openPalette() {
  if (!palette || palette.open) return;
  paletteInput.value = '';
  paletteActive = 0;
  renderPalette();
  palette.showModal();
  paletteInput.focus();
}

if (palette) {
  buildPalette();
  document.getElementById('open-palette').addEventListener('click', openPalette);
  paletteInput.addEventListener('input', () => { paletteActive = 0; renderPalette(); });
  paletteInput.addEventListener('keydown', event => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (!paletteMatches.length) return;
      const step = event.key === 'ArrowDown' ? 1 : -1;
      paletteActive = (paletteActive + step + paletteMatches.length) % paletteMatches.length;
      renderPalette();
      document.getElementById(`palette-option-${paletteActive}`)?.scrollIntoView({block: 'nearest'});
    } else if (event.key === 'Enter') {
      event.preventDefault();
      if (paletteMatches[paletteActive]) choosePalette(paletteMatches[paletteActive]);
    }
  });
  document.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openPalette();
    }
  });
}
