import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source = readFileSync(new URL('../../vulnassess/ui/static/workflow-data.js', import.meta.url), 'utf8');
const workflow = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const input = JSON.parse(readFileSync(0, 'utf8'));
const before = JSON.stringify(input.assessment);

const rows = workflow.queueRows(input.assessment);
assert.equal(rows.length, input.assessment.scores.length);
assert.deepEqual(rows.map(row => row.risk), input.assessment.scores.map(score => score.risk), 'queue order must equal stored risk order');
assert.deepEqual(rows.map((row, index) => row.position), rows.map((_, index) => index + 1));
const titles = new Map(input.assessment.findings.map(finding => [finding.id, finding]));
for (const row of rows) {
  const finding = titles.get(row.finding_id);
  assert.ok(finding, 'queue row must reference a stored finding');
  assert.equal(row.host_ip, finding.host_ip);
  assert.equal(row.tool, finding.tool);
}

const first = rows[0];
const trace = workflow.traceLayers(input.assessment, input.scope, input.weights, {host: first.host_ip, finding: first.finding_id});
assert.equal(trace.layers.length, 5);
assert.deepEqual(trace.layers.map(layer => layer.id), ['priority', 'calculation', 'intelligence', 'context', 'evidence']);
const priority = trace.layers.find(layer => layer.id === 'priority');
assert.equal(priority.rows.find(row => row.label === 'Stored risk').value, first.risk, 'stored score fidelity');
assert.equal(priority.rows.find(row => row.label === 'Band').value, first.band, 'stored score fidelity');
const calculation = trace.layers.find(layer => layer.id === 'calculation');
assert.equal(calculation.rows.find(row => row.label === 'Threat multiplier').value, input.assessment.scores[0].threat_multiplier, 'stored score fidelity');
assert.equal(calculation.rows.find(row => row.label === 'EPSS percentile used').value, input.assessment.scores[0].epss_percentile, 'stored score fidelity');
const evidence = trace.layers.find(layer => layer.id === 'evidence');
assert.equal(evidence.quote.text, titles.get(first.finding_id).evidence, 'verbatim evidence fidelity');
assert.ok(evidence.rows.find(row => row.label === 'Raw artifact').value, 'provenance path shown');
const stored = input.assessment.enrichments.filter(item => item.finding_id === first.finding_id);
const intelligence = trace.layers.find(layer => layer.id === 'intelligence');
assert.equal(intelligence.present, stored.length > 0);
if (stored.length) {
  const ids = new Set(stored.map(item => item.cve_id));
  for (const group of intelligence.groups) assert.ok(ids.has(group.title));
  assert.equal(intelligence.groups[0].rows.find(row => row.label === 'Match method').value, stored[0].match_method, 'stored score fidelity');
}
const profile = input.assessment.context.find(item => item.host_ip === first.host_ip);
assert.equal(trace.layers.find(layer => layer.id === 'context').present, Boolean(profile));

// Analyst responses never leak across run or host, and never touch stored layers.
const host = input.assessment.hosts[0].ip;
const analysis = {runId: input.assessment.run.run_id, hostIp: host, status: 'complete', result: {}};
assert.equal(workflow.traceLayers(input.assessment, null, null, {host}, analysis).analysis, analysis);
assert.equal(workflow.traceLayers(input.assessment, null, null, {host: 'synthetic-other', finding: first.finding_id}, analysis).analysis, null);
assert.equal(workflow.traceLayers(input.assessment, null, null, {host, finding: first.finding_id}, {...analysis, runId: 'synthetic-other-run'}).analysis, null);
assert.equal(workflow.traceLayers(input.assessment, null, null, {host, finding: first.finding_id}, analysis).score, input.assessment.scores.find(score => score.finding_id === first.finding_id));

// Slice fidelity is unchanged.
const slice = workflow.currentSlice(input.assessment, host);
assert.deepEqual(slice.scores, input.assessment.scores.filter(score => score.host_ip === host));
assert.deepEqual(workflow.currentSlice(input.assessment, '', first.finding_id).profiles, input.assessment.context.filter(item => item.host_ip === first.host_ip));

// Divergence marking: two stored scores differing in a field are reported as differing.
const other = rows[1] ? input.assessment.scores.find(score => score.finding_id === rows[1].finding_id) : null;
if (other) {
  const cloned = JSON.parse(JSON.stringify(other));
  cloned.risk = other.risk === 1 ? 2 : 1;
  assert.ok(workflow.diffFields(input.assessment.scores.find(score => score.finding_id === first.finding_id), cloned).has('risk'));
}

// Empty store: every layer names its absence; no band, order or enrichment is invented.
const empty = {...input.assessment, hosts: [], findings: [], scores: [], enrichments: [], context: [], rationales: [], feeds_meta: [], run: {...input.assessment.run, summary: {}}};
assert.equal(workflow.queueRows(empty).length, 0);
const emptyTrace = workflow.traceLayers(empty, null, null, {});
assert.equal(emptyTrace.finding, null);
assert.ok(emptyTrace.layers.every(layer => !layer.present && layer.missing), 'absent layers must name their absence');

assert.equal(JSON.stringify(input.assessment), before, 'assessment records must never be mutated');
console.log(`TRACEBACK: ${rows.length} stored marks; queue order, layer fidelity, provenance, analyst isolation, empty states and stored score fidelity passed`);
