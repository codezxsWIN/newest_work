import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source = readFileSync(new URL('../../vulnassess/ui/static/workflow-data.js', import.meta.url), 'utf8');
const workflow = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const input = JSON.parse(readFileSync(0, 'utf8'));
const before = JSON.stringify(input.assessment);
const nodes = workflow.buildNodes(input.assessment, input.scope);
assert.equal(new Set(nodes.map(node => node.id)).size, nodes.length);
for (const edge of workflow.EDGES) {
  assert.ok(nodes.some(node => node.id === edge.from));
  assert.ok(nodes.some(node => node.id === edge.to));
  assert.notEqual(edge.from, edge.to);
}
for (const identity of ['scope', 'nmap', 'zap', 'nikto', 'canonical', 'nvd', 'epss', 'kev', 'intel', 'context', 'shadow', 'score', 'queue', 'rationale', 'report', 'analyst', 'evaluation', 'rescan']) assert.ok(nodes.some(node => node.id === identity));
assert.equal(nodes.find(node => node.id === 'analyst').status, 'Not run');
assert.equal(nodes.find(node => node.id === 'report').status, 'Artifact not attached');
assert.equal(nodes.find(node => node.id === 'evaluation').status, 'No result attached');
assert.ok(!workflow.EDGES.some(edge => edge.from === 'analyst' && ['context', 'score', 'queue'].includes(edge.to)));
const host = input.assessment.hosts[0].ip;
const slice = workflow.currentSlice(input.assessment, host);
assert.deepEqual(slice.scores, input.assessment.scores.filter(score => score.host_ip === host));
const score = slice.scores[0];
const details = workflow.nodeDetails('score', input.assessment, input.scope, input.weights, {host, finding: score.finding_id});
assert.deepEqual(details.records, [score]);
assert.equal(details.rows.find(row => row.label === 'Risk').value, score.risk);
assert.equal(details.rows.find(row => row.label === 'Threat multiplier').value, score.threat_multiplier);
assert.deepEqual(workflow.currentSlice(input.assessment, '', score.finding_id).profiles, input.assessment.context.filter(profile => profile.host_ip === score.host_ip));
const selected = {host};
const result = {runId: input.assessment.run.run_id, hostIp: host, status: 'complete', result: {}};
assert.equal(workflow.buildNodes(input.assessment, input.scope, selected, result).find(node => node.id === 'analyst').status, 'Response received');
assert.equal(workflow.buildNodes(input.assessment, input.scope, {host: 'synthetic-other'}, result).find(node => node.id === 'analyst').status, 'Not run');
assert.equal(workflow.buildNodes(input.assessment, input.scope, selected, {...result, status: 'error'}).find(node => node.id === 'analyst').status, 'Request failed');
const empty = {...input.assessment, hosts: [], findings: [], scores: [], enrichments: [], context: [], rationales: [], feeds_meta: [], run: {...input.assessment.run, summary: {}}};
assert.equal(workflow.buildNodes(empty, null).find(node => node.id === 'score').status, 'No stored output');
assert.equal(workflow.buildNodes(empty, null).find(node => node.id === 'nmap').status, 'No import recorded');
assert.equal(JSON.stringify(input.assessment), before);
console.log(`WORKFLOW: ${nodes.length} nodes; graph links, stored score fidelity, empty states and analyst isolation passed`);