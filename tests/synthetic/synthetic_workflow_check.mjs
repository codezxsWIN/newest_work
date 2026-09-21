import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source = readFileSync(new URL('../../vulnassess/ui/static/workflow-data.js', import.meta.url), 'utf8');
const workflow = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const input = JSON.parse(readFileSync(0, 'utf8'));
const before = JSON.stringify(input.assessment);
const nodes = workflow.buildNodes(input.assessment, input.scope);
assert.equal(new Set(nodes.map(node => node.id)).size, nodes.length);
for (const node of nodes) {
  assert.ok(node.x >= 82 && node.x + 82 <= workflow.SIZE.width, `${node.id} tile must fit horizontally`);
  assert.ok(node.y >= 49 && node.y + 130 <= workflow.SIZE.height, `${node.id} tile and labels must fit vertically`);
  for (const other of nodes.filter(other => other.id !== node.id)) {
    assert.ok(Math.abs(node.x - other.x) >= 164 || Math.abs(node.y - other.y) >= 179, `${node.id} and ${other.id} must not overlap`);
  }
}
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

const clientSource = readFileSync(new URL('../../vulnassess/ui/static/analyst-client.js', import.meta.url), 'utf8');
const client = await import(`data:text/javascript;base64,${Buffer.from(clientSource).toString('base64')}`);
const syntheticResponse = (runId, hostIp) => ({
  run_id: runId, host_ip: hostIp, model: 'synthetic-model', canonical_scores_changed: false,
  analysis: {
    summary: 'Synthetic response for a pure queue test, not model evidence.', confidence: 'low',
    recommended_actions: [{order: 1, action: 'Synthetic action', reason: 'Synthetic reason', finding_ids: ['synthetic-finding'], evidence_ids: ['E1']}],
    correlations: [], uncertainties: ['Synthetic uncertainty'],
  },
  evidence: [{id: 'E1', text: 'Synthetic evidence for a unit test only.'}],
});
const requested = [];
let activeRequests = 0;
let peakRequests = 0;
const queue = client.createAnalysisQueue({request: async (runId, hostIp) => {
  requested.push(hostIp);
  activeRequests += 1;
  peakRequests = Math.max(peakRequests, activeRequests);
  await Promise.resolve();
  activeRequests -= 1;
  return syntheticResponse(runId, hostIp);
}});
assert.equal(requested.length, 0, 'Constructing the queue must not request analysis');
const queueTargets = ['synthetic-host-a', 'synthetic-host-b', 'synthetic-host-c'];
const finished = await queue.start('synthetic-run', queueTargets);
assert.deepEqual(requested, queueTargets);
assert.equal(peakRequests, 1);
assert.equal(finished.busy, false);
assert.deepEqual(finished.entries.map(entry => entry.status), ['complete', 'complete', 'complete']);
assert.deepEqual(queueTargets, ['synthetic-host-a', 'synthetic-host-b', 'synthetic-host-c']);

let releaseRequest;
const heldResponse = new Promise(resolve => { releaseRequest = resolve; });
const stoppedRequests = [];
const stoppedQueue = client.createAnalysisQueue({request: async (runId, hostIp) => {
  stoppedRequests.push(hostIp);
  await heldResponse;
  return syntheticResponse(runId, hostIp);
}});
const pendingQueue = stoppedQueue.start('synthetic-run', queueTargets);
await assert.rejects(stoppedQueue.start('synthetic-run', queueTargets), /already in progress/);
assert.equal(stoppedQueue.stopAfterCurrent(), true);
releaseRequest();
const stopped = await pendingQueue;
assert.deepEqual(stoppedRequests, ['synthetic-host-a']);
assert.deepEqual(stopped.entries.map(entry => entry.status), ['complete', 'not-run', 'not-run']);
assert.equal(stoppedQueue.stopAfterCurrent(), false);

const failedRequests = [];
const failedQueue = client.createAnalysisQueue({request: async (_runId, hostIp) => {
  failedRequests.push(hostIp);
  throw new Error('Synthetic model unavailable');
}});
const failed = await failedQueue.start('synthetic-run', queueTargets);
assert.deepEqual(failedRequests, ['synthetic-host-a']);
assert.deepEqual(failed.entries.map(entry => entry.status), ['error', 'not-run', 'not-run']);
assert.equal(failed.entries[0].result, null);
assert.equal(failed.entries[0].error, 'Synthetic model unavailable');
await assert.rejects(queue.start('synthetic-run', []), /recorded systems/);
await assert.rejects(queue.start('synthetic-run', ['synthetic-host-a', 'synthetic-host-a']), /distinct/);
for (const invalid of [
  {...syntheticResponse('synthetic-run', 'synthetic-host-a'), run_id: 'synthetic-other-run'},
  {...syntheticResponse('synthetic-run', 'synthetic-host-a'), host_ip: 'synthetic-other-host'},
  {...syntheticResponse('synthetic-run', 'synthetic-host-a'), canonical_scores_changed: true},
  {...syntheticResponse('synthetic-run', 'synthetic-host-a'), evidence: []},
]) {
  assert.throws(() => client.validateAnalystResponse(invalid, 'synthetic-run', 'synthetic-host-a'));
}
const mismatchedQueue = client.createAnalysisQueue({request: async () => syntheticResponse('synthetic-other-run', 'synthetic-host-a')});
const mismatched = await mismatchedQueue.start('synthetic-run', queueTargets);
assert.deepEqual(mismatched.entries.map(entry => entry.status), ['error', 'not-run', 'not-run']);
assert.equal(JSON.stringify(input.assessment), before);
console.log('ANALYST: sequential requests, duplicate prevention, stop, failure, identity and citation checks; analyst queue safety passed');