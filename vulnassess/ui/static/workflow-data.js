/* TRACEBACK data layer. Every value a layer shows is copied from stored records;
 * nothing here computes a score, infers a state, or invents feed freshness. */

export function currentSlice(assessment, hostIp = '', findingId = '') {
  const selectedHost = hostIp || assessment.findings.find(finding => finding.id === findingId)?.host_ip || '';
  const hosts = assessment.hosts.filter(host => !selectedHost || host.ip === selectedHost);
  const findings = assessment.findings.filter(finding => (!selectedHost || finding.host_ip === selectedHost) && (!findingId || finding.id === findingId));
  const identities = new Set(findings.map(finding => finding.id));
  const hostAddresses = new Set(hosts.map(host => host.ip));
  return {
    hosts, findings,
    scores: assessment.scores.filter(score => identities.has(score.finding_id)),
    enrichments: assessment.enrichments.filter(item => identities.has(item.finding_id)),
    profiles: assessment.context.filter(profile => hostAddresses.has(profile.host_ip)),
    rationales: assessment.rationales.filter(item => identities.has(item.finding_id)),
  };
}

export function evidenceKind(assessment) {
  const paths = [...assessment.feeds_meta.map(feed => feed.path), ...assessment.findings.map(finding => finding.provenance.raw_path)];
  return paths.some(path => String(path).toLowerCase().includes('synthetic')) ? 'SYNTHETIC INPUTS' : 'SOURCE UNLABELLED';
}

export function sourceStamps(assessment) {
  const tools = ['nmap', 'zap', 'nikto'];
  return tools.map(tool => ({
    tool,
    recorded: assessment.findings.some(finding => finding.tool === tool)
      || (assessment.run.summary.imports || []).some(item => Object.hasOwn(item.findings || {}, tool)),
  }));
}

function featureRows(profile) {
  if (!profile) return [];
  return [['Role', profile.role], ['Exposure', profile.exposure], ...Object.entries(profile.controls || {}), ...Object.entries(profile.manual || {})]
    .filter(([, feature]) => feature)
    .map(([name, feature]) => ({
      label: name.replaceAll('_', ' '),
      value: feature.value,
      confidence: feature.confidence,
      source: feature.source,
      quote: feature.evidence,
    }));
}

export function queueRows(assessment, hostIp = '') {
  const titles = new Map(assessment.findings.map(finding => [finding.id, finding]));
  return assessment.scores
    .filter(score => !hostIp || score.host_ip === hostIp)
    .map((score, index) => {
      const finding = titles.get(score.finding_id);
      return {
        position: index + 1,
        finding_id: score.finding_id,
        host_ip: score.host_ip,
        port: finding?.port ?? null,
        cve_id: score.cve_id,
        tool: finding?.tool || 'unknown',
        title: finding?.title || score.finding_id,
        risk: score.risk,
        band: score.band,
      };
    });
}

/* The five stored layers of one stored score. Missing layers stay in the trace
 * with their absence named; absence is never rendered as zero or as a blank. */
export function traceLayers(assessment, scope, weights, selection = {}, analysis = null) {
  const findingId = selection.finding || '';
  const finding = assessment.findings.find(item => item.id === findingId) || null;
  const score = assessment.scores.find(item => item.finding_id === findingId) || null;
  const enrichments = assessment.enrichments.filter(item => item.finding_id === findingId);
  const profile = finding ? assessment.context.find(item => item.host_ip === finding.host_ip) || null : null;
  const position = queueRows(assessment, finding?.host_ip || '').find(row => row.finding_id === findingId)?.position || null;
  const runId = assessment.run.run_id;
  const analysisForThisRun = analysis && analysis.runId === runId && analysis.hostIp === (finding?.host_ip || selection.host) ? analysis : null;
  const layers = [
    {
      id: 'priority',
      title: 'PRIORITY',
      operation: 'The stored risk order, exactly as the deterministic run recorded it.',
      present: Boolean(score),
      missing: 'This finding has no stored score. It was imported but never scored; no band is inferred here.',
      rows: score ? [
        {label: 'Stored risk', value: score.risk},
        {label: 'Band', value: score.band},
        {label: 'Queue position', value: position},
        {label: 'Recorded reason', value: score.reason},
        {label: 'Weights hash', value: score.weights_hash},
        {label: 'Config hash', value: assessment.run.config_hash},
      ] : [],
      outputs: [
        {label: 'Report artifact', value: 'Not attached'},
        {label: 'Expert evaluation', value: 'No result attached'},
        {label: 'Re-scan comparison', value: 'No comparison attached'},
      ],
    },
    {
      id: 'calculation',
      title: 'CALCULATION',
      operation: 'Deterministic arithmetic over the stored inputs. No model participates.',
      present: Boolean(score),
      missing: 'No calculation is stored for this finding.',
      rows: score ? [
        {label: 'CVSS version used', value: score.cvss_version_used},
        {label: 'Base score', value: score.base_score},
        {label: 'Base vector', value: score.base_vector},
        {label: 'Environmental score', value: score.env_score},
        {label: 'Environmental vector', value: score.env_vector},
        {label: 'Threat multiplier', value: score.threat_multiplier === null ? 'Unscored — EPSS missing' : score.threat_multiplier},
        {label: 'EPSS percentile used', value: score.epss_percentile},
        {label: 'KEV applied', value: score.kev},
        {label: 'Native fallback', value: score.native_fallback},
      ] : [],
      vector: score?.env_vector || score?.base_vector || null,
    },
    {
      id: 'intelligence',
      title: 'INTELLIGENCE',
      operation: 'Stored NVD / EPSS / KEV matches for this finding, with their match provenance.',
      present: enrichments.length > 0,
      missing: 'No enrichment stored for this finding. A native-severity fallback may still have been scored.',
      groups: enrichments.map(item => ({
        title: item.cve_id,
        rows: [
          {label: 'Match method', value: item.match_method},
          {label: 'Match confidence', value: item.match_confidence},
          {label: 'CVSS 3.1 base', value: item.cvss31_base},
          {label: 'CVSS 3.1 vector', value: item.cvss31_vector},
          {label: 'CVSS 4.0 base', value: item.cvss40_base},
          {label: 'EPSS probability', value: item.epss},
          {label: 'EPSS percentile', value: item.epss_percentile},
          {label: 'KEV member', value: item.kev},
          {label: 'KEV date added', value: item.kev_date_added},
          {label: 'Version boundary', value: item.version_end},
        ],
        quote: item.description ? {label: 'Intel description', text: item.description} : null,
      })),
    },
    {
      id: 'context',
      title: 'CONTEXT',
      operation: 'The evidence-backed role, exposure and controls recorded for this host.',
      present: Boolean(profile),
      missing: 'No context profile stored for this host.',
      features: featureRows(profile),
      rows: profile?.segment ? [{label: 'Segment', value: profile.segment}] : [],
    },
    {
      id: 'evidence',
      title: 'RAW EVIDENCE',
      operation: 'The verbatim scanner record this finding was built from. Not paraphrased.',
      present: Boolean(finding),
      missing: 'No stored finding record for this selection.',
      rows: finding ? [
        {label: 'Scanner', value: finding.tool},
        {label: 'Native identifier', value: finding.tool_native_id},
        {label: 'Endpoint', value: finding.url || (finding.port ? `${finding.host_ip}:${finding.port}/${finding.protocol || ''}` : finding.host_ip)},
        {label: 'CVEs', value: finding.cve_ids.join(', ') || null},
        {label: 'CWEs', value: finding.cwe_ids.join(', ') || null},
        {label: 'Native severity', value: finding.native_severity},
        {label: 'First seen', value: finding.first_seen},
        {label: 'Raw artifact', value: finding.provenance.raw_path},
        {label: 'Record index', value: finding.provenance.record_index},
      ] : [],
      quote: finding ? {label: 'Verbatim evidence', text: finding.evidence} : null,
    },
  ];
  return {finding, score, position, layers, sources: sourceStamps(assessment), analysis: analysisForThisRun};
}

/* Values the compare view marks as diverging between two stored scores. */
export function diffFields(scoreA, scoreB) {
  if (!scoreA || !scoreB) return new Set();
  const fields = ['risk', 'band', 'base_score', 'env_score', 'threat_multiplier', 'epss_percentile', 'kev'];
  return new Set(fields.filter(field => String(scoreA[field]) !== String(scoreB[field])));
}
