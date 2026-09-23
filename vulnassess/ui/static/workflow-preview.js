const step = (id, label, node, edges, detail, outcome = 'complete') => ({id, label, node, edges, detail, outcome});

export const PREVIEW_SCENARIOS = {
  light: {
    label: 'Nmap + AI · no findings',
    context: 'Current live path: light Nmap scan followed by a grounded model assessment.',
    steps: [
      step('scope', 'Authorise target', 'scope', [], 'Simulated: the target is in scope and its address is pinned.'),
      step('scanner', 'Scan services', 'nmap', ['scope:nmap'], 'Simulated: Nmap observes SSH and HTTP; this light scan establishes no vulnerability.'),
      step('context', 'Infer context', 'context', ['nmap:canonical', 'canonical:context'], 'Simulated: infer an internet-facing web role from the observed services.'),
      step('model', 'Check model access', 'analyst', ['context:analyst'], 'Simulated: check that the selected model provider is available.'),
      step('evidence', 'Gather evidence', 'analyst', [], 'Simulated: collect service and context citations; no vulnerability finding exists.'),
      step('prompt', 'Ground request', 'analyst', [], 'Simulated: prepare the bounded evidence and uncertainty instructions.'),
      step('generation', 'Generate analysis', 'analyst', [], 'Simulated: the model proposes a cautious service verification.'),
      step('validation', 'Validate citations', 'analyst', [], 'Simulated: reject unknown citations and leave risk scores unchanged.'),
    ],
  },
  web: {
    label: 'Full web assessment',
    context: 'Orchestrated example: Nmap finds HTTP, so ZAP and Nikto can contribute findings. The current live button does not launch them.',
    steps: [
      step('scope', 'Authorise target', 'scope', [], 'Simulated: authorize and pin the lab target.'),
      step('scanner', 'Discover services', 'nmap', ['scope:nmap'], 'Simulated: Nmap observes an HTTP endpoint on the authorized target.'),
      step('zap', 'ZAP web checks', 'zap', ['scope:zap'], 'Simulated: ZAP baseline inspects the observed web endpoint.'),
      step('nikto', 'Nikto checks', 'nikto', ['scope:nikto'], 'Simulated: Nikto inspects the same observed web server.'),
      step('canonical', 'Normalize findings', 'canonical', ['nmap:canonical', 'zap:canonical', 'nikto:canonical'], 'Simulated: retain original scanner provenance while normalizing findings.'),
      step('intel', 'Enrich findings', 'intel', ['canonical:intel', 'nvd:intel', 'epss:intel', 'kev:intel'], 'Simulated: match supported CVEs to NVD, EPSS and KEV snapshots; unmatched findings stay unmatched.'),
      step('context', 'Infer context', 'context', ['canonical:context'], 'Simulated: infer role, exposure and controls from the authorized asset evidence.'),
      step('score', 'Calculate risk', 'score', ['intel:score', 'context:score'], 'Simulated: deterministic risk combines the stored findings, threat data and context.'),
      step('queue', 'Prioritize', 'queue', ['score:queue'], 'Simulated: order the scored findings without model-written scores.'),
      step('model', 'Check model', 'analyst', ['queue:analyst'], 'Simulated: confirm the selected analyst model is available.'),
      step('evidence', 'Build AI case', 'analyst', [], 'Simulated: select cited findings, services, intelligence and context within the evidence budget.'),
      step('generation', 'Investigate', 'analyst', [], 'Simulated: generate a hypothesis, verification step and alternative explanation grounded in citations.'),
      step('validation', 'Validate AI', 'analyst', [], 'Simulated: validate each cited ID and show uncertainty; scores remain deterministic.'),
    ],
  },
  noWeb: {
    label: 'No HTTP · web tools skipped',
    context: 'Orchestrated example: no HTTP(S) endpoint was observed, so web scanners are skipped.',
    steps: [
      step('scope', 'Authorise target', 'scope', [], 'Simulated: authorize the target.'),
      step('scanner', 'Discover services', 'nmap', ['scope:nmap'], 'Simulated: Nmap observes SSH but no HTTP(S) endpoint.'),
      step('zap', 'ZAP skipped', 'zap', [], 'Skipped: ZAP needs an observed HTTP(S) endpoint.', 'skipped'),
      step('nikto', 'Nikto skipped', 'nikto', [], 'Skipped: Nikto needs an observed HTTP(S) endpoint.', 'skipped'),
      step('context', 'Infer context', 'context', ['nmap:canonical', 'canonical:context'], 'Simulated: infer context from the observed non-web service.'),
      step('model', 'Check model', 'analyst', ['context:analyst'], 'Simulated: verify model availability.'),
      step('generation', 'Assess evidence', 'analyst', [], 'Simulated: describe service exposure without claiming an unobserved vulnerability.'),
      step('validation', 'Validate citations', 'analyst', [], 'Simulated: verify citations and retain the zero-finding boundary.'),
    ],
  },
  modelError: {
    label: 'Model unavailable',
    context: 'Failure example: collected scan evidence remains evidence, while AI analysis stops.',
    steps: [
      step('scope', 'Authorise target', 'scope', [], 'Simulated: authorize and pin the target.'),
      step('scanner', 'Scan services', 'nmap', ['scope:nmap'], 'Simulated: Nmap returns observed services.'),
      step('context', 'Infer context', 'context', ['nmap:canonical', 'canonical:context'], 'Simulated: infer context from the observed services.'),
      step('model', 'Check model', 'analyst', ['context:analyst'], 'Simulated failure: model endpoint unavailable; no AI result is substituted.', 'error'),
    ],
  },
  denied: {
    label: 'Target outside scope',
    context: 'Failure example: target authorization stops before any scanner or model stage.',
    steps: [
      step('scope', 'Authorise target', 'scope', [], 'Simulated failure: target is outside the authorized scope; no scan starts.', 'error'),
    ],
  },
};
