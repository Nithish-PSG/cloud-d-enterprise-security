(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const fmt = value => new Intl.NumberFormat('en-US').format(value || 0);
  const vectors = [
    { id: 'auth', attacker: 'Credential-Bot', defender: 'AuthSentinel', domain: 'Credential attacks', icon: '⌑', target: 'Auth Server', color: 'var(--cyan)' },
    { id: 'flow', attacker: 'FloodSwarm', defender: 'FlowGuardian', domain: 'DDoS / traffic floods', icon: '≋', target: 'API Gateway', color: 'var(--blue)' },
    { id: 'query', attacker: 'Injector-X', defender: 'QueryShield', domain: 'SQL injection', icon: '⌘', target: 'Primary DB', color: 'var(--purple)' },
    { id: 'behavior', attacker: 'GhostUser', defender: 'BehaviorWatch', domain: 'Insider / anomalous behavior', icon: '◌', target: 'Customer DB', color: 'var(--amber)' }
  ];
  let sim = null;
  let running = false;
  let apiPassword = '';
  try { apiPassword = sessionStorage.getItem('cloudDAccessPassword') || ''; } catch (_error) { /* file:// pages may disable session storage */ }

  function saveApiPassword(value) {
    apiPassword = value;
    try { sessionStorage.setItem('cloudDAccessPassword', value); } catch (_error) { /* keep the password in memory for this tab */ }
  }

  function clearApiPassword() {
    apiPassword = '';
    try { sessionStorage.removeItem('cloudDAccessPassword'); } catch (_error) { /* no persistent browser storage */ }
  }

  async function authorizedFetch(path, { method = 'GET', body, headers } = {}, retryAuth = true) {
    let response;
    try {
      const requestHeaders = new Headers(headers || {});
      if (apiPassword) requestHeaders.set('Authorization', `Bearer ${apiPassword}`);
      response = await fetch(path, { method, body, headers: requestHeaders });
    } catch (_error) {
      const message = location.protocol === 'file:'
        ? 'The dashboard file was opened directly. Start Cloud-D with Start Cloud-D.command, then use the local browser page.'
        : 'Could not reach the local simulation. Start Cloud-D.command again to launch its Python engine.';
      $('upload-status').textContent = message;
      throw new Error(message);
    }
    if (response.status === 401 && retryAuth) {
      const password = window.prompt('Enter the Cloud-D access password provided by the administrator.');
      if (password === null) throw new Error('Cloud-D access password is required.');
      saveApiPassword(password);
      return authorizedFetch(path, { method, body, headers }, false);
    }
    if (response.status === 401) {
      clearApiPassword();
    }
    return response;
  }

  async function request(path, options = {}) {
    const response = await authorizedFetch(path, options);
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status}).`);
    return payload;
  }

  function config() {
    return {
      threshold: Number($('threshold').value),
      intensity: $('intensity-select').value,
      active_vectors: [...document.querySelectorAll('.vector-toggle:checked')].map(input => input.value)
    };
  }

  function setSimulation(value) {
    sim = value;
    if (value.threshold !== undefined) {
      $('threshold').value = $('threshold-lab').value = value.threshold;
      $('threshold-label').textContent = $('threshold-lab-label').textContent = Number(value.threshold).toFixed(2);
      $('engine-threshold').textContent = Number(value.threshold).toFixed(2);
    }
    if (value.intensity) $('intensity-select').value = value.intensity;
    if (value.active_vectors) {
      document.querySelectorAll('.vector-toggle').forEach(input => { input.checked = value.active_vectors.includes(input.value); });
    }
    renderAll();
  }

  function showToast(message, error = false) {
    const toast = $('toast');
    toast.textContent = message;
    toast.style.background = error ? '#47252b' : '';
    toast.style.borderColor = error ? '#a44958' : '';
    toast.classList.add('show');
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => toast.classList.remove('show'), 3200);
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, character => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[character]);
  }

  function nav(page) {
    document.querySelectorAll('.page').forEach(item => item.classList.toggle('active', item.id === `page-${page}`));
    document.querySelectorAll('.nav button').forEach(button => button.classList.toggle('active', button.dataset.page === page));
    $('crumb-current').textContent = ({ cloud: 'Cloud', overview: 'Security Overview', simulation: 'Simulation', threats: 'Attack Simulation', report: 'Defense Report' })[page] || 'Cloud';
    window.scrollTo(0, 0);
  }

  function renderOverview() {
    const metrics = sim?.metrics;
    const counts = sim?.counts || {};
    const totalAttacks = metrics?.total_attacks || 0;
    const blocked = metrics?.blocked || 0;
    $('kpi-block').textContent = totalAttacks ? `${metrics.block_rate.toFixed(1)}%` : '—';
    $('kpi-block-note').innerHTML = totalAttacks ? `<strong>${blocked} blocked</strong> of ${totalAttacks} attack events` : 'Run the agents to start the simulation';
    $('kpi-data').textContent = metrics ? `${metrics.protection_rate.toFixed(3)}%` : '—';
    $('kpi-data-note').textContent = metrics ? `${fmt(metrics.protected)} / ${fmt(metrics.total_records)} actual records protected` : 'Records protected / stored';
    $('kpi-response').textContent = sim?.has_run ? `${sim.latency_ms} ms` : '—';
    $('kpi-contained').innerHTML = `${blocked} <small style="font-size:12px;color:#8190a8;font-weight:600">/ ${totalAttacks}</small>`;
    $('kpi-contained-note').textContent = sim?.round ? `${sim.round} of ${sim.max_rounds} rounds processed` : 'No attack rounds processed';
    $('round-pill').textContent = `${running ? 'RUNNING' : sim?.game_over ? 'COMPLETE' : sim?.round ? 'IN PROGRESS' : 'READY'} · ${sim?.round || 0} ROUNDS`;
    for (const vector of vectors) $(`node-${vector.id}`).textContent = counts[vector.id]?.actions || 0;
    for (let i = 1; i <= 4; i++) $(`link-${i}`).classList.toggle('active', running);
    renderAgentSummary();
    renderAttackSummary();
    renderFeed();
    renderNodes();
  }

  function renderAgentSummary() {
    const counts = sim?.counts || {};
    $('agent-summary').innerHTML = vectors.map(vector => {
      const count = counts[vector.id] || { scored: 0, blocked: 0 };
      const rate = count.scored ? count.blocked / count.scored * 100 : 0;
      return `<div class="agent-row"><div class="agent-id"><span class="agent-icon" style="--agent-color:${vector.color}">${vector.icon}</span>${vector.defender}</div><div class="bar-wrap"><div class="bar" style="--agent-color:${vector.color};width:${rate}%"></div></div><div class="agent-score">${count.scored ? `${rate.toFixed(0)}%` : '—'}</div></div>`;
    }).join('');
  }

  function renderAttackSummary() {
    const counts = sim?.counts || {};
    $('attack-summary').innerHTML = vectors.map(vector => {
      const count = counts[vector.id] || { scored: 0, blocked: 0 };
      const passed = count.scored - count.blocked;
      return `<div class="agent-row"><div class="agent-id"><span class="agent-icon" style="--agent-color:${vector.color}">${vector.icon}</span>${vector.attacker}</div><div style="color:#8796ad;font-size:9px">${count.scored} attempts · ${passed} passed</div><div class="agent-score"><span class="pill ${passed ? 'red' : count.scored ? 'green' : 'blue'}">${passed ? 'ACTIVE' : count.scored ? 'CLEAR' : 'IDLE'}</span></div></div>`;
    }).join('');
    $('attack-count-label').textContent = `${sim?.metrics?.total_attacks || 0} events`;
  }

  function renderFeed() {
    const events = [...(sim?.attack_log || [])].reverse().slice(0, 7);
    $('event-feed').innerHTML = events.length ? events.map(event => {
      const result = event.blocked ? 'Threat contained' : event.damage ? 'Threat impacted node' : 'Attempt caused no damage';
      const status = event.blocked ? '' : event.damage ? 'missed' : '';
      return `<div class="feed-item"><i class="feed-dot ${status}"></i><div><div class="feed-title">${result} · ${event.attacker}</div><div class="feed-detail">${event.action || 'No qualifying defense'} · Utility ${Number(event.utility).toFixed(2)} · ${event.target}${event.damage ? ` · ${event.damage} damage` : ''}</div></div><span class="feed-time">R${event.round}</span></div>`;
    }).join('') : '<div class="empty">Run a simulation to see agent decisions and attack outcomes.</div>';
  }

  function renderNodes() {
    const nodes = sim?.nodes || [];
    renderCloudFiles(nodes);
    if (!nodes.length) {
      $('node-cards').innerHTML = '<div class="empty" style="grid-column:1/-1">Cloud nodes are waiting for the local Python engine.</div>';
      $('cloud-status-pill').textContent = '5 NODES · READY';
      $('cloud-nodes-online').textContent = '—';
      $('cloud-record-count').textContent = '—';
      return;
    }
    $('node-cards').innerHTML = nodes.map(node => {
      const color = node.health > 70 ? 'var(--green)' : node.health > 30 ? 'var(--amber)' : 'var(--red)';
      const source = node.uploaded_records ? `${fmt(node.uploaded_records)} uploaded` : 'sample data';
      const files = (node.uploaded_files || []).map(escapeHtml);
      const storedFiles = files.length ? `<div class="asset-files" title="${files.join(', ')}">${files.join(' · ')}</div>` : '';
      return `<div class="asset-card"><div class="asset-name">${node.name}</div><div class="asset-role">${node.role.toUpperCase()} · ${node.status}</div><div class="asset-health"><span>Health</span><strong style="color:${color}">${node.health} HP</strong></div><div class="health-track"><div class="health-fill" style="width:${node.health}%;background:${color}"></div></div><div class="asset-data"><span>Records <strong>${fmt(node.total_records)}</strong></span><span>Exposed <strong>${fmt(node.compromised_records)}</strong></span></div><div class="asset-data"><span>${source}</span><strong>${node.protection_rate.toFixed(1)}%</strong></div>${storedFiles}<button type="button" class="asset-upload" data-upload-node="${node.id}">＋ Add documents</button></div>`;
    }).join('');
    const available = nodes.filter(node => node.health > 0).length;
    $('cloud-status-pill').textContent = `${available}/5 NODES ONLINE`;
    $('cloud-nodes-online').textContent = `${available} / ${nodes.length}`;
    $('cloud-record-count').textContent = fmt(nodes.reduce((total, node) => total + node.total_records, 0));
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return `${(bytes / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
  }

  function renderCloudFiles(nodes) {
    const files = nodes.flatMap(node => (node.files || []).map(file => ({ ...file, nodeName: node.name })));
    const storageBytes = files.reduce((total, file) => total + Number(file.size_bytes || 0), 0);
    $('cloud-file-count').textContent = fmt(files.length);
    $('cloud-storage-size').textContent = formatBytes(storageBytes);
    $('stored-files-pill').textContent = `${files.length} FILE${files.length === 1 ? '' : 'S'}`;
    $('cloud-files-body').innerHTML = files.length ? files.map(file => {
      const name = escapeHtml(file.filename);
      const kind = file.kind === 'data' ? 'Structured data' : 'Document';
      return `<tr><td><strong>${name}</strong></td><td>${escapeHtml(file.nodeName)}</td><td>${formatBytes(Number(file.size_bytes || 0))}</td><td>${kind}</td><td>${fmt(file.record_count)}</td><td><button class="btn" type="button" data-download-file="${escapeHtml(file.id)}" data-filename="${name}">Download</button></td></tr>`;
    }).join('') : '<tr><td colspan="6" class="empty">No files yet. Upload a document above to add it to the cloud.</td></tr>';
  }

  function renderAttackCards() {
    const counts = sim?.counts || {};
    const active = sim?.active_vectors || vectors.map(item => item.id);
    $('attack-cards').innerHTML = vectors.map(vector => {
      const count = counts[vector.id] || { scored: 0, blocked: 0 };
      const enabled = active.includes(vector.id);
      const algorithm = vector.id === 'auth' ? 'Minimax attacker' : vector.id === 'query' ? 'Expectimax defense' : vector.id === 'flow' ? 'Traffic growth model' : 'Stochastic success model';
      return `<article class="card attack-card" style="--attack-color:${vector.color};opacity:${enabled ? 1 : .45}"><div class="top"><span class="attack-symbol">${vector.icon}</span><span class="pill ${count.scored ? (count.scored === count.blocked ? 'green' : 'amber') : 'blue'}">${count.scored ? `${count.blocked}/${count.scored} BLOCKED` : enabled ? 'READY' : 'DISABLED'}</span></div><div class="attack-name">${vector.attacker}</div><div class="attack-type">${vector.domain} · ${algorithm}</div><div class="attack-stats"><span>Target node</span><strong>${vector.target}</strong></div></article>`;
    }).join('');
  }

  function renderAttackTable() {
    const rows = [...(sim?.attack_log || [])].reverse().slice(0, 16);
    $('attack-table').innerHTML = rows.length ? rows.map(event => `<tr><td>${String(event.round).padStart(2, '0')}</td><td><strong>${event.attacker}</strong><div class="node-meta">${event.tactic || event.attack_type}</div></td><td>${event.target}</td><td>${Number(event.utility).toFixed(2)}</td><td>${event.action || 'No action'}</td><td><span class="pill ${event.blocked ? 'green' : event.damage ? 'red' : 'amber'}">${event.blocked ? 'BLOCKED' : event.damage ? 'IMPACT' : 'NO DAMAGE'}</span></td></tr>`).join('') : '<tr><td colspan="6" class="empty">No events yet. Start a simulation to populate attack decisions.</td></tr>';
  }

  function renderAgentCards() {
    const blurbs = {
      auth: 'Scores credential attack signals and proposes IP blocking or account locks. Cross-round signature counts are shared through the cloud state. Credential-Bot searches two moves ahead with Minimax.',
      flow: 'Monitors simulated request rates and proposes rate limiting when a flood exceeds the node’s traffic tolerance.',
      query: 'Uses Expectimax chance nodes to compare query sanitization, rejection, and monitoring against uncertain parser outcomes.',
      behavior: 'Flags anomalous workforce access and estimates session-revocation utility from simulated credential-harvest evidence.'
    };
    const counts = sim?.counts || {};
    const defenders = sim?.defenders || [];
    $('agent-cards').innerHTML = vectors.map(vector => {
      const count = counts[vector.id] || { scored: 0, blocked: 0, actions: 0, last: 0 };
      const defender = defenders.find(item => item.vector_id === vector.id) || {};
      const searchValue = defender.search_nodes ? defender.search_nodes : vector.id === 'auth' ? (sim?.attackers?.find(item => item.vector_id === 'auth')?.search_nodes || 0) : 0;
      const method = vector.id === 'query' ? 'Expectimax' : 'Utility heuristic';
      const rate = count.scored ? `${(count.blocked / count.scored * 100).toFixed(1)}%` : '—';
      return `<article class="card agent-card"><div class="agent-card-head"><div class="agent-card-name"><span class="agent-icon" style="--agent-color:${vector.color}">${vector.icon}</span><div><h3>${vector.defender}</h3><div class="node-meta">${vector.domain}</div></div></div><span class="pill ${defender.active ? 'green' : 'blue'}">${defender.active ? 'ACTIVE' : 'READY'}</span></div><p>${blurbs[vector.id]}</p><div class="metric-pairs"><div><span>Events scored</span><strong>${count.scored}</strong></div><div><span>Actions proposed</span><strong>${count.actions}</strong></div><div><span>Decision method</span><strong>${method}</strong></div></div><div class="metric-pairs" style="border:0;padding-top:8px"><div><span>Containment</span><strong>${rate}</strong></div><div><span>Search nodes</span><strong>${searchValue || '—'}</strong></div><div><span>Last utility</span><strong>${count.scored ? Number(count.last).toFixed(2) : '—'}</strong></div></div></article>`;
    }).join('');
    $('agents-state').textContent = sim?.has_run ? `${sim.round} rounds · ${sim.metrics.blocked} blocks` : 'Awaiting simulation';
  }

  function renderReport() {
    const metrics = sim?.metrics;
    const counts = sim?.counts || {};
    $('report-block').textContent = metrics?.total_attacks ? `${metrics.block_rate.toFixed(1)}%` : '—';
    $('report-block-note').textContent = metrics?.total_attacks ? `${metrics.blocked} / ${metrics.total_attacks} attack events blocked` : 'No events yet';
    $('report-data').textContent = metrics ? `${metrics.protection_rate.toFixed(3)}%` : '—';
    $('report-data-note').textContent = metrics ? `${fmt(metrics.protected)} / ${fmt(metrics.total_records)} records protected` : 'No records assessed';
    $('report-response').textContent = sim?.has_run ? `${sim.latency_ms} ms` : '—';
    $('report-exposed').textContent = metrics ? fmt(metrics.compromised) : '—';
    $('report-damage').textContent = metrics ? `${metrics.damage_taken} HP` : '—';
    $('report-rounds').textContent = sim?.round || 0;
    $('report-date').textContent = sim?.last_run_at ? new Date(sim.last_run_at).toLocaleString() : 'Not run';
    $('report-summary').textContent = metrics
      ? `The ${metrics.rounds}-round Cloud-D simulation processed ${metrics.total_attacks} attack events across ${(sim.active_vectors || []).length} enabled vectors. Defender agents blocked ${metrics.blocked} events (${metrics.block_rate.toFixed(1)}%). The cloud contains ${fmt(metrics.total_records)} individual records; ${fmt(metrics.compromised)} were compromised (${metrics.protection_rate.toFixed(3)}% protected). Simulated node damage totaled ${metrics.damage_taken}. Uploaded file contents are not included in this report.`
      : 'No simulation has been run yet. Start an exercise to populate this report.';
    $('report-agent-table').innerHTML = vectors.map(vector => {
      const count = counts[vector.id] || { scored: 0, blocked: 0, actions: 0, last: 0 };
      const rate = count.scored ? `${(count.blocked / count.scored * 100).toFixed(1)}%` : '—';
      return `<tr><td><strong>${vector.defender}</strong></td><td>${vector.domain}</td><td>${count.scored}</td><td>${count.actions}</td><td>${rate}</td><td>${count.scored ? Number(count.last).toFixed(2) : '—'}</td></tr>`;
    }).join('');
    const nodes = sim?.nodes || [];
    $('node-table').innerHTML = nodes.length ? nodes.map(node => {
      const statusClass = node.status === 'HEALTHY' ? 'green' : node.status === 'DAMAGED' ? 'amber' : node.status === 'COMPROMISED' ? 'red' : 'amber';
      const observed = (sim.attack_log || []).filter(event => event.target === node.name).length;
      const defended = (sim.attack_log || []).filter(event => event.target === node.name && event.blocked).length;
      return `<tr><td><strong>${node.name}</strong><div class="node-meta">${node.role} · ${node.uploaded_records} uploaded</div></td><td><span class="pill ${statusClass}">${node.status}</span></td><td>${observed}</td><td>${defended}</td><td>${node.compromised_records} records exposed · ${node.health} HP</td></tr>`;
    }).join('') : '<tr><td colspan="5" class="empty">Cloud nodes initialize when you start the local Python app.</td></tr>';
  }

  function renderAll() {
    renderOverview();
    renderAttackCards();
    renderAttackTable();
    renderAgentCards();
    renderReport();
  }

  async function runSimulation({ oneRound = false } = {}) {
    if (running) return;
    const selected = config();
    if (!selected.active_vectors.length) { showToast('Select at least one attack vector.', true); nav('threats'); return; }
    running = true;
    renderOverview();
    try {
      const rounds = oneRound ? 1 : Number($('round-select').value);
      if (!oneRound || !sim || sim.game_over) sim = await request('/api/restart', { method: 'POST', body: JSON.stringify(selected), headers: { 'Content-Type': 'application/json' } });
      for (let index = 0; index < rounds; index++) {
        if (sim.game_over || sim.round >= sim.max_rounds) break;
        sim = await request('/api/round', { method: 'POST', body: JSON.stringify(selected), headers: { 'Content-Type': 'application/json' } });
        renderAll();
        if (!oneRound) await new Promise(resolve => setTimeout(resolve, 110));
      }
      renderAll();
      showToast(`Round ${sim.round} · ${sim.metrics.blocked} of ${sim.metrics.total_attacks} attacks blocked.`);
    } catch (error) {
      showToast(error.message, true);
    } finally {
      running = false;
      renderOverview();
    }
  }

  async function uploadDataset(event) {
    event.preventDefault();
    const files = [...$('upload-file').files];
    if (!files.length) { showToast('Choose at least one document or data file first.', true); return; }
    const totalBytes = files.reduce((total, file) => total + file.size, 0);
    if (totalBytes > 10 * 1024 * 1024) { showToast('Selected files must total 10 MB or less.', true); return; }
    const button = $('upload-button');
    button.disabled = true;
    const selectedNode = $('upload-node').value;
    const selectedMode = $('upload-mode').value;
    $('upload-status').textContent = `Loading ${files.length} file${files.length === 1 ? '' : 's'} into the local cloud…`;
    try {
      const result = await request('/api/upload', { method: 'POST', body: new FormData($('upload-form')) });
      setSimulation(result.state);
      $('upload-status').textContent = `${fmt(result.loaded)} file records loaded into ${result.node}. File contents stay on this device.`;
      $('upload-form').reset();
      $('upload-node').value = selectedNode;
      $('upload-mode').value = selectedMode;
      $('upload-selection').textContent = 'No files selected';
      showToast(`${fmt(result.loaded)} file records added to ${result.node}.`);
    } catch (error) {
      $('upload-status').textContent = error.message;
      showToast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  function exportJson() {
    if (!sim) { showToast('Start the local Python app before exporting.', true); return; }
    const report = {
      project: 'Cloud-D — A Multi-Agent Decision System for Enterprise Cloud Security',
      author: 'Nithish M · 24X064', simulation_only: true,
      generated_at: sim.last_run_at,
      configuration: { round: sim.round, threshold: sim.threshold, intensity: sim.intensity, active_vectors: sim.active_vectors },
      algorithms: { credential_bot: 'Minimax depth 2', query_shield: 'Expectimax with chance nodes', others: 'Rule and utility heuristics' },
      metrics: sim.metrics,
      counts: sim.counts,
      nodes: sim.nodes,
      attack_log: sim.attack_log,
      events: sim.events
    };
    downloadFile('cloud-d-defense-report.json', JSON.stringify(report, null, 2), 'application/json');
  }

  function exportCsv() {
    if (!sim) { showToast('Start the local Python app before exporting.', true); return; }
    const rows = [['round','attacker','attack_type','target_node','utility','defender','action','outcome','damage','record_id','payload']];
    for (const event of sim.attack_log) rows.push([event.round,event.attacker,event.attack_type,event.target,event.utility,event.defender,event.action,event.blocked ? 'blocked' : event.damage ? 'impact' : 'no_damage',event.damage,event.record_id,event.payload]);
    const csv = rows.map(row => row.map(value => `"${String(value ?? '').replaceAll('"','""')}"`).join(',')).join('\n');
    downloadFile('cloud-d-events.csv', csv, 'text/csv');
  }

  function downloadFile(name, content, type) {
    saveBlob(name, new Blob([content], { type }));
  }

  function saveBlob(name, blob) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 500);
    showToast(`${name} downloaded.`);
  }

  async function downloadCloudFile(fileId, filename) {
    const response = await authorizedFetch(`/api/files/${encodeURIComponent(fileId)}/download`);
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || `Download failed (${response.status}).`);
    }
    saveBlob(filename, await response.blob());
  }

  document.querySelectorAll('.nav button').forEach(button => button.addEventListener('click', () => nav(button.dataset.page)));
  $('threshold').addEventListener('input', event => {
    $('threshold-lab').value = event.target.value;
    $('threshold-label').textContent = $('threshold-lab-label').textContent = Number(event.target.value).toFixed(2);
    $('engine-threshold').textContent = Number(event.target.value).toFixed(2);
  });
  $('threshold-lab').addEventListener('input', event => {
    $('threshold').value = event.target.value;
    $('threshold-label').textContent = $('threshold-lab-label').textContent = Number(event.target.value).toFixed(2);
    $('engine-threshold').textContent = Number(event.target.value).toFixed(2);
  });
  $('run-btn').addEventListener('click', () => runSimulation());
  $('step-btn').addEventListener('click', () => runSimulation({ oneRound: true }));
  $('threat-run').addEventListener('click', () => runSimulation());
  $('threat-step').addEventListener('click', () => runSimulation({ oneRound: true }));
  $('agents-run').addEventListener('click', () => { nav('simulation'); runSimulation(); });
  $('simulation-step').addEventListener('click', () => runSimulation({ oneRound: true }));
  $('print-report').addEventListener('click', () => window.print());
  $('download-report').addEventListener('click', exportJson);
  $('download-csv').addEventListener('click', exportCsv);
  $('upload-form').addEventListener('submit', uploadDataset);
  $('cloud-files-body').addEventListener('click', event => {
    const button = event.target.closest('[data-download-file]');
    if (!button) return;
    downloadCloudFile(button.dataset.downloadFile, button.dataset.filename).catch(error => showToast(error.message, true));
  });
  $('upload-file').addEventListener('change', () => {
    const files = [...$('upload-file').files];
    $('upload-selection').textContent = files.length
      ? `${files.length} selected · ${files.map(file => file.name).join(', ')}`
      : 'No files selected';
  });
  $('node-cards').addEventListener('click', event => {
    const button = event.target.closest('[data-upload-node]');
    if (!button) return;
    $('upload-node').value = button.dataset.uploadNode;
    $('upload-panel').scrollIntoView({ behavior: 'smooth', block: 'center' });
    $('upload-file').click();
  });
  const dropArea = $('upload-drop');
  dropArea.addEventListener('dragover', event => { event.preventDefault(); dropArea.classList.add('drag-over'); });
  dropArea.addEventListener('dragleave', () => dropArea.classList.remove('drag-over'));
  dropArea.addEventListener('drop', event => {
    event.preventDefault();
    dropArea.classList.remove('drag-over');
    $('upload-file').files = event.dataTransfer.files;
    $('upload-file').dispatchEvent(new Event('change', { bubbles: true }));
  });
  $('round-select').addEventListener('change', event => {
    $('run-btn').textContent = Number(event.target.value) === 20 ? 'Run 20-round simulation' : `Run ${event.target.value}-round simulation`;
  });

  request('/api/state').then(setSimulation).then(() => {
    $('upload-status').textContent = 'Python simulation connected · data stays on this device.';
  }).catch(error => {
    renderAll();
    $('upload-status').textContent = error.message;
  });
})();
