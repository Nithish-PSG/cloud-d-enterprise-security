(() => {
  'use strict';

  // A browser cannot launch the Python process from file://. The installed
  // macOS login service starts it in the background; send file-opened users to
  // the same-origin dashboard served by that local service.
  if (location.protocol === 'file:') {
    location.replace('http://127.0.0.1:8765/');
    return;
  }

  const $ = id => document.getElementById(id);
  const fmt = value => new Intl.NumberFormat('en-US').format(value || 0);
  const isHostedDeployment = Boolean(location.hostname) && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  const vectors = [
    { id: 'auth', attacker: 'Credential-Bot', defender: 'AuthSentinel', domain: 'Credential attacks', icon: '⌑', target: 'Auth Server', color: 'var(--cyan)' },
    { id: 'flow', attacker: 'FloodSwarm', defender: 'FlowGuardian', domain: 'DDoS / traffic floods', icon: '≋', target: 'API Gateway', color: 'var(--blue)' },
    { id: 'query', attacker: 'Injector-X', defender: 'QueryShield', domain: 'SQL injection', icon: '⌘', target: 'Primary DB', color: 'var(--purple)' },
    { id: 'behavior', attacker: 'GhostUser', defender: 'BehaviorWatch', domain: 'Insider / anomalous behavior', icon: '◌', target: 'Customer DB', color: 'var(--amber)' }
  ];
  let sim = null;
  let running = false;
  let uploading = false;
  let cloudFileCache = [];
  let cloudActivity = [];
  let lastCloudFileIds = new Set();
  let progressHideTimer = null;
  let currentUser = null;
  let authMode = 'login';
  let accountType = 'customer';

  function updateDeploymentCopy() {
    const hosted = isHostedDeployment;
    $('storage-mode-pill').textContent = hosted ? 'HOSTED · PERSISTENT DISK' : 'LOCAL · PERSISTENT';
    $('cloud-storage-note').textContent = hosted
      ? 'AES-256-GCM file copies · Render persistent disk'
      : 'Automatic SQLite recovery copy';
    $('upload-storage-note').textContent = hosted
      ? 'Uploads are encrypted with AES-256-GCM before SQLite writes them. The hosted service uses a Render persistent disk so data survives instance restarts.'
      : 'File contents are encrypted before SQLite writes them and stay on this device across app restarts. Back up both databases and the encryption key together.';
    $('stored-files-description').textContent = 'Folders and files are scoped to your account. Each saved revision is mirrored to the encrypted recovery database.';
    $('storage-footer-note').textContent = hosted
      ? 'Simulation only · file contents use AES-256-GCM and are stored on a Render persistent disk (/var/cloud-d-data).'
      : 'Simulation only · file contents use AES-256-GCM and persist in local SQLite databases.';
  }
  updateDeploymentCopy();

  async function authorizedFetch(path, { method = 'GET', body, headers } = {}) {
    try {
      const requestHeaders = new Headers(headers || {});
      return await fetch(path, { method, body, headers: requestHeaders, credentials: 'same-origin' });
    } catch (_error) {
      const message = isHostedDeployment
          ? 'Could not reach the hosted simulation. It may be starting or waking; retry in a moment.'
          : 'Could not reach the local simulation. The Cloud-D background service may still be starting; try again in a moment.';
      $('upload-status').textContent = message;
      throw new Error(message);
    }
  }

  async function request(path, options = {}) {
    const response = await authorizedFetch(path, options);
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401 && currentUser) {
      showAuthScreen('Your session expired. Please sign in again.');
    }
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status}).`);
    return payload;
  }

  function showAuthScreen(message = '') {
    currentUser = null;
    sim = null;
    lastCloudFileIds = new Set();
    cloudFileCache = [];
    cloudActivity = [];
    $('app-shell').hidden = true;
    $('auth-screen').hidden = false;
    setAuthMode('login', false);
    $('auth-message').textContent = message;
    $('auth-message').classList.toggle('error', Boolean(message));
    $('auth-message').classList.remove('error');
    $('auth-password').value = '';
  }

  async function enterWorkspace(user) {
    currentUser = user;
    $('auth-screen').hidden = true;
    $('app-shell').hidden = false;
    $('current-user-name').textContent = user.username;
    $('current-user-role').textContent = user.role === 'staff' ? 'Staff operator' : 'Customer';
    $('current-user-avatar').textContent = user.username.slice(0, 2).toUpperCase();
    document.querySelectorAll('.page').forEach(item => item.classList.toggle('active', item.id === 'page-cloud'));
    document.querySelectorAll('.nav button').forEach(item => item.classList.toggle('active', item.dataset.page === 'cloud'));
    $('crumb-current').textContent = 'Cloud';
    document.querySelectorAll('.staff-only').forEach(item => { item.hidden = user.role !== 'staff'; });
    $('cloud-nodes-online').textContent = user.role === 'staff' ? 'Primary DB' : 'Customer DB';
    $('cloud-status-pill').textContent = user.role === 'staff' ? 'STAFF AREA' : 'CUSTOMER AREA';
    $('cloud-area-eyebrow').textContent = user.role === 'staff' ? 'Staff workspace · Primary DB' : 'Customer workspace · Customer DB';
    $('cloud-area-description').textContent = user.role === 'staff'
      ? 'Manage files in shared staff folders. Cloud-D routes them to the Primary DB and keeps encrypted recovery copies.'
      : 'Your files stay in your private Customer DB folders. Cloud-D assigns this storage area automatically.';
    try {
      await refreshFolders();
      setSimulation(await request('/api/state'));
      setCloudConnection('connected');
      $('upload-status').textContent = 'Signed in · files are encrypted and backed up automatically.';
    } catch (error) {
      $('upload-status').textContent = error.message;
      setCloudConnection('offline');
    }
  }

  let lastSelectedFolder = '';

  async function refreshFolders(selectedId = '') {
    const result = await request('/api/folders');
    const folders = result.folders || [];
    const uploadSelect = $('upload-folder');
    const filterSelect = $('cloud-folder-filter');
    const previousUpload = selectedId || uploadSelect.value;
    const previousFilter = filterSelect.value;

    const isCustomer = currentUser && currentUser.role === 'customer';
    const folderBtn = $('create-folder-button');
    if (folderBtn) {
      folderBtn.hidden = isCustomer;
      folderBtn.style.display = isCustomer ? 'none' : '';
    }

    let uploadOptions = folders.map(folder => `<option value="${escapeHtml(folder.id)}">${escapeHtml(folder.name)}</option>`).join('');
    uploadOptions += '<option value="__new_folder__">＋ New folder…</option>';

    uploadSelect.innerHTML = uploadOptions;
    filterSelect.innerHTML = '<option value="all">All folders</option>' + folders.map(folder => `<option value="${escapeHtml(folder.id)}">${escapeHtml(folder.name)}</option>`).join('');

    if (folders.some(folder => folder.id === previousUpload)) {
      uploadSelect.value = previousUpload;
      lastSelectedFolder = previousUpload;
    } else if (folders.length > 0) {
      uploadSelect.value = folders[0].id;
      lastSelectedFolder = folders[0].id;
    }
    if (folders.some(folder => folder.id === previousFilter)) filterSelect.value = previousFilter;
    renderFilteredCloudFiles();
  }

  async function submitAuth(event) {
    event.preventDefault();
    const message = $('auth-message');
    message.textContent = 'Verifying account…';
    message.classList.remove('error');
    const payload = {
      username: $('auth-username').value.trim(),
      password: $('auth-password').value
    };
    const path = authMode === 'login' ? '/api/auth/login' : '/api/auth/signup';
    if (authMode === 'signup') {
      payload.role = accountType;
      payload.email = $('auth-email').value.trim();
      payload.staff_registration_code = $('staff-registration-code').value.trim();
    }
    try {
      const response = await authorizedFetch(path, {
        method: 'POST', body: JSON.stringify(payload), headers: { 'Content-Type': 'application/json' }
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || 'Account verification failed.');
      $('auth-form').reset();
      setPasswordVisibility(false);
      await enterWorkspace(result.user);
    } catch (error) {
      message.textContent = error.message;
      message.classList.add('error');
    }
  }

  function setPasswordVisibility(visible) {
    const password = $('auth-password');
    const toggle = $('password-toggle');
    password.type = visible ? 'text' : 'password';
    toggle.checked = visible;
  }

  function setAuthMode(mode, clearMessage = true) {
    authMode = mode;
    const signup = mode === 'signup';
    setPasswordVisibility(false);
    $('auth-title').textContent = signup ? 'Create your Cloud-D account' : 'Sign in to your cloud';
    $('auth-copy').textContent = signup
      ? 'Enter your email address and choose a username. Choose Customer or Staff to set your cloud access.'
      : 'Sign in using your username and password. Cloud-D finds your account type automatically.';
    $('auth-email-field').hidden = !signup;
    $('auth-email').required = signup;
    $('auth-username').required = true;
    $('auth-username-help').hidden = false;
    $('auth-username-help').textContent = signup
      ? 'Use 3–30 letters, numbers, dots, underscores, or hyphens. Usernames must start with a letter or number.'
      : 'For older accounts, the username is based on the part of your email before @. Your username appears beside your role after sign-in.';
    $('auth-role-switch').hidden = !signup;
    $('auth-password').autocomplete = signup ? 'new-password' : 'current-password';
    $('auth-submit').textContent = signup ? 'Create account' : 'Sign in';
    $('staff-code-field').hidden = !signup || accountType !== 'staff';
    $('staff-registration-code').required = signup && accountType === 'staff';
    $('auth-mode-link').textContent = signup ? 'Sign in' : 'Create an account';
    $('auth-mode-link').href = signup ? '#login' : '#signup';
    $('auth-link-row').firstChild.textContent = signup ? 'Already have an account?' : 'New to Cloud-D?';
    if (clearMessage) {
      $('auth-message').textContent = '';
      $('auth-message').classList.remove('error');
    }
  }

  async function signOut() {
    try { await authorizedFetch('/api/auth/logout', { method: 'POST' }); } catch (_error) { /* clear the local view even offline */ }
    lastCloudFileIds = new Set();
    cloudFileCache = [];
    cloudActivity = [];
    showAuthScreen('You have signed out.');
  }

  async function createFolder(event) {
    event.preventDefault();
    const button = $('folder-form').querySelector('[type="submit"]');
    button.disabled = true;
    try {
      const result = await request('/api/folders', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: $('folder-name-input').value })
      });
      $('folder-dialog').close();
      $('folder-form').reset();
      await refreshFolders(result.folder.id);
      showToast(`Folder “${result.folder.name}” created.`);
    } catch (error) {
      showToast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  function config() {
    return {
      threshold: Number($('threshold').value),
      intensity: $('intensity-select').value,
      active_vectors: [...document.querySelectorAll('.vector-toggle:checked')].map(input => input.value)
    };
  }

  function setSimulation(value) {
    const previousIds = lastCloudFileIds;
    const currentFiles = value.files || [];
    const newFiles = currentFiles.filter(file => !previousIds.has(file.id));
    const firstConnection = sim === null;
    sim = value;
    lastCloudFileIds = new Set(currentFiles.map(file => file.id));
    if (firstConnection) {
      addCloudActivity('Cloud workspace connected', `${fmt(currentFiles.length)} current files · ${fmt(value.storage?.backup_file_count || 0)} encrypted backup copies`, 'success');
    } else if (newFiles.length) {
      const versioned = newFiles.filter(file => Number(file.version) > 1);
      if (versioned.length === 1 && newFiles.length === 1) {
        addCloudActivity('New file version saved', `${versioned[0].filename} · version ${versioned[0].version}`, 'upload');
      } else {
        const locations = [...new Set(newFiles.map(file => file.folder_name).filter(Boolean))].join(', ');
        addCloudActivity(`${newFiles.length} file${newFiles.length === 1 ? '' : 's'} synced`, locations ? `Added or updated in ${locations}` : 'Added or updated in your assigned storage area', 'upload');
      }
    }
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

  function addCloudActivity(title, detail, style = 'success') {
    cloudActivity.unshift({ title, detail, style, time: new Date() });
    cloudActivity = cloudActivity.slice(0, 8);
    renderCloudActivity();
  }

  function renderCloudActivity() {
    $('cloud-activity-list').innerHTML = cloudActivity.length ? cloudActivity.map(item => {
      const icon = item.style === 'upload' ? '⇧' : item.style === 'download' ? '⇩' : item.style === 'secure' ? '✓' : '◉';
      const when = item.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      return `<div class="activity-row"><span class="activity-icon ${item.style}">${icon}</span><div class="activity-copy"><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.detail)}</span></div><time class="activity-time">${when}</time></div>`;
    }).join('') : '<div class="empty">Cloud activity will appear here.</div>';
  }

  function setCloudConnection(state) {
    const badge = $('cloud-connection-badge');
    badge.className = `cloud-live ${state === 'connected' ? '' : state}`;
    $('cloud-connection-label').textContent = state === 'connected' ? 'CONNECTED' : state === 'syncing' ? 'SYNCING' : 'OFFLINE';
    if (state === 'connected') {
      $('cloud-last-sync').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
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
    if (page !== 'cloud' && currentUser?.role !== 'staff') return;
    document.querySelectorAll('.page').forEach(item => item.classList.toggle('active', item.id === `page-${page}`));
    document.querySelectorAll('.nav button').forEach(button => button.classList.toggle('active', button.dataset.page === page));
    $('crumb-current').textContent = ({ cloud: 'Cloud', overview: 'Security Overview', simulation: 'Simulation', threats: 'Attack Simulation', report: 'Defense Report' })[page] || 'Cloud';
    window.scrollTo(0, 0);
    if (page === 'cloud') syncCloudWorkspace();
  }

  async function syncCloudWorkspace() {
    if (!currentUser || document.visibilityState !== 'visible' || running || uploading) return;
    setCloudConnection('syncing');
    try {
      setSimulation(await request('/api/state'));
      await refreshFolders();
      setCloudConnection('connected');
    } catch (_error) {
      setCloudConnection('offline');
    }
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
    renderStorage();
    renderCloudFiles(sim?.files || []);
    $('cloud-nodes-online').textContent = currentUser?.role === 'staff' ? 'Primary DB' : currentUser ? 'Customer DB' : '—';
    $('cloud-status-pill').textContent = currentUser?.role === 'staff' ? 'STAFF AREA' : currentUser ? 'CUSTOMER AREA' : 'YOUR AREA';
    $('cloud-record-count').textContent = fmt((sim?.files || []).reduce((total, file) => total + Number(file.record_count || 0), 0));
    $('cloud-storage-size').textContent = fmt(sim?.storage?.backup_file_count || 0);
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return `${(bytes / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
  }

  function renderStorage() {
    const storage = sim?.storage || {};
    const persistent = storage.persistent === undefined ? !isHostedDeployment : Boolean(storage.persistent);
    $('database-engine').textContent = storage.engine || 'SQLite';
    $('database-encryption').textContent = storage.encryption || 'AES-256-GCM';
    $('database-files').textContent = fmt(storage.backup_file_count || 0);
    $('database-size').textContent = storage.backup_ready ? 'Ready' : 'Unavailable';
    $('database-heading').textContent = persistent ? 'Primary and recovery storage are ready' : 'Hosted primary and recovery storage are temporary';
    $('database-note').textContent = storage.storage_note || (isHostedDeployment
      ? 'The hosted service uses temporary storage. Encrypted file contents may be lost when the instance is replaced.'
      : 'Encrypted file contents and the separate SQLite recovery copy stay in this device’s Cloud-D data folder. Account and folder metadata are not encrypted as a whole database.');
    $('database-status-pill').textContent = persistent ? 'FILE COPIES READY' : 'TEMPORARY HOSTED';
    $('database-status-pill').className = `pill ${persistent && storage.backup_ready ? 'green' : 'amber'}`;
  }

  function renderCloudFiles(files) {
    cloudFileCache = files || [];
    const storageBytes = cloudFileCache.reduce((total, file) => total + Number(file.size_bytes || 0), 0);
    $('cloud-file-count').textContent = fmt(cloudFileCache.length);
    $('cloud-storage-size').textContent = formatBytes(storageBytes);
    renderFilteredCloudFiles();
  }

  function renderFilteredCloudFiles() {
    const query = ($('cloud-file-search').value || '').trim().toLowerCase();
    const selectedFolder = $('cloud-folder-filter').value;
    const selectedType = $('cloud-type-filter').value;
    const files = cloudFileCache.filter(file => {
      const matchesText = !query || `${file.filename} ${file.folder_name}`.toLowerCase().includes(query);
      const matchesFolder = selectedFolder === 'all' || file.folder_id === selectedFolder;
      const matchesType = selectedType === 'all' || (selectedType === 'data' ? file.kind === 'data' : file.kind !== 'data');
      return matchesText && matchesFolder && matchesType;
    });
    $('stored-files-pill').textContent = files.length === cloudFileCache.length
      ? `${files.length} FILE${files.length === 1 ? '' : 'S'}`
      : `${files.length} OF ${cloudFileCache.length} FILES`;
    $('cloud-files-body').innerHTML = files.length ? files.map(file => {
      const name = escapeHtml(file.filename);
      const kind = file.kind === 'data' ? 'Structured data' : 'Document';
      const icon = file.kind === 'data' ? '▦' : '▤';
      const version = Number(file.version || 1);
      const versions = Number(file.version_count || 1);
      const savedAt = file.created_at ? new Date(file.created_at).toLocaleString() : 'Saved';
      const backupStatus = file.backup_available ? '<span class="pill green">BACKED UP</span>' : '<span class="pill amber">NO COPY</span>';
      const restoreButton = !file.primary_available ? `<button class="btn primary" type="button" data-restore-file="${escapeHtml(file.id)}">Restore</button>` : '';
      return `<tr><td><div class="file-entry"><span class="file-icon ${file.kind === 'data' ? 'structured' : ''}">${icon}</span><span class="file-entry-text"><strong>${name}</strong><small>Version ${version} · ${escapeHtml(savedAt)}</small></span></div></td><td>${escapeHtml(file.folder_name)}</td><td>${formatBytes(Number(file.size_bytes || 0))}</td><td>${kind}</td><td>${fmt(file.record_count)}</td><td>${backupStatus}</td><td><div class="file-actions">${restoreButton}<button class="btn" type="button" data-download-file="${escapeHtml(file.id)}" data-filename="${name}">Download</button><button class="btn" type="button" data-view-versions="${escapeHtml(file.logical_id)}" data-filename="${name}">Versions · ${versions}</button></div></td></tr>`;
    }).join('') : `<tr><td colspan="7" class="empty">${cloudFileCache.length ? 'No matching files. Change the search or filters.' : 'Your cloud is ready. Upload a file to see it here.'}</td></tr>`;
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
    }).join('') : '<tr><td colspan="5" class="empty">Cloud nodes initialize when the Python simulation starts.</td></tr>';
  }

  function renderAll() {
    renderOverview();
    renderAttackCards();
    renderAttackTable();
    renderAgentCards();
    renderReport();
  }

  async function runSimulation({ oneRound = false } = {}) {
    if (currentUser?.role !== 'staff') { showToast('Security simulations are available to staff accounts.', true); return; }
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
    const selectedFolder = $('upload-folder').value;
    if (!selectedFolder || selectedFolder === '__new_folder__') {
      showToast('Please select or create a destination folder first.', true);
      return;
    }
    const button = $('upload-button');
    button.disabled = true;
    uploading = true;
    $('upload-progress-panel').classList.add('active');
    clearTimeout(progressHideTimer);
    button.textContent = 'Uploading…';
    $('upload-status').textContent = `Connecting ${files.length} file${files.length === 1 ? '' : 's'} to ${$('upload-folder').selectedOptions[0]?.textContent || 'your folder'}…`;
    updateUploadProgress(0, 'Preparing encrypted upload…');
    try {
      const formData = new FormData($('upload-form'));
      const progress = percent => {
        const stage = percent >= 100 ? 'Transfer complete · encrypting and saving in SQLite…' : `Transferring ${formatBytes(totalBytes * percent / 100)}`;
        updateUploadProgress(percent, stage);
        $('upload-status').textContent = stage;
      };
      let result;
      try {
        result = await uploadWithProgress(formData, progress);
      } catch (error) {
        if (error.status !== 409 || !error.payload?.duplicates?.length) throw error;
        const duplicateMode = await chooseDuplicateMode(error.payload.duplicates);
        if (!duplicateMode) throw new Error('Upload cancelled. No files were changed.');
        formData.set('duplicate_mode', duplicateMode);
        $('upload-status').textContent = duplicateMode === 'replace'
          ? 'Replacing the matching file and its previous versions…'
          : 'Updating the matching file as a new version…';
        result = await uploadWithProgress(formData, progress);
      }
      updateUploadProgress(100, 'Encrypted and saved to the cloud node.');
      setSimulation(result.state);
      const updateSummary = (result.file_updates || []).map(file => `${file.filename} · v${file.version}`).join(', ');
      $('upload-status').textContent = `${fmt(result.loaded)} records saved to ${result.folder}${updateSummary ? ` · ${updateSummary}` : ''}. Encrypted backup created.`;
      $('upload-form').reset();
      $('upload-folder').value = selectedFolder;
      $('upload-selection').textContent = 'No files selected';
      showToast(`${fmt(result.loaded)} records saved to ${result.folder}.`);
    } catch (error) {
      if (error.status === 401) showAuthScreen('Your session expired. Please sign in again.');
      $('upload-status').textContent = error.message;
      updateUploadProgress(0, `Upload failed · ${error.message}`);
      showToast(error.message, true);
    } finally {
      uploading = false;
      button.disabled = false;
      button.textContent = 'Upload encrypted';
      progressHideTimer = setTimeout(() => $('upload-progress-panel').classList.remove('active'), 2800);
    }
  }

  function updateUploadProgress(percent, stage) {
    const clamped = Math.max(0, Math.min(100, percent));
    $('upload-progress-fill').style.width = `${clamped}%`;
    $('upload-progress-percent').textContent = `${Math.round(clamped)}%`;
    $('upload-progress-stage').textContent = stage;
  }

  function uploadWithProgress(formData, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/upload');
      xhr.timeout = 120000;
      xhr.withCredentials = true;
      xhr.upload.addEventListener('progress', event => {
        if (event.lengthComputable) onProgress(Math.round(event.loaded / event.total * 100));
      });
      xhr.addEventListener('load', () => {
        let payload = {};
        try { payload = JSON.parse(xhr.responseText || '{}'); } catch (_error) { /* report status below */ }
        if (xhr.status < 200 || xhr.status >= 300) {
          const error = new Error(payload.error || `Upload failed (${xhr.status}).`);
          error.status = xhr.status;
          error.payload = payload;
          reject(error);
          return;
        }
        resolve(payload);
      });
      xhr.addEventListener('error', () => reject(new Error('The cloud connection ended during upload. Check the connection and retry.')));
      xhr.addEventListener('timeout', () => reject(new Error('Upload timed out. Try a smaller batch of files.')));
      xhr.addEventListener('abort', () => reject(new Error('Upload was cancelled.')));
      xhr.send(formData);
    });
  }

  function chooseDuplicateMode(duplicates) {
    const dialog = $('duplicate-dialog');
    $('duplicate-file-list').innerHTML = duplicates.map(item =>
      `<li><strong>${escapeHtml(item.filename)}</strong><span>Current version ${Number(item.version) || 1} · ${Number(item.version_count) || 1} saved</span></li>`
    ).join('');
    return new Promise(resolve => {
      dialog.returnValue = '';
      const onClose = () => resolve(dialog.returnValue === 'new_version' || dialog.returnValue === 'replace' ? dialog.returnValue : null);
      dialog.addEventListener('close', onClose, { once: true });
      dialog.showModal();
    });
  }

  async function openVersionHistory(logicalId, filename) {
    const dialog = $('version-dialog');
    $('version-dialog-title').textContent = `Version history · ${filename}`;
    $('version-list').innerHTML = '<div class="empty">Loading versions…</div>';
    dialog.showModal();
    try {
      const result = await request(`/api/file-groups/${encodeURIComponent(logicalId)}/versions`);
      $('version-list').innerHTML = result.versions.map(version => {
        const savedAt = new Date(version.created_at).toLocaleString();
        const status = version.current ? '<span class="pill green">CURRENT</span>' : '<span class="pill blue">HISTORY</span>';
        return `<div class="version-row"><div class="version-main"><div><strong>Version ${Number(version.version)}</strong> ${status}</div><small>${escapeHtml(savedAt)} · ${formatBytes(Number(version.size_bytes || 0))} · ${fmt(version.record_count)} record${Number(version.record_count) === 1 ? '' : 's'}</small></div><button class="btn" type="button" data-download-file="${escapeHtml(version.id)}" data-filename="${escapeHtml(filename)}">Download</button></div>`;
      }).join('') || '<div class="empty">No saved versions were found.</div>';
    } catch (error) {
      $('version-list').innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }

  function handleCloudFileAction(event) {
    const restoreButton = event.target.closest('[data-restore-file]');
    if (restoreButton) {
      restoreBackedUpFile(restoreButton.dataset.restoreFile, restoreButton);
      return;
    }
    const versionButton = event.target.closest('[data-view-versions]');
    if (versionButton) {
      openVersionHistory(versionButton.dataset.viewVersions, versionButton.dataset.filename);
      return;
    }
    const downloadButton = event.target.closest('[data-download-file]');
    if (downloadButton) {
      downloadCloudFile(downloadButton.dataset.downloadFile, downloadButton.dataset.filename)
        .catch(error => showToast(error.message, true));
    }
  }

  async function restoreBackedUpFile(fileId, button) {
    button.disabled = true;
    const oldText = button.textContent;
    button.textContent = 'Restoring…';
    try {
      const result = await request(`/api/files/${encodeURIComponent(fileId)}/restore`, { method: 'POST' });
      setSimulation(result.state);
      showToast(`${result.filename} restored from the encrypted backup.`);
      addCloudActivity('File restored from backup', result.filename, 'secure');
    } catch (error) {
      showToast(error.message, true);
    } finally {
      button.disabled = false;
      button.textContent = oldText;
    }
  }

  function exportJson() {
    if (!sim) { showToast('Connect to the Python simulation before exporting.', true); return; }
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
    if (!sim) { showToast('Connect to the Python simulation before exporting.', true); return; }
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
    if (response.status === 401) showAuthScreen('Your session expired. Please sign in again.');
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || `Download failed (${response.status}).`);
    }
    saveBlob(filename, await response.blob());
    addCloudActivity('File decrypted and downloaded', filename, 'download');
  }

  async function runNodeCryptoAction(nodeId, action, button) {
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = action === 'verify' ? 'Checking…' : 'Updating…';
    try {
      const result = await request('/api/node-crypto', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ node_id: Number(nodeId), action })
      });
      if (action === 'verify') {
        showToast(`${result.node}: ${fmt(result.verified)} encrypted file${result.verified === 1 ? '' : 's'} decrypted and verified. Plaintext stayed on the server.`);
        addCloudActivity('Decryption verified', `${result.node} · ${fmt(result.verified)} encrypted files authenticated`, 'secure');
      } else {
        showToast(`${result.node}: re-encrypted ${fmt(result.reencrypted)} file${result.reencrypted === 1 ? '' : 's'}.`);
        addCloudActivity('Node data re-encrypted', `${result.node} · ${fmt(result.reencrypted)} encrypted files updated`, 'secure');
      }
    } catch (error) {
      showToast(error.message, true);
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
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
  $('cloud-upload-shortcut').addEventListener('click', () => {
    $('upload-panel').scrollIntoView({ behavior: 'smooth', block: 'center' });
    setTimeout(() => $('upload-file').click(), 220);
  });
  $('cloud-file-search').addEventListener('input', renderFilteredCloudFiles);
  $('cloud-folder-filter').addEventListener('change', renderFilteredCloudFiles);
  $('cloud-type-filter').addEventListener('change', renderFilteredCloudFiles);
  $('cloud-files-body').addEventListener('click', handleCloudFileAction);
  $('version-list').addEventListener('click', handleCloudFileAction);
  $('close-version-dialog').addEventListener('click', () => $('version-dialog').close());
  $('upload-file').addEventListener('change', () => {
    const files = [...$('upload-file').files];
    $('upload-selection').textContent = files.length
      ? `${files.length} selected · ${files.map(file => file.name).join(', ')}`
      : 'No files selected';
    if (files.length) $('upload-progress-panel').classList.remove('active');
  });
  $('auth-form').addEventListener('submit', submitAuth);
  $('password-toggle').addEventListener('change', event => {
    setPasswordVisibility(event.target.checked);
  });
  $('auth-mode-link').addEventListener('click', event => {
    event.preventDefault();
    setAuthMode(authMode === 'login' ? 'signup' : 'login');
  });
  $('auth-role-switch').addEventListener('click', event => {
    const button = event.target.closest('[data-auth-role]');
    if (!button) return;
    accountType = button.dataset.authRole;
    $('auth-screen').querySelectorAll('[data-auth-role]').forEach(item => item.classList.toggle('active', item === button));
    $('staff-code-field').hidden = authMode !== 'signup' || accountType !== 'staff';
    $('staff-registration-code').required = authMode === 'signup' && accountType === 'staff';
    $('auth-message').textContent = '';
    $('auth-message').classList.remove('error');
  });
  $('verify-encryption-button').addEventListener('click', event => runNodeCryptoAction(2, 'verify', event.currentTarget));
  $('reencrypt-button').addEventListener('click', event => runNodeCryptoAction(2, 'reencrypt', event.currentTarget));
  $('logout-button').addEventListener('click', signOut);
  $('create-folder-button').addEventListener('click', () => {
    $('folder-dialog').showModal();
    $('folder-name-input').focus();
  });
  $('upload-folder').addEventListener('change', event => {
    if (event.target.value === '__new_folder__') {
      $('folder-dialog').showModal();
      $('folder-name-input').focus();
    } else {
      lastSelectedFolder = event.target.value;
    }
  });
  $('folder-dialog').addEventListener('close', () => {
    if ($('upload-folder').value === '__new_folder__') {
      $('upload-folder').value = lastSelectedFolder;
    }
  });
  $('folder-form').addEventListener('submit', createFolder);
  $('close-folder-dialog').addEventListener('click', () => $('folder-dialog').close());
  $('cancel-folder-dialog').addEventListener('click', () => $('folder-dialog').close());
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

  async function bootstrapSession() {
    try {
      const response = await authorizedFetch('/api/auth/me');
      const result = await response.json().catch(() => ({}));
      if (result.user) await enterWorkspace(result.user);
      else showAuthScreen();
    } catch (_error) {
      showAuthScreen('Start the Cloud-D Python service, then refresh this page.');
    }
  }
  bootstrapSession();
  setInterval(syncCloudWorkspace, 4000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') syncCloudWorkspace();
  });
})();
