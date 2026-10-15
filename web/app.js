document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const btnBuildCircuit = document.getElementById('btn-build-circuit');
  const btnBuildText = document.getElementById('btn-build-circuit-text');
  const btnSendMessage = document.getElementById('btn-send-message');
  const btnRefreshConsensus = document.getElementById('btn-refresh-consensus');
  const btnClearLogs = document.getElementById('btn-clear-logs');
  
  const inputMessage = document.getElementById('input-message');
  const inputDest = document.getElementById('input-dest');

  const circuitStatusText = document.getElementById('circuit-status-text');
  const circuitDot = document.getElementById('circuit-dot');
  const backendStatusText = document.getElementById('backend-status-text');

  const valK1 = document.getElementById('val-k1');
  const valK2 = document.getElementById('val-k2');
  const valK3 = document.getElementById('val-k3');
  const keysStatus = document.getElementById('keys-status');

  const labelGuardName = document.getElementById('label-guard-name');
  const labelGuardAddr = document.getElementById('label-guard-addr');
  const labelMiddleName = document.getElementById('label-middle-name');
  const labelMiddleAddr = document.getElementById('label-middle-addr');
  const labelExitName = document.getElementById('label-exit-name');
  const labelExitAddr = document.getElementById('label-exit-addr');

  const nodeGuard = document.querySelector('.guard-box');
  const nodeMiddle = document.querySelector('.middle-box');
  const nodeExit = document.querySelector('.exit-box');

  const cardLayer1 = document.getElementById('card-layer-1');
  const cardLayer2 = document.getElementById('card-layer-2');
  const cardLayer3 = document.getElementById('card-layer-3');
  const sizeL1 = document.getElementById('size-l1');
  const sizeL2 = document.getElementById('size-l2');
  const sizeL3 = document.getElementById('size-l3');
  const hexL1 = document.getElementById('hex-l1');
  const hexL2 = document.getElementById('hex-l2');
  const hexL3 = document.getElementById('hex-l3');

  const respContentText = document.getElementById('resp-content-text');
  const respLatencyBadge = document.getElementById('resp-latency-badge');

  const terminalLogs = document.getElementById('terminal-logs');
  const activeRelaysList = document.getElementById('active-relays-list');
  const relaysCountBadge = document.getElementById('relays-count-badge');

  let activeFilter = 'ALL';
  let isCircuitActive = false;

  // ----------------------------------------------------
  // 1. Live SSE Log Streamer
  // ----------------------------------------------------
  function initSSE() {
    const eventSource = new EventSource('/api/events');

    eventSource.onopen = () => {
      backendStatusText.textContent = 'Backend: Online';
    };

    eventSource.onmessage = (e) => {
      try {
        const item = JSON.parse(e.data);
        appendLogEntry(item);
      } catch (err) {
        console.error('SSE JSON error', err);
      }
    };

    eventSource.onerror = () => {
      backendStatusText.textContent = 'Backend: Reconnecting...';
    };
  }

  function appendLogEntry(item) {
    const div = document.createElement('div');
    const levelLower = (item.level || 'info').toLowerCase();
    div.className = `log-entry log-${levelLower}`;
    div.dataset.level = (item.level || 'INFO').toUpperCase();

    div.innerHTML = `
      <span class="log-time">[${item.timestamp || ''}]</span>
      <span class="log-comp">[${item.component || ''}]</span>
      <span class="log-msg">${escapeHtml(item.message || '')}</span>
    `;

    if (activeFilter !== 'ALL' && div.dataset.level !== activeFilter) {
      div.style.display = 'none';
    }

    terminalLogs.appendChild(div);
    terminalLogs.scrollTop = terminalLogs.scrollHeight;
  }

  function escapeHtml(text) {
    return text.replace(/[&<>"']/g, (m) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
    }[m]));
  }

  // Filter Bar
  document.querySelectorAll('.filter-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeFilter = btn.dataset.filter;

      document.querySelectorAll('.log-entry').forEach(entry => {
        if (activeFilter === 'ALL' || entry.dataset.level === activeFilter) {
          entry.style.display = 'flex';
        } else {
          entry.style.display = 'none';
        }
      });
    });
  });

  btnClearLogs.addEventListener('click', () => {
    terminalLogs.innerHTML = '';
  });

  // ----------------------------------------------------
  // 2. Fetch Directory Consensus
  // ----------------------------------------------------
  async function fetchConsensus() {
    try {
      const res = await fetch('/api/consensus');
      if (!res.ok) throw new Error('Consensus fetch failed');
      const data = await res.json();
      renderRelays(data.relays || []);
    } catch (err) {
      activeRelaysList.innerHTML = `<div class="empty-state" style="color: var(--accent-red);">Directory Authority unreachable at 127.0.0.1:8000. Start dir_authority server.</div>`;
    }
  }

  function renderRelays(relays) {
    relaysCountBadge.textContent = `${relays.length} Active`;
    if (relays.length === 0) {
      activeRelaysList.innerHTML = `<div class="empty-state">No relays currently registered in consensus.</div>`;
      return;
    }

    activeRelaysList.innerHTML = '';
    relays.forEach(r => {
      const item = document.createElement('div');
      item.className = 'relay-item';
      item.innerHTML = `
        <div class="relay-item-left">
          <span class="relay-role-badge ${r.role}">${r.role}</span>
          <div>
            <div class="relay-name-text">${escapeHtml(r.name)}</div>
            <div class="relay-addr-text">${r.ip}:${r.port}</div>
          </div>
        </div>
        <div class="relay-item-right">
          <span class="pubkey-snippet" title="${r.pubkey}">🔑 ${r.pubkey.substring(0, 12)}...</span>
        </div>
      `;
      activeRelaysList.appendChild(item);
    });
  }

  btnRefreshConsensus.addEventListener('click', fetchConsensus);

  // ----------------------------------------------------
  // 3. Build Circuit Action
  // ----------------------------------------------------
  btnBuildCircuit.addEventListener('click', async () => {
    btnBuildCircuit.disabled = true;
    btnBuildText.textContent = 'Negotiating Telescopic Handshake...';

    // Animate connector dots
    animateHop('dot-hop1');

    try {
      const res = await fetch('/api/circuit/build', { method: 'POST' });
      const data = await res.json();

      if (!res.ok || data.error) {
        throw new Error(data.error || 'Failed to establish circuit');
      }

      // Success! Update UI
      isCircuitActive = true;
      circuitStatusText.textContent = `Circuit: Active (#${data.circuit_id})`;
      circuitDot.className = 'pulse-dot green';

      // Update Node Boxes
      const guard = data.hops[0];
      const middle = data.hops[1];
      const exit = data.hops[2];

      labelGuardName.textContent = guard.name;
      labelGuardAddr.textContent = `${guard.ip}:${guard.port}`;
      nodeGuard.classList.add('active');

      setTimeout(() => {
        animateHop('dot-hop2');
        labelMiddleName.textContent = middle.name;
        labelMiddleAddr.textContent = `${middle.ip}:${middle.port}`;
        nodeMiddle.classList.add('active');
      }, 400);

      setTimeout(() => {
        animateHop('dot-hop3');
        labelExitName.textContent = exit.name;
        labelExitAddr.textContent = `${exit.ip}:${exit.port}`;
        nodeExit.classList.add('active');
      }, 800);

      // Update Keys Cards
      valK1.textContent = guard.session_key;
      valK2.textContent = middle.session_key;
      valK3.textContent = exit.session_key;
      keysStatus.textContent = '3-Hop Circuit Ready';
      keysStatus.className = 'badge-status active';

      btnBuildText.textContent = 'Rebuild 3-Hop Circuit';
    } catch (err) {
      alert(`Circuit Construction Error: ${err.message}`);
      btnBuildText.textContent = 'Establish 3-Hop Circuit';
    } finally {
      btnBuildCircuit.disabled = false;
    }
  });

  function animateHop(dotId) {
    const dot = document.getElementById(dotId);
    if (!dot) return;
    dot.classList.remove('animating');
    void dot.offsetWidth; // trigger reflow
    dot.classList.add('animating');
  }

  // ----------------------------------------------------
  // 4. Transmit Onion Message & Peel Layers
  // ----------------------------------------------------
  btnSendMessage.addEventListener('click', async () => {
    if (!isCircuitActive) {
      alert('Please click "Establish 3-Hop Circuit" first to build the cryptographic route!');
      return;
    }

    const message = inputMessage.value.trim();
    if (!message) {
      alert('Please enter a message to send.');
      return;
    }

    const destParts = inputDest.value.trim().split(':');
    const dest_ip = destParts[0] || '127.0.0.1';
    const dest_port = parseInt(destParts[1], 10) || 9090;

    btnSendMessage.disabled = true;
    btnSendMessage.querySelector('span').textContent = 'Encrypting & Routing...';

    // Reset Peeler UI
    resetPeelerUI();

    try {
      const res = await fetch('/api/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dest_ip, dest_port, message })
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Failed to route message');
      }

      // Step 1: Hop 1 Peeling (Guard)
      animateHop('dot-hop1');
      cardLayer1.classList.add('peeling');
      sizeL1.textContent = `${data.layers[0].total_bytes} Bytes`;
      hexL1.textContent = data.layers[0].ciphertext_hex_preview;

      setTimeout(() => {
        cardLayer1.classList.remove('peeling');
        cardLayer1.classList.add('peeled');

        // Step 2: Hop 2 Peeling (Middle)
        animateHop('dot-hop2');
        cardLayer2.classList.add('peeling');
        sizeL2.textContent = `${data.layers[1].total_bytes} Bytes`;
        hexL2.textContent = data.layers[1].ciphertext_hex_preview;
      }, 350);

      setTimeout(() => {
        cardLayer2.classList.remove('peeling');
        cardLayer2.classList.add('peeled');

        // Step 3: Hop 3 Peeling (Exit)
        animateHop('dot-hop3');
        cardLayer3.classList.add('peeling');
        sizeL3.textContent = `${data.layers[2].total_bytes} Bytes`;
        hexL3.textContent = data.layers[2].ciphertext_hex_preview;
      }, 700);

      setTimeout(() => {
        cardLayer3.classList.remove('peeling');
        cardLayer3.classList.add('peeled');

        // Destination reached
        animateHop('dot-dest');
        respContentText.textContent = data.response_plaintext;
        respLatencyBadge.textContent = `Latency: ${data.latency_ms.toFixed(1)} ms`;
      }, 1050);

    } catch (err) {
      alert(`Onion Routing Error: ${err.message}`);
    } finally {
      setTimeout(() => {
        btnSendMessage.disabled = false;
        btnSendMessage.querySelector('span').textContent = 'Transmit Across C++ Onion Circuit';
      }, 1100);
    }
  });

  function resetPeelerUI() {
    [cardLayer1, cardLayer2, cardLayer3].forEach(c => {
      c.classList.remove('peeling', 'peeled');
    });
    sizeL1.textContent = '--';
    sizeL2.textContent = '--';
    sizeL3.textContent = '--';
    hexL1.textContent = 'Encrypting outer layer...';
    hexL2.textContent = 'Encrypting intermediate layer...';
    hexL3.textContent = 'Encrypting innermost layer...';
    respContentText.textContent = 'Awaiting transit through C++ relays...';
    respLatencyBadge.textContent = 'Latency: -- ms';
  }

  // ----------------------------------------------------
  // 5. Preset Buttons
  // ----------------------------------------------------
  document.querySelectorAll('.btn-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      inputMessage.value = pill.dataset.preset;
    });
  });

  // ----------------------------------------------------
  // 6. Threat Matrix Tabs
  // ----------------------------------------------------
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));

      btn.classList.add('active');
      const targetId = btn.dataset.tab;
      document.getElementById(targetId)?.classList.remove('hidden');
    });
  });

  // Check initial state
  async function checkInitialCircuit() {
    try {
      const res = await fetch('/api/circuit');
      if (res.ok) {
        const data = await res.json();
        if (data.active) {
          isCircuitActive = true;
          circuitStatusText.textContent = `Circuit: Active (#${data.circuit_id})`;
          circuitDot.className = 'pulse-dot green';
          labelGuardName.textContent = data.hops[0].name;
          labelGuardAddr.textContent = `${data.hops[0].ip}:${data.hops[0].port}`;
          labelMiddleName.textContent = data.hops[1].name;
          labelMiddleAddr.textContent = `${data.hops[1].ip}:${data.hops[1].port}`;
          labelExitName.textContent = data.hops[2].name;
          labelExitAddr.textContent = `${data.hops[2].ip}:${data.hops[2].port}`;
          nodeGuard.classList.add('active');
          nodeMiddle.classList.add('active');
          nodeExit.classList.add('active');

          if (data.hops[0].session_key) {
            valK1.textContent = data.hops[0].session_key;
            valK2.textContent = data.hops[1].session_key;
            valK3.textContent = data.hops[2].session_key;
            keysStatus.textContent = '3-Hop Circuit Ready';
            keysStatus.className = 'badge-status active';
            btnBuildText.textContent = 'Rebuild 3-Hop Circuit';
          }
        }
      }
    } catch (_) {}
  }

  // Initial runs
  initSSE();
  fetchConsensus();
  setTimeout(fetchConsensus, 1500); // Auto-sync after relays register
  checkInitialCircuit();
});
