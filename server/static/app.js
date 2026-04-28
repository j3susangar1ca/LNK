/* ═══════════════════════════════════════════
   LNK TOOL v4.0 — Vanilla JS Application
   Port from React to pure DOM manipulation
   ═══════════════════════════════════════════ */

(function () {
  'use strict';

  /* ─── SVG ICON TEMPLATES ─── */
  const SVG = {
    eye: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
    eyeOff: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`,
    shield: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    layers: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>`,
    zap: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
    alert: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    fileCode: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="15" x2="15" y2="15"/></svg>`,
    download: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
  };

  /* ─── TECHNIQUE DATA ─── */
  const TECHNIQUES = [
    { id: 'SPOOFEXE_SHOWARGS_ENABLETARGET', name: 'Spoof Properties', desc: 'Display fake target, execute real with visible arguments.', icon: 'eye' },
    { id: 'REALEXE_HIDEARGS_DISABLETARGET', name: 'Hide Arguments', desc: 'Execute real target, conceal arguments and disable metadata.', icon: 'eyeOff' },
    { id: 'SPOOFEXE_HIDEARGS_DISABLETARGET', name: 'Silent Spoof', desc: 'Fake display with hidden args via empty UnicodeTarget.', icon: 'shield' },
    { id: 'LOLBIN_CHAIN', name: 'LOLBin Chain', desc: 'Chain execution through legitimate Windows system binaries.', icon: 'layers' },
    { id: 'FILE_SMUGGLING', name: 'File Smuggling', desc: 'Remote payload download, execute, and automatic cleanup.', icon: 'zap' },
    { id: 'ANTI_SANDBOX', name: 'Anti-Sandbox', desc: 'VM and sandbox environment detection pre-execution.', icon: 'alert' },
    { id: 'CVE20259491', name: 'CVE Padding', desc: 'Newline/return padding technique for format evasion.', icon: 'fileCode' },
  ];

  const SETTINGS_ITEMS = [
    { key: 'timestamps', title: 'Random Timestamps', desc: 'Generate plausible random creation, access, and modification timestamps for each output file.' },
    { key: 'polymorphic', title: 'Polymorphic Output', desc: 'Apply jitter mutations to reserved bytes and trailing padding so every file has a unique SHA-256 hash.' },
    { key: 'obfuscation', title: 'String Obfuscation', desc: 'Compile-time XOR obfuscation with per-line LCG-derived keys to defeat static string analysis.' },
    { key: 'crc32', title: 'CRC32 Verification', desc: 'Calculate and display CRC32 checksum for each generated LNK file upon completion.' },
  ];

  /* ─── STATE ─── */
  let selectedTech = TECHNIQUES[0].id;
  let settings = { timestamps: true, polymorphic: true, obfuscation: true, crc32: true };

  /* ─── HELPERS ─── */
  function $(sel) { return document.querySelector(sel); }
  function $$(sel) { return document.querySelectorAll(sel); }
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  /* ─── TAB NAVIGATION ─── */
  function initTabs() {
    $$('.nav-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        $$('.nav-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        $$('.tab-content').forEach(t => t.classList.remove('active'));
        $(`#tab-${tab}`).classList.add('active');
      });
    });
  }

  /* ─── TECHNIQUE GRID ─── */
  function renderTechGrid() {
    const grid = $('#tech-grid');
    grid.innerHTML = '';
    TECHNIQUES.forEach(tech => {
      const card = document.createElement('div');
      card.className = `tech-card${tech.id === selectedTech ? ' active' : ''}`;
      card.innerHTML = `
        <div class="tc-icon">${SVG[tech.icon] || ''}</div>
        <div class="tc-name">${tech.name}</div>
        <div class="tc-desc">${tech.desc}</div>
      `;
      card.addEventListener('click', () => {
        selectedTech = tech.id;
        renderTechGrid();
        // Show/hide URL field for FILE_SMUGGLING
        const urlGroup = $('#url-group');
        urlGroup.style.display = selectedTech === 'FILE_SMUGGLING' ? '' : 'none';
      });
      grid.appendChild(card);
    });
  }

  /* ─── SETTINGS GRID ─── */
  function renderSettings() {
    const grid = $('#settings-grid');
    grid.innerHTML = '';
    SETTINGS_ITEMS.forEach(item => {
      const el = document.createElement('div');
      el.className = 'setting-item';
      el.innerHTML = `
        <h4>${item.title}</h4>
        <p>${item.desc}</p>
        <div class="toggle${settings[item.key] ? ' on' : ''}" role="switch" aria-checked="${settings[item.key]}" tabindex="0" data-key="${item.key}"></div>
      `;
      el.querySelector('.toggle').addEventListener('click', function () {
        settings[item.key] = !settings[item.key];
        this.classList.toggle('on');
        this.setAttribute('aria-checked', settings[item.key]);
      });
      grid.appendChild(el);
    });
  }

  /* ─── GENERATE ─── */
  function initGenerate() {
    const btn = $('#btn-generate');
    const consoleEl = $('#console-output');

    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = 'Processing...';
      consoleEl.innerHTML = '<div class="console-idle">Processing request...</div>';

      const payload = {
        technique: selectedTech,
        target: $('#inp-target').value,
        fake: $('#inp-fake').value,
        args: $('#inp-args').value,
        out: $('#inp-out').value,
        delay: parseInt($('#inp-delay').value) || 0,
        url: $('#inp-url').value,
        timestamps: settings.timestamps,
        polymorphic: settings.polymorphic,
        obfuscation: settings.obfuscation,
        crc32: settings.crc32,
      };

      try {
        const res = await fetch('/api/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json();

        if (data.success) {
          const sep = '─'.repeat(40);
          consoleEl.innerHTML = `
            <div class="line info">&gt; Process completed successfully</div>
            <div class="line dim">${sep}</div>
            <div class="line">File: ${escapeHtml(data.file)}</div>
            <div class="line">Size: ${escapeHtml(String(data.size))} bytes</div>
            <div class="line">CRC32: ${escapeHtml(String(data.crc32))}</div>
            <div class="line success">Technique: ${escapeHtml(selectedTech)}</div>
            <div class="line dim">${sep}</div>
            <a href="/api/download/${encodeURIComponent(data.file)}" target="_blank" rel="noopener noreferrer" class="download-btn">
              ${SVG.download} Download LNK
            </a>
          `;
        } else {
          consoleEl.innerHTML = `<div class="line error">&gt; ERROR: ${escapeHtml(data.error || 'Unknown error')}</div>`;
        }
      } catch (err) {
        consoleEl.innerHTML = `<div class="line error">&gt; ERROR: Connection to backend failed. Ensure the API server is running.</div>`;
      }

      btn.disabled = false;
      btn.innerHTML = `${SVG.zap} Generate LNK`;
    });
  }

  /* ─── VERIFY (Drag & Drop + Click) ─── */
  function initVerify() {
    const zone = $('#verify-dropzone');
    const fileInput = $('#verify-file-input');
    const output = $('#verify-output');
    const title = $('#verify-zone-title');

    zone.addEventListener('click', () => fileInput.click());

    zone.addEventListener('dragover', (e) => {
      e.preventDefault();
      zone.style.borderColor = 'var(--accent)';
      zone.style.background = 'var(--accent-deep)';
    });

    zone.addEventListener('dragleave', () => {
      zone.style.borderColor = '';
      zone.style.background = '';
    });

    zone.addEventListener('drop', (e) => {
      e.preventDefault();
      zone.style.borderColor = '';
      zone.style.background = '';
      const file = e.dataTransfer.files[0];
      if (file) verifyFile(file);
    });

    fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) verifyFile(file);
      fileInput.value = ''; // Reset for re-upload
    });

    async function verifyFile(file) {
      title.textContent = 'Analyzing...';
      output.innerHTML = '<div class="console-idle">Processing file...</div>';

      const formData = new FormData();
      formData.append('file', file);

      try {
        const res = await fetch('/api/verify', {
          method: 'POST',
          body: formData,
        });
        const data = await res.json();

        const sep = '─'.repeat(40);
        const statusClass = data.verified ? 'success' : 'warn';
        const statusText = data.verified ? 'VERIFIED SAFE' : 'ANOMALY DETECTED';

        output.innerHTML = `
          <div class="line ${statusClass}">&gt; Status: ${statusText}</div>
          <div class="line dim">${sep}</div>
          <pre style="white-space:pre-wrap;font-size:0.7rem">${escapeHtml(data.output || '')}</pre>
        `;
      } catch (err) {
        output.innerHTML = `<div class="line error">&gt; ERROR: Verification failed.</div>`;
      }

      title.textContent = 'Drop LNK File Here';
    }
  }

  /* ─── INIT ─── */
  document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    renderTechGrid();
    renderSettings();
    initGenerate();
    initVerify();
  });
})();
