/**
 * PhishGuard AI — Interactive Frontend Engine
 * Handles theme switching, async URL scanning, email threat modeling,
 * gauge animation, explainable AI filtering, SQLite audit trail, and metrics.
 */

document.addEventListener('DOMContentLoaded', () => {
    initThemeManager();
    initTabs();
    initUrlScanner();
    initEmailScanner();
    initHistoryViewer();
    initMetricsDashboard();

    // Safely parse initial template result if present
    const scanDataEl = document.getElementById('initial-scan-result');
    if (scanDataEl && scanDataEl.textContent.trim()) {
        try {
            window.INITIAL_SCAN_RESULT = JSON.parse(scanDataEl.textContent);
        } catch (e) {
            console.error('Failed to parse initial scan result payload:', e);
        }
    }

    if (window.INITIAL_SCAN_RESULT) {
        renderScanResults(window.INITIAL_SCAN_RESULT);
    }
});

/* ==========================================================================
   0. Color Palette Dropdown Theme System (Pure Color Swatches)
   ========================================================================== */
function initThemeManager() {
    const selectorBtn = document.getElementById('btn-theme-selector');
    const menuOptions = document.getElementById('theme-menu-options');
    const colorOptions = document.querySelectorAll('.theme-color-option');
    const activeSwatch = document.getElementById('theme-active-swatch');

    // Retrieve active theme from DOM or localStorage
    let currentTheme = localStorage.getItem('phishguard_theme') || document.documentElement.getAttribute('data-theme') || 'cream';
    applyTheme(currentTheme, false);

    // Toggle dropdown open/close
    if (selectorBtn && menuOptions) {
        selectorBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const isExpanded = selectorBtn.getAttribute('aria-expanded') === 'true';
            selectorBtn.setAttribute('aria-expanded', !isExpanded);
            menuOptions.classList.toggle('show');
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!selectorBtn.contains(e.target) && !menuOptions.contains(e.target)) {
                selectorBtn.setAttribute('aria-expanded', 'false');
                menuOptions.classList.remove('show');
            }
        });
    }

    // Color option selection
    colorOptions.forEach(btn => {
        btn.addEventListener('click', () => {
            const selected = btn.getAttribute('data-set-theme');
            if (selected) {
                applyTheme(selected, true);
                if (selectorBtn && menuOptions) {
                    selectorBtn.setAttribute('aria-expanded', 'false');
                    menuOptions.classList.remove('show');
                }
            }
        });
    });

    function applyTheme(themeKey, notify = false) {
        if (!['cream', 'light', 'dark'].includes(themeKey)) {
            themeKey = 'cream';
        }

        document.documentElement.setAttribute('data-theme', themeKey);
        localStorage.setItem('phishguard_theme', themeKey);

        if (activeSwatch) {
            activeSwatch.className = `theme-active-swatch swatch-${themeKey}`;
        }

        colorOptions.forEach(b => {
            if (b.getAttribute('data-set-theme') === themeKey) {
                b.classList.add('active');
                b.setAttribute('aria-checked', 'true');
            } else {
                b.classList.remove('active');
                b.setAttribute('aria-checked', 'false');
            }
        });

        if (notify) {
            const names = { cream: 'Warm Cream', light: 'Pure White', dark: 'Cyber Dark' };
            showToast(`Theme changed to ${names[themeKey] || themeKey}`, 'info');
        }
    }
}

/* ==========================================================================
   1. Tab Navigation System
   ========================================================================== */
function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');

    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');

            tabButtons.forEach(b => b.classList.remove('active'));
            tabPanels.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            const targetPanel = document.getElementById(targetId);
            if (targetPanel) {
                targetPanel.classList.add('active');
            }

            // Lazy load tab data
            if (targetId === 'tab-history') {
                loadHistoryTable();
            } else if (targetId === 'tab-metrics') {
                loadMetricsData();
            }
        });
    });
}

/* ==========================================================================
   2. URL Scanner Module
   ========================================================================== */
let currentIndicators = [];

function initUrlScanner() {
    const scanForm = document.getElementById('url-scan-form');
    const urlInput = document.getElementById('url-input');
    const sampleChips = document.querySelectorAll('.chip-sample');

    // Sample Link Click Handler
    sampleChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const sampleUrl = chip.getAttribute('data-url');
            if (sampleUrl && urlInput) {
                urlInput.value = sampleUrl;
                urlInput.focus();
            }
        });
    });

    // Form Submit Handler
    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = urlInput.value.trim();
            if (!url) return;

            await performUrlScan(url);
        });
    }

    // Indicator Filter Buttons
    const filterButtons = document.querySelectorAll('.btn-filter-pill');
    filterButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            filterButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const filter = btn.getAttribute('data-filter');
            renderIndicatorsGrid(currentIndicators, filter);
        });
    });

    // Copy Defanged URL
    const copyBtn = document.getElementById('btn-copy-defanged');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const defangedText = document.getElementById('defanged-url-display').innerText;
            navigator.clipboard.writeText(defangedText).then(() => {
                showToast('Defanged URL copied to clipboard!', 'success');
            });
        });
    }
}

async function performUrlScan(url) {
    const loadingCard = document.getElementById('scan-loading');
    const resultCard = document.getElementById('scan-result-card');
    const scanBtn = document.getElementById('btn-scan-submit');

    // UI State: Scanning
    if (loadingCard) loadingCard.style.display = 'block';
    if (resultCard) resultCard.style.display = 'none';
    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.innerHTML = `
            <svg class="scan-spinner" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none">
                <circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-linecap="round"></circle>
            </svg> Analyzing...
        `;
    }

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || 'Failed to complete URL scan.');
        }

        renderScanResults(data);
        showToast('Cyber threat scan complete!', 'success');

    } catch (err) {
        console.error(err);
        showToast(err.message || 'Error executing threat scan.', 'error');
    } finally {
        if (loadingCard) loadingCard.style.display = 'none';
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.innerHTML = `
                <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                </svg> Scan Target
            `;
        }
    }
}

function renderScanResults(data) {
    const resultCard = document.getElementById('scan-result-card');
    if (!resultCard) return;

    resultCard.style.display = 'block';
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    currentIndicators = data.indicators || [];

    // 1. Verdict Banner
    const banner = document.getElementById('verdict-banner');
    const iconBox = document.getElementById('verdict-icon-box');
    const titleEl = document.getElementById('verdict-title');
    const descEl = document.getElementById('verdict-desc');
    const riskBadge = document.getElementById('verdict-risk-badge');
    const threatsBadge = document.getElementById('verdict-threats-badge');

    banner.className = 'verdict-banner';

    if (data.verdict === 'PHISHING') {
        banner.classList.add('verdict-danger');
        iconBox.innerHTML = `
            <svg viewBox="0 0 24 24" width="32" height="32" stroke="currentColor" stroke-width="2" fill="none">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                <line x1="12" y1="9" x2="12" y2="13"></line>
                <line x1="12" y1="17" x2="12.01" y2="17"></line>
            </svg>
        `;
        titleEl.innerText = 'High-Risk Phishing Detected';
        descEl.innerText = 'Critical deceptive markers detected. Avoid entering credentials or personal data.';
        riskBadge.className = 'pill-badge pill-badge-danger';
        riskBadge.innerText = `Threat Index: ${data.risk_score}%`;
    } else if (data.verdict === 'SUSPICIOUS') {
        banner.classList.add('verdict-warning');
        iconBox.innerHTML = `
            <svg viewBox="0 0 24 24" width="32" height="32" stroke="currentColor" stroke-width="2" fill="none">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
        `;
        titleEl.innerText = 'Suspicious Indicators Found';
        descEl.innerText = 'Anomalous URL characteristics detected. Exercise heightened vigilance.';
        riskBadge.className = 'pill-badge pill-badge-danger';
        riskBadge.innerText = `Threat Index: ${data.risk_score}%`;
    } else {
        banner.classList.add('verdict-safe');
        iconBox.innerHTML = `
            <svg viewBox="0 0 24 24" width="32" height="32" stroke="currentColor" stroke-width="2" fill="none">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <polyline points="9 12 11 14 15 10"></polyline>
            </svg>
        `;
        titleEl.innerText = 'Verified Legitimate Website';
        descEl.innerText = 'URL matches authentic structural and domain integrity standards.';
        riskBadge.className = 'pill-badge pill-badge-safe';
        riskBadge.innerText = `Safety Index: ${data.safety_score}%`;
    }

    if (threatsBadge) {
        threatsBadge.innerText = `${data.threat_count || 0} Threat Flag(s)`;
    }

    // 2. Animated Circular Gauge
    animateGauge(data.risk_score, data.verdict);

    // 3. URL Details & Defanged Display
    const defangedEl = document.getElementById('defanged-url-display');
    if (defangedEl) defangedEl.innerText = data.defanged_url || data.url;

    const rawUrlEl = document.getElementById('raw-url-display');
    if (rawUrlEl) rawUrlEl.innerText = data.url;

    const statFeaturesEl = document.getElementById('stat-features-total');
    if (statFeaturesEl) statFeaturesEl.innerText = (data.indicators || []).length || '30';

    const statThreatsEl = document.getElementById('stat-threats-count');
    if (statThreatsEl) statThreatsEl.innerText = data.threat_count || '0';

    const statDomainEl = document.getElementById('stat-domain-status');
    if (statDomainEl) {
        const isSsrf = data.is_ssrf_risk;
        statDomainEl.innerText = isSsrf ? 'Private / Internal' : 'Public Web';
        statDomainEl.style.color = isSsrf ? 'var(--danger)' : 'var(--cyan-400)';
    }

    // 4. Render 30 Explainable AI Indicator Cards
    renderIndicatorsGrid(currentIndicators, 'all');
}

function animateGauge(riskScore, verdict) {
    const progressCircle = document.getElementById('gauge-circle-progress');
    const scoreValEl = document.getElementById('gauge-score-num');

    if (!progressCircle || !scoreValEl) return;

    // Circumference = 2 * PI * r = 2 * 3.14159 * 70 ≈ 440
    const circumference = 440;
    const offset = circumference - (riskScore / 100) * circumference;

    progressCircle.style.strokeDashoffset = offset;

    // Gauge Stroke Color based on threat level
    if (verdict === 'PHISHING') {
        progressCircle.style.stroke = 'var(--danger)';
        scoreValEl.style.color = 'var(--danger)';
    } else if (verdict === 'SUSPICIOUS') {
        progressCircle.style.stroke = 'var(--warning)';
        scoreValEl.style.color = 'var(--warning)';
    } else {
        progressCircle.style.stroke = 'var(--safe)';
        scoreValEl.style.color = 'var(--safe)';
    }

    // Number counting animation
    let currentVal = 0;
    const duration = 1000;
    const stepTime = 20;
    const steps = duration / stepTime;
    const increment = riskScore / steps;

    const counter = setInterval(() => {
        currentVal += increment;
        if (currentVal >= riskScore) {
            currentVal = riskScore;
            clearInterval(counter);
        }
        scoreValEl.innerText = `${Math.round(currentVal)}%`;
    }, stepTime);
}

function renderIndicatorsGrid(indicators, filter = 'all') {
    const grid = document.getElementById('indicators-grid');
    if (!grid) return;

    grid.innerHTML = '';

    let filtered = indicators;
    if (filter === 'threats') {
        filtered = indicators.filter(ind => ind.status === 'danger');
    } else if (filter === 'warnings') {
        filtered = indicators.filter(ind => ind.status === 'warning');
    } else if (filter === 'safe') {
        filtered = indicators.filter(ind => ind.status === 'success');
    }

    if (filtered.length === 0) {
        grid.innerHTML = `
            <div style="grid-column: 1/-1; text-align: center; padding: 2rem; color: var(--text-muted);">
                No indicators match the selected filter (${filter}).
            </div>
        `;
        return;
    }

    filtered.forEach(ind => {
        const card = document.createElement('div');
        card.className = `indicator-card status-${ind.status || 'info'}`;
        card.innerHTML = `
            <div class="ind-header">
                <span class="ind-category">${ind.category || 'Feature'}</span>
                <span class="ind-badge">${ind.status === 'danger' ? 'Threat' : (ind.status === 'warning' ? 'Warning' : 'Pass')}</span>
            </div>
            <div class="ind-title">${ind.title || ind.name}</div>
            <div class="ind-desc">${ind.detail || ind.explanation || ''}</div>
        `;
        grid.appendChild(card);
    });
}

/* ==========================================================================
   3. Email Threat Scanner Module
   ========================================================================== */
function initEmailScanner() {
    const emailForm = document.getElementById('email-scan-form');
    const resultCard = document.getElementById('email-result-card');

    if (emailForm) {
        emailForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const sender = document.getElementById('email-sender').value.trim();
            const subject = document.getElementById('email-subject').value.trim();
            const body = document.getElementById('email-body').value.trim();

            if (!body && !subject) {
                showToast('Please enter an email subject or body.', 'warning');
                return;
            }

            try {
                const res = await fetch('/api/scan-email', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sender, subject, body })
                });

                const data = await res.json();
                if (!res.ok || !data.success) {
                    throw new Error(data.error || 'Failed to scan email.');
                }

                renderEmailResults(data);
                showToast('Email threat analysis complete!', 'success');
            } catch (err) {
                console.error(err);
                showToast(err.message, 'error');
            }
        });
    }
}

function renderEmailResults(data) {
    const card = document.getElementById('email-result-card');
    if (!card) return;

    card.style.display = 'block';
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    const verdictEl = document.getElementById('email-verdict-title');
    const scoreEl = document.getElementById('email-risk-score');
    const flagsEl = document.getElementById('email-indicators-list');

    if (verdictEl) {
        verdictEl.innerText = data.verdict === 'PHISHING' 
            ? '🚨 Phishing / Social Engineering Campaign Detected'
            : (data.verdict === 'SUSPICIOUS' ? '⚠️ Suspicious Email Construction' : '🛡️ Low Phishing Probability');
        verdictEl.style.color = data.verdict === 'PHISHING' ? 'var(--danger)' : (data.verdict === 'SUSPICIOUS' ? 'var(--warning)' : 'var(--safe)');
    }

    if (scoreEl) {
        scoreEl.innerText = `Threat Risk Score: ${data.risk_score}%`;
    }

    if (flagsEl) {
        flagsEl.innerHTML = '';
        if (data.indicators && data.indicators.length > 0) {
            data.indicators.forEach(ind => {
                const item = document.createElement('div');
                item.className = `indicator-card status-${ind.type === 'danger' ? 'danger' : (ind.type === 'warning' ? 'warning' : 'success')}`;
                item.style.marginBottom = '0.75rem';
                item.innerHTML = `
                    <div class="ind-header">
                        <span class="ind-category">${ind.category}</span>
                        <span class="ind-badge">${ind.type.toUpperCase()}</span>
                    </div>
                    <div class="ind-title">${ind.title}</div>
                    <div class="ind-desc">${ind.detail}</div>
                `;
                flagsEl.appendChild(item);
            });
        } else {
            flagsEl.innerHTML = '<p style="color: var(--text-muted);">No overt threat markers identified in text content.</p>';
        }
    }
}

/* ==========================================================================
   4. Scan History & Audit Trail Module
   ========================================================================== */
function initHistoryViewer() {
    const clearBtn = document.getElementById('btn-clear-history');
    const searchInput = document.getElementById('history-search-input');

    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            if (confirm('Are you sure you want to clear all scan history logs?')) {
                await fetch('/api/clear-history', { method: 'POST' });
                loadHistoryTable();
                showToast('Scan history cleared.', 'info');
            }
        });
    }

    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            filterHistoryRows(query);
        });
    }
}

let loadedHistoryRows = [];

async function loadHistoryTable() {
    const tbody = document.getElementById('history-table-body');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">Loading scan logs from SQLite...</td></tr>';

    try {
        const res = await fetch('/api/history?limit=50');
        const data = await res.json();

        if (data.success && data.history) {
            loadedHistoryRows = data.history;
            renderHistoryRows(loadedHistoryRows);

            // Update stats
            const stats = data.stats;
            if (stats) {
                const totalEl = document.getElementById('stat-hist-total');
                if (totalEl) totalEl.innerText = stats.total_scans;
                const phishEl = document.getElementById('stat-hist-phishing');
                if (phishEl) phishEl.innerText = stats.phishing_count;
                const safeEl = document.getElementById('stat-hist-safe');
                if (safeEl) safeEl.innerText = stats.safe_count;
            }
        }
    } catch (err) {
        console.error(err);
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--danger); padding: 2rem;">Error fetching history logs.</td></tr>';
    }
}

function renderHistoryRows(rows) {
    const tbody = document.getElementById('history-table-body');
    if (!tbody) return;

    if (rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">No historical scans recorded yet.</td></tr>';
        return;
    }

    tbody.innerHTML = '';
    rows.forEach((row, idx) => {
        const tr = document.createElement('tr');
        const badgeClass = row.verdict === 'PHISHING' ? 'pill-badge-danger' : (row.verdict === 'SUSPICIOUS' ? 'pill-badge-danger' : 'pill-badge-safe');
        
        tr.innerHTML = `
            <td>#${row.id}</td>
            <td class="mono" style="color: var(--cyan-400); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${row.url}">
                ${row.defanged_url || row.url}
            </td>
            <td>
                <span class="pill-badge ${badgeClass}">${row.verdict}</span>
            </td>
            <td style="font-weight: 700; color: ${row.verdict === 'PHISHING' ? 'var(--danger)' : 'var(--safe)'};">
                ${row.risk_score}% Risk
            </td>
            <td>${row.threat_count || 0} flags</td>
            <td style="color: var(--text-muted); font-size: 0.8rem;">${row.created_at}</td>
        `;
        tbody.appendChild(tr);
    });
}

function filterHistoryRows(query) {
    if (!loadedHistoryRows) return;
    const filtered = loadedHistoryRows.filter(r => 
        (r.url && r.url.toLowerCase().includes(query)) ||
        (r.defanged_url && r.defanged_url.toLowerCase().includes(query)) ||
        (r.verdict && r.verdict.toLowerCase().includes(query))
    );
    renderHistoryRows(filtered);
}

/* ==========================================================================
   5. AI Model Metrics Module
   ========================================================================== */
async function loadMetricsData() {
    try {
        const res = await fetch('/api/metrics');
        const data = await res.json();

        if (data.success && data.metrics) {
            const m = data.metrics;

            // Summary Stats
            document.getElementById('metric-accuracy').innerText = `${(m.accuracy * 100).toFixed(2)}%`;
            document.getElementById('metric-f1').innerText = m.f1_score.toFixed(4);
            document.getElementById('metric-precision').innerText = `${(m.precision * 100).toFixed(2)}%`;
            document.getElementById('metric-recall').innerText = `${(m.recall * 100).toFixed(2)}%`;

            // Confusion Matrix
            const cm = m.confusion_matrix;
            document.getElementById('cm-tp').innerText = cm.tp.toLocaleString();
            document.getElementById('cm-tn').innerText = cm.tn.toLocaleString();
            document.getElementById('cm-fp').innerText = cm.fp.toLocaleString();
            document.getElementById('cm-fn').innerText = cm.fn.toLocaleString();

            // Feature Importances
            const featContainer = document.getElementById('feature-importance-bars');
            if (featContainer && m.feature_importances) {
                featContainer.innerHTML = '';
                m.feature_importances.forEach(feat => {
                    const barItem = document.createElement('div');
                    barItem.style.marginBottom = '0.85rem';
                    barItem.innerHTML = `
                        <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 0.3rem;">
                            <span class="mono" style="color: var(--text-main); font-weight: 500;">${feat.name}</span>
                            <span style="color: var(--cyan-400); font-weight: 700;">${feat.percentage}%</span>
                        </div>
                        <div style="height: 6px; background: var(--feat-bar-bg); border-radius: 999px; overflow: hidden;">
                            <div style="width: ${Math.min(100, feat.percentage * 2.2)}%; height: 100%; background: linear-gradient(90deg, var(--cyan-500), var(--indigo-500)); border-radius: 999px;"></div>
                        </div>
                    `;
                    featContainer.appendChild(barItem);
                });
            }
        }
    } catch (err) {
        console.error('Error fetching metrics:', err);
    }
}

function initMetricsDashboard() {
    // Initial placeholder bindings
}

/* ==========================================================================
   6. Toast Helper
   ========================================================================== */
function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = 'toast-msg';

    let icon = `
        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="16" x2="12" y2="12"></line>
            <line x1="12" y1="8" x2="12.01" y2="8"></line>
        </svg>
    `;

    if (type === 'success') {
        toast.style.borderColor = 'var(--safe)';
        icon = `
            <svg viewBox="0 0 24 24" width="18" height="18" stroke="var(--safe)" stroke-width="2" fill="none">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
        `;
    } else if (type === 'error') {
        toast.style.borderColor = 'var(--danger)';
        icon = `
            <svg viewBox="0 0 24 24" width="18" height="18" stroke="var(--danger)" stroke-width="2" fill="none">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="15" y1="9" x2="9" y2="15"></line>
                <line x1="9" y1="9" x2="15" y2="15"></line>
            </svg>
        `;
    }

    toast.innerHTML = `${icon} <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}
