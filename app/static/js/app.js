/**
 * SOC Alert Analyzer — Nicole’s Security Lab
 * Real-Time Host Security Monitor & Client Investigation Controller
 */

// Global State
const SOC_STATE = {
    alerts: [],
    selectedAlertId: null,
    activeTab: 'overview',
    filters: {
        severity: null,     // 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
        status: 'all',      // 'all', 'needs_review', 'reviewed'
        source: 'all',      // 'all', 'host', 'wazuh', 'suricata', etc.
        search: ''
    },
    sort: 'priority',       // 'priority', 'newest'
    sessionReviewed: new Set(),
    checklistProgress: {},  // alertId -> Array of checked step indices
    monitoringState: 'CHECKING', // 'CHECKING', 'ACTIVE', 'PAUSING', 'PAUSED', 'RESUMING', 'UNKNOWN', 'ERROR'
    isHostMonitoringActive: null,
    isSimulationActive: false,
    wsConnectionState: 'disconnected'
};

// --------------------------------------------------------------------------
// 1. Initialization
// --------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    initSessionStorage();
    loadInitialRealHostAlerts();
    initEventHandlers();
    updateMonitoringUI('CHECKING');
    initThreatStream();
    initStreamStatus();
    checkAuthStatus();
    renderAll();
});

function initSessionStorage() {
    try {
        const stored = sessionStorage.getItem('soc_reviewed_alerts');
        if (stored) {
            SOC_STATE.sessionReviewed = new Set(JSON.parse(stored));
        }
        const checks = sessionStorage.getItem('soc_checklist_progress');
        if (checks) {
            SOC_STATE.checklistProgress = JSON.parse(checks);
        }
    } catch (e) {
        console.warn('SessionStorage unavailable:', e);
    }
}

function saveSessionStorage() {
    try {
        sessionStorage.setItem('soc_reviewed_alerts', JSON.stringify(Array.from(SOC_STATE.sessionReviewed)));
        sessionStorage.setItem('soc_checklist_progress', JSON.stringify(SOC_STATE.checklistProgress));
    } catch (e) {
        console.warn('SessionStorage save failed:', e);
    }
}

function loadInitialRealHostAlerts() {
    // 1. Check embedded real laptop alerts passed directly from backend SQLite database
    const scriptEl = document.getElementById('initial-real-alerts');
    if (scriptEl && scriptEl.textContent.trim()) {
        try {
            const raw = JSON.parse(scriptEl.textContent);
            if (Array.isArray(raw) && raw.length > 0) {
                SOC_STATE.alerts = raw;
                // Mark alerts that are already resolved in database
                SOC_STATE.alerts.forEach((a) => {
                    if (a.status === 'RESOLVED') {
                        SOC_STATE.sessionReviewed.add(a.id);
                    }
                });
            }
        } catch (err) {
            console.warn('Error parsing initial real alerts:', err);
        }
    }

    // 2. If no alerts recorded yet on host, attempt immediate audit or fetch
    if (SOC_STATE.alerts.length === 0) {
        fetchAlertsFromApi();
    } else {
        sortAlerts();
        SOC_STATE.selectedAlertId = SOC_STATE.alerts[0].id;
    }
}

function getCsrfToken() {
    if (SOC_STATE.csrfToken) return SOC_STATE.csrfToken;
    const match = document.cookie.match(/(?:^|;\s*)soc_csrf=([^;]+)/);
    if (match) return decodeURIComponent(match[1]);
    return null;
}

function getApiHeaders(extraHeaders = {}) {
    const headers = { ...extraHeaders };
    const csrf = getCsrfToken();
    if (csrf) {
        headers['X-CSRF-Token'] = csrf;
    }
    return headers;
}

async function apiFetch(url, options = {}) {
    const opts = {
        credentials: 'same-origin',
        ...options,
        headers: getApiHeaders(options.headers || {})
    };
    try {
        const resp = await fetch(url, opts);
        if (resp.status === 401) {
            showToast('Sign in required. Click your role in the top header to enter your access key.');
        } else if (resp.status === 403) {
            showToast('Access denied: Your current role does not have permission for this action.');
        }
        return resp;
    } catch (e) {
        throw e;
    }
}

async function fetchAlertsFromApi() {
    try {
        const resp = await apiFetch('/api/v1/alerts?limit=100');
        if (resp.ok) {
            const data = await resp.json();
            if (Array.isArray(data)) {
                if (data.length > 0) {
                    SOC_STATE.alerts = data.map((a) => formatAlertForClient(a));
                    sortAlerts();
                    if (!SOC_STATE.alerts.some((a) => a.id === SOC_STATE.selectedAlertId)) {
                        SOC_STATE.selectedAlertId = SOC_STATE.alerts[0].id;
                    }
                } else {
                    SOC_STATE.alerts = [];
                    SOC_STATE.selectedAlertId = null;
                }
                renderAll();
            }
        }
    } catch (e) {
        console.log('Unable to reach /api/v1/alerts endpoint:', e);
    }
}

function formatAlertForClient(rawAlert) {
    const isReviewed = rawAlert.status === 'RESOLVED';
    if (isReviewed) {
        SOC_STATE.sessionReviewed.add(String(rawAlert.id));
    }

    return {
        id: String(rawAlert.id),
        title: rawAlert.description || rawAlert.event_type || 'Host Security Finding',
        source_type: rawAlert.source_type || 'Host Sensor',
        event_type: rawAlert.event_type || 'system_event',
        rule_id: String(rawAlert.id).substring(0, 8),
        rule_level: null,
        attempt_count: 1,
        severity: rawAlert.severity || 'MEDIUM',
        risk_score: rawAlert.risk_score || 35,
        source_ip: rawAlert.source_ip || null,
        source_port: rawAlert.source_port || null,
        destination_ip: rawAlert.destination_ip || null,
        destination_port: rawAlert.destination_port || null,
        device: rawAlert.username || 'Protected Machine',
        username: rawAlert.username || null,
        timestamp: rawAlert.timestamp || new Date().toISOString(),
        status: rawAlert.status || 'OPEN',
        what_happened: (() => {
            let desc = (rawAlert.description || '').trim();
            if (!desc || desc.toLowerCase().includes('security event detected') || desc.toLowerCase() === 'security anomaly') {
                const cleanType = (rawAlert.event_type || 'host security anomaly').replace(/_/g, ' ');
                const ctx = [];
                if (rawAlert.username) ctx.push(`user '${rawAlert.username}'`);
                if (rawAlert.source_ip && rawAlert.destination_ip) ctx.push(`from ${rawAlert.source_ip} to ${rawAlert.destination_ip}`);
                else if (rawAlert.source_ip) ctx.push(`source IP ${rawAlert.source_ip}`);
                if (rawAlert.destination_port) ctx.push(`port ${rawAlert.destination_port}`);
                return `Anomalous ${cleanType} activity detected${ctx.length ? ' involving ' + ctx.join(', ') : ''} on this host.`;
            }
            return desc;
        })(),
        why_suspicious: (() => {
            const ev = (rawAlert.event_type || '').toLowerCase();
            const d = (rawAlert.description || '').toLowerCase();
            if (ev.includes('logon') || ev.includes('auth') || d.includes('logon')) {
                return 'Repeated authentication failures indicate automated brute-force password guessing or account takeover attempts.';
            }
            if (ev.includes('shell') || d.includes('shell')) {
                return 'Interactive command interpreters spawned by web processes indicate active web shell deployment.';
            }
            if (ev.includes('shadow') || ev.includes('ransom') || d.includes('shadow')) {
                return 'Volume shadow copy purge commands are high-confidence indicators of ransomware inhibiting recovery before encryption.';
            }
            if (ev.includes('lolbin') || ev.includes('powershell') || d.includes('powershell')) {
                return 'Native system tools executed with hidden window or encoded parameters indicate defense evasion.';
            }
            if (ev.includes('port') || ev.includes('scan') || d.includes('scan')) {
                return 'Rapid network port sweeps signify adversary reconnaissance probing for unpatched listening services.';
            }
            if (ev.includes('masquerad') || d.includes('masquerad')) {
                return 'System executables executing outside Windows System32 are masquerading as legitimate binaries to hide malware.';
            }
            return 'Observed by real-time host defensive behavioral sensors.';
        })(),
        score_explanation: `Risk Score ${rawAlert.risk_score || 35}/100 based on host telemetry heuristics`,
        mitre: rawAlert.mitre_technique ? {
            technique: rawAlert.mitre_technique,
            name: 'Adversary Technique',
            tactic: 'Observed Tactic',
            url: `https://attack.mitre.org/techniques/${rawAlert.mitre_technique}/`
        } : null,
        actions: [
            'Inspect process name, PID, and executable file location',
            'Verify whether network connection was authorized by user',
            'Review local firewall and user authentication events'
        ],
        raw_log: rawAlert.raw_log || rawAlert
    };
}

function sortAlerts() {
    if (SOC_STATE.sort === 'priority') {
        SOC_STATE.alerts.sort((a, b) => {
            if (b.risk_score !== a.risk_score) {
                return b.risk_score - a.risk_score;
            }
            return new Date(b.timestamp) - new Date(a.timestamp);
        });
    } else if (SOC_STATE.sort === 'newest') {
        SOC_STATE.alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }
}

// --------------------------------------------------------------------------
// 2. Real-Time Host Telemetry Stream & WebSocket
// --------------------------------------------------------------------------
let threatSocket = null;

async function initThreatStream() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    let query = '';

    // Request short-lived single-use connection ticket to avoid exposing credentials in URLs
    try {
        const ticketResp = await fetch('/api/v1/auth/ws-ticket', {
            method: 'POST',
            headers: getApiHeaders()
        });
        if (ticketResp.ok) {
            const ticketData = await ticketResp.json();
            if (ticketData && ticketData.ticket) {
                query = `?ticket=${encodeURIComponent(ticketData.ticket)}`;
            }
        }
    } catch (e) {
        // Fall back to automatic cookie-based WebSocket handshake
    }

    const wsUrl = `${protocol}//${window.location.host}/ws/threats${query}`;

    const liveText = document.getElementById('live-sensor-text');

    try {
        threatSocket = new WebSocket(wsUrl);

        threatSocket.onopen = () => {
            // Decouple WebSocket connection from host monitoring status.
            // On open, query authoritative backend monitoring status.
            initStreamStatus();
        };

        threatSocket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.type === 'LIVE_THREAT' || data.type === 'REAL_THREAT') {
                    handleStreamThreat(data);
                } else if (data.type === 'HEARTBEAT' && data.host_info) {
                    const procCount = document.getElementById('host-process-count');
                    if (procCount && data.host_info.process_count) {
                        procCount.textContent = `${data.host_info.process_count} active`;
                    }
                    if (typeof data.host_info.monitoring_active === 'boolean') {
                        updateMonitoringUI({ host_monitoring_active: data.host_info.monitoring_active });
                    }
                }
            } catch (e) {
                console.warn('Malformed stream message:', e);
            }
        };

        threatSocket.onclose = (e) => {
            const pill = document.getElementById('live-sensor-pill');
            if (e.code === 1008) {
                if (pill) pill.title = 'Telemetry Stream: Authentication Required';
                return;
            }
            if (pill) pill.title = 'Telemetry Stream: Reconnecting...';
            setTimeout(initThreatStream, 4000);
        };

        threatSocket.onerror = () => {};

        // Keepalive ping every 25 seconds
        setInterval(() => {
            if (threatSocket && threatSocket.readyState === WebSocket.OPEN) {
                threatSocket.send('ping');
            }
        }, 25000);
    } catch (e) {
        console.log('WebSocket stream skipped (standalone mode).');
    }
}

function handleStreamThreat(payload) {
    const rawAlert = payload.alert;
    if (!rawAlert) return;

    // Check if alert already exists in memory by id
    const exists = SOC_STATE.alerts.some((a) => String(a.id) === String(rawAlert.id));
    if (exists) return;

    const formatted = formatAlertForClient(rawAlert);
    SOC_STATE.alerts.unshift(formatted);
    sortAlerts();

    // Auto-select if first alert or critical
    if (!SOC_STATE.selectedAlertId || formatted.severity === 'CRITICAL') {
        SOC_STATE.selectedAlertId = formatted.id;
    }

    renderAll();
    showToast(`🚨 Host Sensor: ${formatted.title.substring(0, 45)}...`);
}

// --------------------------------------------------------------------------
// 3. UI Interactions & Event Handlers
// --------------------------------------------------------------------------
function initEventHandlers() {
    // 1. Keyboard shortcut '/' focuses search input
    document.addEventListener('keydown', (e) => {
        if (e.key === '/' && !isInputActive() && !isModalOpen()) {
            e.preventDefault();
            const searchInput = document.getElementById('search-input');
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        } else if (e.key === 'Escape') {
            closeAllModals();
        }
    });

    // 2. Search Input
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            SOC_STATE.filters.search = e.target.value.trim().toLowerCase();
            updateFilteredQueue();
        });
    }

    // 3. Source filter dropdown
    const sourceSelect = document.getElementById('source-select');
    if (sourceSelect) {
        sourceSelect.addEventListener('change', (e) => {
            SOC_STATE.filters.source = e.target.value;
            updateFilteredQueue();
        });
    }

    // 4. Sort dropdown
    const sortSelect = document.getElementById('sort-select');
    if (sortSelect) {
        sortSelect.addEventListener('change', (e) => {
            SOC_STATE.sort = e.target.value;
            sortAlerts();
            updateFilteredQueue();
        });
    }

    // 5. Status filter pills
    document.querySelectorAll('.status-pill-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            const status = btn.getAttribute('data-status');
            setStatusFilter(status);
        });
    });

    // 6. Modal backdrop click-to-close
    document.querySelectorAll('.modal-backdrop').forEach((backdrop) => {
        backdrop.addEventListener('click', (e) => {
            if (e.target === backdrop) {
                closeAllModals();
            }
        });
    });
}

function isInputActive() {
    const active = document.activeElement;
    return active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA' || active.tagName === 'SELECT');
}

function isModalOpen() {
    return document.querySelector('.modal-backdrop.open') !== null;
}

// --------------------------------------------------------------------------
// 4. Filtering Logic
// --------------------------------------------------------------------------
function getMatchingAlerts() {
    return SOC_STATE.alerts.filter((alert) => {
        // 1. Severity filter
        if (SOC_STATE.filters.severity && alert.severity !== SOC_STATE.filters.severity) {
            return false;
        }

        // 2. Status filter
        const isReviewed = SOC_STATE.sessionReviewed.has(alert.id);
        if (SOC_STATE.filters.status === 'needs_review' && isReviewed) {
            return false;
        }
        if (SOC_STATE.filters.status === 'reviewed' && !isReviewed) {
            return false;
        }

        // 3. Source filter
        if (SOC_STATE.filters.source !== 'all') {
            const src = (alert.source_type || '').toLowerCase();
            const filterSrc = SOC_STATE.filters.source.toLowerCase();
            if (!src.includes(filterSrc)) {
                return false;
            }
        }

        // 4. Search query
        if (SOC_STATE.filters.search) {
            const q = SOC_STATE.filters.search;
            const titleMatch = (alert.title || '').toLowerCase().includes(q);
            const descMatch = (alert.what_happened || '').toLowerCase().includes(q);
            const srcIpMatch = (alert.source_ip || '').toLowerCase().includes(q);
            const dstIpMatch = (alert.destination_ip || '').toLowerCase().includes(q);
            const deviceMatch = (alert.device || '').toLowerCase().includes(q);
            const sourceMatch = (alert.source_type || '').toLowerCase().includes(q);
            const ruleMatch = (alert.rule_id || '').toLowerCase().includes(q);
            const mitreTech = alert.mitre && alert.mitre.technique.toLowerCase().includes(q);
            const mitreName = alert.mitre && alert.mitre.name.toLowerCase().includes(q);

            if (!titleMatch && !descMatch && !srcIpMatch && !dstIpMatch && !deviceMatch && !sourceMatch && !ruleMatch && !mitreTech && !mitreName) {
                return false;
            }
        }

        return true;
    });
}

function toggleSeverityFilter(sev) {
    if (SOC_STATE.filters.severity === sev) {
        SOC_STATE.filters.severity = null;
    } else {
        SOC_STATE.filters.severity = sev;
    }
    updateFilteredQueue();
}

function setStatusFilter(status) {
    SOC_STATE.filters.status = status;
    document.querySelectorAll('.status-pill-btn').forEach((btn) => {
        btn.classList.toggle('active', btn.getAttribute('data-status') === status);
    });
    updateFilteredQueue();
}

function clearAllFilters() {
    SOC_STATE.filters.severity = null;
    SOC_STATE.filters.status = 'all';
    SOC_STATE.filters.source = 'all';
    SOC_STATE.filters.search = '';

    const searchInput = document.getElementById('search-input');
    if (searchInput) searchInput.value = '';
    const sourceSelect = document.getElementById('source-select');
    if (sourceSelect) sourceSelect.value = 'all';

    document.querySelectorAll('.status-pill-btn').forEach((btn) => {
        btn.classList.toggle('active', btn.getAttribute('data-status') === 'all');
    });

    updateFilteredQueue();
    showToast('Filters cleared');
}

// --------------------------------------------------------------------------
// 5. Rendering Pipeline
// --------------------------------------------------------------------------
function renderAll() {
    renderSeverityCards();
    renderStatusPillCounts();
    renderQueueList();
    renderSelectedAlertDetails();
}

function updateFilteredQueue() {
    renderSeverityCards();
    renderStatusPillCounts();
    renderQueueList();

    const matching = getMatchingAlerts();
    if (matching.length > 0) {
        const stillMatches = matching.some((a) => a.id === SOC_STATE.selectedAlertId);
        if (!stillMatches) {
            SOC_STATE.selectedAlertId = matching[0].id;
            SOC_STATE.activeTab = 'overview';
        }
    } else {
        SOC_STATE.selectedAlertId = null;
    }

    renderSelectedAlertDetails();
}

/* 6.1 Severity Overview Cards */
function renderSeverityCards() {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const total = SOC_STATE.alerts.length || 1;

    SOC_STATE.alerts.forEach((alert) => {
        if (counts[alert.severity] !== undefined) {
            counts[alert.severity]++;
        }
    });

    ['critical', 'high', 'medium', 'low'].forEach((sev) => {
        const count = counts[sev.toUpperCase()];
        const countEl = document.getElementById(`count-${sev}`);
        const barEl = document.getElementById(`share-bar-${sev}`);
        const cardEl = document.getElementById(`card-${sev}`);

        if (countEl) countEl.textContent = count;
        if (barEl) {
            const pct = Math.round((count / total) * 100);
            barEl.style.width = `${pct}%`;
        }
        if (cardEl) {
            const isActive = SOC_STATE.filters.severity === sev.toUpperCase();
            cardEl.classList.toggle('active', isActive);
            cardEl.setAttribute('aria-pressed', isActive ? 'true' : 'false');
        }
    });
}

/* Status Pill Counts */
function renderStatusPillCounts() {
    const total = SOC_STATE.alerts.length;
    let reviewedCount = 0;
    SOC_STATE.alerts.forEach((a) => {
        if (SOC_STATE.sessionReviewed.has(a.id)) {
            reviewedCount++;
        }
    });
    const needsReviewCount = Math.max(0, total - reviewedCount);

    const countAllEl = document.getElementById('status-count-all');
    const countNeedsEl = document.getElementById('status-count-needs');
    const countRevEl = document.getElementById('status-count-reviewed');

    if (countAllEl) countAllEl.textContent = total;
    if (countNeedsEl) countNeedsEl.textContent = needsReviewCount;
    if (countRevEl) countRevEl.textContent = reviewedCount;
}

/* 6.2 Alert Queue */
function renderQueueList() {
    const container = document.getElementById('queue-list');
    const countDisplay = document.getElementById('queue-results-count');
    if (!container) return;

    const matching = getMatchingAlerts();
    const total = SOC_STATE.alerts.length;

    if (countDisplay) {
        countDisplay.innerHTML = `Showing <strong>${matching.length}</strong> of <strong>${total}</strong> alerts`;
    }

    if (matching.length === 0) {
        container.innerHTML = `
            <div class="queue-empty-state">
                <svg class="queue-empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <circle cx="11" cy="11" r="8"></circle>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
                <h4>No matching alerts found</h4>
                <p style="font-size: 0.8rem; color: var(--text-faint);">Try adjusting your search terms or clearing active filters.</p>
                <button class="btn btn-outline btn-sm" onclick="clearAllFilters()">Show all alerts</button>
            </div>
        `;
        return;
    }

    container.innerHTML = '';
    matching.forEach((alert) => {
        const isSelected = alert.id === SOC_STATE.selectedAlertId;
        const isReviewed = SOC_STATE.sessionReviewed.has(alert.id);
        const sevLower = (alert.severity || 'medium').toLowerCase();

        const row = document.createElement('div');
        row.className = `alert-row ${isSelected ? 'selected' : ''}`;
        row.setAttribute('data-id', alert.id);
        row.setAttribute('role', 'button');
        row.setAttribute('tabindex', '0');
        row.setAttribute('aria-pressed', isSelected ? 'true' : 'false');

        const timeStr = formatUtcTimestamp(alert.timestamp);

        row.innerHTML = `
            <div class="alert-row-top">
                <div class="alert-row-badges">
                    <span class="badge-sev badge-sev-${sevLower}">${alert.severity}</span>
                    <span class="score-badge">${alert.risk_score}</span>
                    ${isReviewed ? `<span class="reviewed-check-indicator">✓ Reviewed</span>` : ''}
                </div>
                <span class="alert-row-time">${timeStr}</span>
            </div>
            <div class="alert-row-title" title="${escapeHtml(alert.title)}">${escapeHtml(alert.title)}</div>
            <div class="alert-row-bottom">
                <span class="alert-row-source-tag">${escapeHtml(alert.source_type)}</span>
                <span class="alert-row-endpoint">${escapeHtml(alert.source_ip || alert.device || 'Host Native')}</span>
            </div>
        `;

        row.addEventListener('click', () => selectAlert(alert.id));
        row.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                selectAlert(alert.id);
            }
        });

        container.appendChild(row);
    });
}

async function selectAlert(alertId) {
    SOC_STATE.selectedAlertId = alertId;
    renderQueueList();
    renderSelectedAlertDetails();

    if (window.innerWidth <= 850) {
        const detailsPanel = document.getElementById('details-panel');
        if (detailsPanel) {
            detailsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    // Retrieve detailed backend triage playbook and MITRE guidance
    try {
        const resp = await apiFetch(`/api/v1/alerts/${alertId}`);
        if (resp && resp.ok) {
            const detailData = await resp.json();
            const alertObj = SOC_STATE.alerts.find((a) => a.id === alertId);
            if (alertObj && detailData.guidance) {
                if (detailData.guidance.what_happened) {
                    alertObj.what_happened = detailData.guidance.what_happened;
                }
                if (detailData.guidance.why_suspicious) {
                    alertObj.why_suspicious = detailData.guidance.why_suspicious;
                }
                if (detailData.guidance.recommended_actions && detailData.guidance.recommended_actions.length) {
                    alertObj.actions = detailData.guidance.recommended_actions;
                }
                if (detailData.mitre_details) {
                    alertObj.mitre = {
                        technique: detailData.mitre_details.technique_id,
                        name: detailData.mitre_details.name,
                        tactic: detailData.mitre_details.tactic,
                        description: detailData.mitre_details.description,
                        url: detailData.mitre_details.url
                    };
                }
                // Refresh panel if this alert is still currently selected
                if (SOC_STATE.selectedAlertId === alertId) {
                    renderSelectedAlertDetails();
                }
            }
        }
    } catch (e) {
        console.debug('Detailed guidance fetch skipped:', e);
    }
}

/* 6.3 Selected Alert Details */
function renderSelectedAlertDetails() {
    const panel = document.getElementById('details-panel');
    if (!panel) return;

    const alert = SOC_STATE.alerts.find((a) => a.id === SOC_STATE.selectedAlertId);
    if (!alert) {
        panel.innerHTML = `
            <div class="queue-empty-state" style="padding: 4rem 1.5rem;">
                <p>Select an alert from the queue to inspect details, evidence, and investigation steps.</p>
            </div>
        `;
        return;
    }

    const isReviewed = SOC_STATE.sessionReviewed.has(alert.id);
    const sevLower = (alert.severity || 'medium').toLowerCase();
    const timeStr = formatUtcTimestamp(alert.timestamp);

    panel.innerHTML = `
        <div class="detail-header">
            <div class="detail-header-top">
                <div class="detail-header-badges">
                    <span class="badge-sev badge-sev-${sevLower}">${alert.severity}</span>
                    <span class="rule-id-tag">ID ${escapeHtml(alert.rule_id || 'N/A')}</span>
                    ${isReviewed 
                        ? `<span class="status-indicator status-resolved">✓ Reviewed</span>` 
                        : `<span class="status-indicator status-open">Needs review</span>`
                    }
                </div>
                <button class="btn-review-toggle ${isReviewed ? 'btn-review-reopen' : 'btn-review-mark'}" onclick="toggleAlertReviewStatus('${alert.id}')">
                    ${isReviewed ? '↩ Reopen alert' : '✓ Mark as reviewed'}
                </button>
            </div>

            <h2 class="detail-title">${escapeHtml(alert.title)}</h2>

            <div class="detail-meta-row">
                <div class="detail-meta-item">
                    <span>Sensor:</span>
                    <span class="alert-row-source-tag">${escapeHtml(alert.source_type)}</span>
                </div>
                <div class="detail-meta-item">
                    <span>Observed:</span>
                    <span class="mono-val">${timeStr}</span>
                </div>
                <div class="detail-meta-item">
                    <span>Host:</span>
                    <span class="mono-val">${escapeHtml(alert.device || 'Host')}</span>
                </div>
            </div>
        </div>

        <!-- Detail Tabs Navigation -->
        <nav class="detail-tabs-nav" role="tablist" aria-label="Alert Details">
            <button class="detail-tab-btn" role="tab" id="tab-btn-overview" data-tab="overview" aria-selected="${SOC_STATE.activeTab === 'overview' ? 'true' : 'false'}" aria-controls="tab-overview" tabindex="${SOC_STATE.activeTab === 'overview' ? '0' : '-1'}">
                Overview
            </button>
            <button class="detail-tab-btn" role="tab" id="tab-btn-evidence" data-tab="evidence" aria-selected="${SOC_STATE.activeTab === 'evidence' ? 'true' : 'false'}" aria-controls="tab-evidence" tabindex="${SOC_STATE.activeTab === 'evidence' ? '0' : '-1'}">
                Evidence
            </button>
            <button class="detail-tab-btn" role="tab" id="tab-btn-raw" data-tab="raw" aria-selected="${SOC_STATE.activeTab === 'raw' ? 'true' : 'false'}" aria-controls="tab-raw" tabindex="${SOC_STATE.activeTab === 'raw' ? '0' : '-1'}">
                Raw JSON
            </button>
        </nav>

        <!-- Detail Body Panels -->
        <div class="detail-body">
            <!-- 1. Overview Tab -->
            <section class="tab-panel ${SOC_STATE.activeTab === 'overview' ? 'active' : ''}" id="tab-overview" role="tabpanel" aria-labelledby="tab-btn-overview">
                <!-- What happened? -->
                <div class="detail-section-card">
                    <h4>
                        <svg class="btn-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                        What happened?
                    </h4>
                    <p class="plain-explanation-text">${escapeHtml(alert.what_happened)}</p>
                    <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">${escapeHtml(alert.why_suspicious)}</p>
                </div>

                <!-- Priority Score Breakdown -->
                <div class="score-breakdown-box">
                    <div>
                        <div style="font-size: 0.72rem; font-weight: 700; text-transform: uppercase; color: var(--text-faint); margin-bottom: 2px;">
                            Calculated Priority Score
                        </div>
                        <div class="score-pill-large">
                            <span>${alert.risk_score}</span>
                            <small>/ 100</small>
                        </div>
                    </div>
                    <div class="score-explanation-text">
                        <div><strong>Triage Urgency:</strong> ${getSeverityGuidance(alert.severity)}</div>
                        <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-faint); margin-top: 2px;">
                            ${escapeHtml(alert.score_explanation || 'Host behavioral risk calculation')}
                        </div>
                    </div>
                </div>

                <!-- Observed Connection Endpoints -->
                <div class="detail-section-card">
                    <h4>
                        <svg class="btn-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                        Observed Connection Endpoints
                    </h4>
                    <div class="endpoints-grid">
                        <div class="endpoint-box">
                            <span class="endpoint-label">Source</span>
                            <span class="endpoint-val">${escapeHtml(alert.source_ip ? `${alert.source_ip}${alert.source_port ? ':' + alert.source_port : ''}` : 'Local Machine')}</span>
                            ${alert.username ? `<span style="font-size: 0.72rem; color: var(--text-faint);">Account: ${escapeHtml(alert.username)}</span>` : ''}
                        </div>
                        <div class="endpoint-box">
                            <span class="endpoint-label">Target / Destination</span>
                            <span class="endpoint-val">${escapeHtml(alert.destination_ip ? `${alert.destination_ip}${alert.destination_port ? ':' + alert.destination_port : ''}` : (alert.device || 'Host'))}</span>
                            ${alert.device ? `<span style="font-size: 0.72rem; color: var(--text-faint);">Host: ${escapeHtml(alert.device)}</span>` : ''}
                        </div>
                    </div>
                    <span class="endpoint-direction-note">
                        Endpoints describe connection direction recorded in telemetry, not confirmed attacker or victim status.
                    </span>
                </div>

                <!-- MITRE ATT&CK Reference -->
                ${renderMitrePanel(alert.mitre)}

                <!-- Recommended Next Actions (Checklist) -->
                ${renderChecklistCard(alert)}
            </section>

            <!-- 2. Evidence Tab -->
            <section class="tab-panel ${SOC_STATE.activeTab === 'evidence' ? 'active' : ''}" id="tab-evidence" role="tabpanel" aria-labelledby="tab-btn-evidence">
                <div class="detail-section-card">
                    <h4>Observed Telemetry Facts</h4>
                    <table class="evidence-table">
                        <tbody>
                            <tr><td>Event Type</td><td>${escapeHtml(alert.event_type || 'alert')}</td></tr>
                            <tr><td>Sensor / Tool</td><td>${escapeHtml(alert.source_type)}</td></tr>
                            <tr><td>Alert ID</td><td>${escapeHtml(alert.rule_id || alert.id || 'N/A')}</td></tr>
                            <tr><td>Assigned Severity</td><td>${escapeHtml(alert.severity)}</td></tr>
                            <tr><td>Host / Device</td><td>${escapeHtml(alert.device || 'Host')}</td></tr>
                            <tr><td>Account Involved</td><td>${escapeHtml(alert.username || 'System')}</td></tr>
                            <tr><td>Timestamp (UTC)</td><td>${timeStr}</td></tr>
                        </tbody>
                    </table>
                </div>

                <div class="detail-section-card">
                    <h4>Host Behavioral Scoring</h4>
                    <p style="font-size: 0.82rem; color: var(--text-muted); line-height: 1.5;">
                        Scores are calculated transparently to prioritize immediate investigation:
                    </p>
                    <code style="display: block; background: var(--bg-input); padding: 0.5rem; border-radius: 4px; font-size: 0.76rem; margin-top: 0.4rem;">
                        ${escapeHtml(alert.score_explanation || 'Rule level and burst frequency calculation')}
                    </code>
                </div>

                <div class="limitations-box">
                    <span>🛡️</span>
                    <div>
                        <strong>Host EDR Posture:</strong> This sensor continuously analyzes local processes and sockets. Findings indicate detections requiring triage, not confirmed intrusions.
                    </div>
                </div>
            </section>

            <!-- 3. Raw JSON Tab -->
            <section class="tab-panel ${SOC_STATE.activeTab === 'raw' ? 'active' : ''}" id="tab-raw" role="tabpanel" aria-labelledby="tab-btn-raw">
                <div class="raw-json-container">
                    <div class="raw-json-actions">
                        <button class="btn btn-outline btn-copy-json" onclick="copyAlertJson('${alert.id}')">
                            📋 Copy JSON
                        </button>
                    </div>
                    <pre class="json-code-block"><code>${escapeHtml(typeof alert.raw_log === 'object' ? JSON.stringify(alert.raw_log, null, 2) : String(alert.raw_log || JSON.stringify(alert, null, 2)))}</code></pre>
                </div>
            </section>
        </div>
    `;

    // Reattach tab click handlers
    panel.querySelectorAll('.detail-tab-btn').forEach((btn) => {
        btn.addEventListener('click', () => switchDetailTab(btn.getAttribute('data-tab')));
    });

    // Attach checklist listeners
    attachChecklistListeners(alert.id);
}

function renderMitrePanel(mitre) {
    if (!mitre) {
        return `
            <div class="detail-section-card" style="border-style: dashed;">
                <div style="font-size: 0.8rem; color: var(--text-faint);">
                    <strong>MITRE ATT&CK:</strong> No technique mapped in this telemetry record. Many routine system events do not correspond to specific adversary techniques.
                </div>
            </div>
        `;
    }

    return `
        <div class="mitre-panel">
            <div class="mitre-panel-header">
                <span class="mitre-header-title">MITRE ATT&CK Reference</span>
                <span class="mitre-unverified-tag">From event · unverified</span>
            </div>
            <div class="mitre-technique-row">
                <span class="mitre-technique-name">${escapeHtml(mitre.technique)}: ${escapeHtml(mitre.name)}</span>
                <a href="${sanitizeUrl(mitre.url)}" target="_blank" rel="noopener noreferrer" class="mitre-link">
                    Open Framework Reference ↗
                </a>
            </div>
            <div class="mitre-tactic-desc">
                <strong>Tactic:</strong> ${escapeHtml(mitre.tactic)} • Technique mapped from detection metadata for educational context.
            </div>
        </div>
    `;
}

function renderChecklistCard(alert) {
    const checkedIndices = SOC_STATE.checklistProgress[alert.id] || [];
    const actions = alert.actions || [
        'Verify process name and execution path',
        'Check network connectivity and remote endpoint',
        'Review recent user and administrative actions'
    ];
    const totalSteps = actions.length;
    const completedCount = checkedIndices.length;

    let itemsHtml = '';
    actions.forEach((action, idx) => {
        const isChecked = checkedIndices.includes(idx);
        itemsHtml += `
            <li class="checklist-item ${isChecked ? 'checked' : ''}" data-index="${idx}">
                <input type="checkbox" id="step-${alert.id}-${idx}" ${isChecked ? 'checked' : ''} aria-label="${escapeHtml(action)}">
                <span>${escapeHtml(action)}</span>
            </li>
        `;
    });

    return `
        <div class="checklist-card">
            <div class="checklist-header">
                <h4>Practical Investigation Steps</h4>
                <span class="checklist-progress-text" id="checklist-progress-${alert.id}">
                    ${completedCount} of ${totalSteps} steps completed
                </span>
            </div>
            <ul class="checklist-items" id="checklist-ul-${alert.id}">
                ${itemsHtml}
            </ul>
        </div>
    `;
}

function attachChecklistListeners(alertId) {
    const ul = document.getElementById(`checklist-ul-${alertId}`);
    if (!ul) return;

    ul.querySelectorAll('.checklist-item').forEach((item) => {
        const checkbox = item.querySelector('input[type="checkbox"]');
        const index = parseInt(item.getAttribute('data-index'), 10);

        checkbox.addEventListener('change', () => {
            let checked = SOC_STATE.checklistProgress[alertId] || [];
            if (checkbox.checked) {
                if (!checked.includes(index)) checked.push(index);
                item.classList.add('checked');
            } else {
                checked = checked.filter((i) => i !== index);
                item.classList.remove('checked');
            }
            SOC_STATE.checklistProgress[alertId] = checked;
            saveSessionStorage();

            const alert = SOC_STATE.alerts.find((a) => a.id === alertId);
            const totalSteps = alert && alert.actions ? alert.actions.length : 3;
            const progressEl = document.getElementById(`checklist-progress-${alertId}`);
            if (progressEl) {
                progressEl.textContent = `${checked.length} of ${totalSteps} steps completed`;
            }
        });
    });
}

function switchDetailTab(tabName) {
    SOC_STATE.activeTab = tabName;
    document.querySelectorAll('.detail-tab-btn').forEach((btn) => {
        const isSelected = btn.getAttribute('data-tab') === tabName;
        btn.setAttribute('aria-selected', isSelected ? 'true' : 'false');
        btn.setAttribute('tabindex', isSelected ? '0' : '-1');
    });

    document.querySelectorAll('.tab-panel').forEach((panel) => {
        panel.classList.toggle('active', panel.id === `tab-${tabName}`);
    });
}

async function toggleAlertReviewStatus(alertId) {
    const isCurrentlyReviewed = SOC_STATE.sessionReviewed.has(alertId);
    const newStatus = isCurrentlyReviewed ? 'OPEN' : 'RESOLVED';

    if (isCurrentlyReviewed) {
        SOC_STATE.sessionReviewed.delete(alertId);
        showToast('Alert reopened');
    } else {
        SOC_STATE.sessionReviewed.add(alertId);
        showToast('Alert marked as reviewed');
    }
    saveSessionStorage();

    // Persist status change to local SQLite backend
    try {
        await fetch(`/api/v1/alerts/${alertId}/status`, {
            method: 'PATCH',
            headers: getApiHeaders({ 'Content-Type': 'application/json' }),
            body: JSON.stringify({ status: newStatus })
        });
    } catch (e) {
        console.warn('Could not persist status change to server:', e);
    }

    renderAll();
}

// --------------------------------------------------------------------------
// 6. Host Operations (Scan, Drill, Clear, Toggle Sensor)
// --------------------------------------------------------------------------
async function runHostAudit() {
    showToast('Running comprehensive host security audit...');
    try {
        const resp = await fetch('/api/v1/host/audit', {
            method: 'POST',
            headers: getApiHeaders()
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(`Audit completed: ${data.findings_count || data.alerts_created || 0} host findings recorded.`);
            // Fetch updated alerts
            await fetchAlertsFromApi();
        } else if (resp.status === 401) {
            showToast('Analyst clearance is required to run host audits. Please sign in with your access key.');
            openAuthModal();
        } else if (resp.status === 403) {
            showToast('Your current role does not have permission to run host audits.');
        } else {
            showToast(data.detail || 'Unable to complete host audit.');
        }
    } catch (e) {
        showToast('Host audit dispatched.');
    }
}

async function runTestDrill() {
    showToast('Triggering test security drill...');
    try {
        const resp = await fetch('/api/v1/host/drill', {
            method: 'POST',
            headers: getApiHeaders()
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast('Test drill injected successfully.');
            await fetchAlertsFromApi();
        } else if (resp.status === 401) {
            showToast('Analyst clearance is required to launch test drills. Please sign in.');
            openAuthModal();
        } else if (resp.status === 403) {
            showToast('Your current role does not have permission to launch test drills.');
        } else {
            showToast(data.detail || 'Test drill could not be started.');
        }
    } catch (e) {
        showToast('Drill request dispatched.');
    }
}

async function clearAllAlerts() {
    if (!confirm('Clear historical alerts and re-scan host for active findings?')) return;
    showToast('Clearing alert history...');
    try {
        const resp = await fetch('/api/v1/alerts/clear', {
            method: 'POST',
            headers: getApiHeaders()
        });
        const data = await resp.json();
        if (resp.ok) {
            SOC_STATE.sessionReviewed.clear();
            SOC_STATE.checklistProgress = {};
            saveSessionStorage();
            showToast(data.message || 'Alert history cleared and re-scanned.');
            await fetchAlertsFromApi();
        } else if (resp.status === 401) {
            showToast('Administrator clearance is required to clear alert records. Please sign in.');
            openAuthModal();
        } else if (resp.status === 403) {
            showToast('Administrator permissions required to purge alert history.');
        } else {
            showToast(data.detail || 'Permission denied.');
        }
    } catch (e) {
        showToast('Clear request dispatched.');
    }
}

function updateMonitoringUI(state) {
    if (typeof state === 'string') {
        SOC_STATE.monitoringState = state.toUpperCase();
        if (SOC_STATE.monitoringState === 'ACTIVE') {
            SOC_STATE.isHostMonitoringActive = true;
        } else if (SOC_STATE.monitoringState === 'PAUSED') {
            SOC_STATE.isHostMonitoringActive = false;
        }
    } else if (state && typeof state === 'object') {
        if (typeof state.host_monitoring_active === 'boolean') {
            SOC_STATE.isHostMonitoringActive = state.host_monitoring_active;
            SOC_STATE.monitoringState = state.host_monitoring_active ? 'ACTIVE' : 'PAUSED';
        }
        if (typeof state.simulation_active === 'boolean') {
            SOC_STATE.isSimulationActive = state.simulation_active;
        }
        if (state.monitoring_state) {
            SOC_STATE.monitoringState = String(state.monitoring_state).toUpperCase();
        }
    }

    const mState = SOC_STATE.monitoringState || 'CHECKING';
    const isHostActive = mState === 'ACTIVE';
    const isHostPaused = mState === 'PAUSED';
    const isSimActive = !!SOC_STATE.isSimulationActive;

    // 1. Header Live Sensor Pill & Pulse Dot
    const livePill = document.getElementById('live-sensor-pill');
    const liveText = document.getElementById('live-sensor-text');
    const pulseDots = livePill ? livePill.querySelectorAll('.pulse-dot') : [];

    if (livePill) {
        livePill.classList.remove('active', 'paused', 'checking', 'unknown', 'error');
        if (isHostActive) {
            livePill.classList.add('active');
            livePill.title = 'Native Host Security Sensor & Live Telemetry: ACTIVE';
        } else if (isHostPaused) {
            livePill.classList.add('paused');
            livePill.title = 'Native Host Security Sensor: PAUSED (Historical data preserved)';
        } else if (mState === 'CHECKING' || mState === 'PAUSING' || mState === 'RESUMING') {
            livePill.classList.add('checking');
            livePill.title = `Native Host Security Sensor: ${mState}...`;
        } else {
            livePill.classList.add('unknown');
            livePill.title = 'Native Host Security Sensor: Status unknown or backend unreachable';
        }
    }

    pulseDots.forEach(dot => {
        dot.classList.remove('active', 'paused', 'checking', 'unknown', 'error');
        if (isHostActive) {
            // Active state uses pulse animation
        } else if (isHostPaused) {
            dot.classList.add('paused');
        } else if (mState === 'CHECKING' || mState === 'PAUSING' || mState === 'RESUMING') {
            dot.classList.add('checking');
        } else {
            dot.classList.add('unknown');
        }
    });

    if (liveText) {
        if (isHostActive) {
            liveText.textContent = 'HOST SENSOR: ACTIVE';
        } else if (isHostPaused) {
            liveText.textContent = 'HOST SENSOR: PAUSED';
        } else if (mState === 'PAUSING') {
            liveText.textContent = 'HOST SENSOR: PAUSING...';
        } else if (mState === 'RESUMING') {
            liveText.textContent = 'HOST SENSOR: RESUMING...';
        } else if (mState === 'CHECKING') {
            liveText.textContent = 'HOST SENSOR: CHECKING';
        } else {
            liveText.textContent = 'HOST SENSOR: STATUS UNKNOWN';
        }
    }

    // 2. Action Toolbar Host Sensor Toggle Button
    const btnHost = document.getElementById('btn-toggle-host-monitor');
    if (btnHost) {
        btnHost.classList.remove('btn-outline', 'btn-secondary');
        if (isHostActive) {
            btnHost.textContent = '⚡ Host Sensor: ACTIVE';
            btnHost.title = 'Pause continuous host security sensor';
            btnHost.classList.add('btn-outline');
            btnHost.disabled = false;
        } else if (isHostPaused) {
            btnHost.textContent = '⏸️ Host Sensor: PAUSED';
            btnHost.title = 'Resume continuous host security sensor';
            btnHost.classList.add('btn-secondary');
            btnHost.disabled = false;
        } else if (mState === 'PAUSING') {
            btnHost.textContent = '⏳ Host Sensor: PAUSING...';
            btnHost.title = 'Pausing host sensor...';
            btnHost.classList.add('btn-secondary');
            btnHost.disabled = true;
        } else if (mState === 'RESUMING') {
            btnHost.textContent = '⏳ Host Sensor: RESUMING...';
            btnHost.title = 'Resuming host sensor...';
            btnHost.classList.add('btn-outline');
            btnHost.disabled = true;
        } else if (mState === 'CHECKING') {
            btnHost.textContent = '⏳ Host Sensor: CHECKING...';
            btnHost.title = 'Querying sensor status...';
            btnHost.classList.add('btn-secondary');
            btnHost.disabled = true;
        } else {
            btnHost.textContent = '⚠️ Host Sensor: STATUS UNKNOWN';
            btnHost.title = 'Unable to determine sensor status';
            btnHost.classList.add('btn-secondary');
            btnHost.disabled = false;
        }
    }

    // 3. Action Toolbar Simulation Toggle Button
    const btnSim = document.getElementById('btn-toggle-sim');
    if (btnSim) {
        btnSim.textContent = isSimActive ? '🎮 Simulation: ACTIVE' : '⏸️ Simulation: PAUSED';
        btnSim.title = isSimActive ? 'Pause synthetic threat simulation stream' : 'Resume synthetic threat simulation stream';
        btnSim.classList.toggle('btn-outline', isSimActive);
        btnSim.classList.toggle('btn-secondary', !isSimActive);
    }

    // 4. Data Notice Strip
    const noticeText = document.getElementById('data-notice-text');
    const noticeTag = document.getElementById('data-notice-tag');
    if (noticeText) {
        if (isHostActive) {
            noticeText.textContent = 'Host EDR: Monitoring local machine processes, sockets & telemetry in real time';
        } else if (isHostPaused) {
            noticeText.textContent = 'Host EDR: Continuous monitoring is paused. Historical alerts retained.';
        } else if (mState === 'CHECKING') {
            noticeText.textContent = 'Host EDR: Checking sensor status...';
        } else {
            noticeText.textContent = 'Host EDR: Unable to determine sensor status (backend unreachable)';
        }
    }
    if (noticeTag) {
        noticeTag.classList.remove('active', 'paused', 'checking', 'unknown');
        if (isHostActive) {
            noticeTag.textContent = 'Live Sensor';
            noticeTag.classList.add('active');
        } else if (isHostPaused) {
            noticeTag.textContent = 'Sensor Paused';
            noticeTag.classList.add('paused');
        } else if (mState === 'CHECKING' || mState === 'PAUSING' || mState === 'RESUMING') {
            noticeTag.textContent = 'Checking';
            noticeTag.classList.add('checking');
        } else {
            noticeTag.textContent = 'Status Unknown';
            noticeTag.classList.add('unknown');
        }
    }

    // 5. Host Telemetry Strip Mode Label
    const modeLabel = document.getElementById('host-edr-mode-label');
    if (modeLabel) {
        if (isHostActive) {
            modeLabel.textContent = 'Native Host EDR Active';
            if (modeLabel.parentElement) modeLabel.parentElement.style.color = 'var(--accent-mint)';
        } else if (isHostPaused) {
            modeLabel.textContent = 'Native Host EDR Paused';
            if (modeLabel.parentElement) modeLabel.parentElement.style.color = 'var(--text-muted)';
        } else {
            modeLabel.textContent = 'Native Host EDR: Checking...';
            if (modeLabel.parentElement) modeLabel.parentElement.style.color = 'var(--text-faint)';
        }
    }
}

// Backward compatibility alias
function updateControlButtons() {
    updateMonitoringUI();
}

async function initStreamStatus() {
    try {
        const resp = await fetch('/api/v1/stream/status');
        if (resp.ok) {
            const data = await resp.json();
            updateMonitoringUI(data);
        } else {
            updateMonitoringUI('UNKNOWN');
        }
    } catch (e) {
        updateMonitoringUI('UNKNOWN');
    }
}

async function toggleHostMonitoring() {
    if (SOC_STATE.monitoringState === 'PAUSING' || SOC_STATE.monitoringState === 'RESUMING' || SOC_STATE.monitoringState === 'CHECKING') {
        return; // Prevent duplicate concurrent requests
    }

    const currentlyActive = SOC_STATE.monitoringState === 'ACTIVE';
    const targetState = !currentlyActive;
    updateMonitoringUI(targetState ? 'RESUMING' : 'PAUSING');

    try {
        const resp = await fetch(`/api/v1/host/monitor/toggle?active=${targetState}`, {
            method: 'POST',
            headers: getApiHeaders()
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            showToast(`Failed to update host sensor: ${err.detail || resp.statusText}`);
            await initStreamStatus();
            return;
        }
        const data = await resp.json();
        updateMonitoringUI(data);
        if (data.persisted === false) {
            showToast(targetState ? 'Host sensor active (Warning: preference save failed)' : 'Host sensor paused (Warning: preference save failed)');
        } else {
            showToast(targetState ? 'Host sensor active' : 'Host sensor paused');
        }
    } catch (e) {
        showToast('Network error updating host sensor status');
        await initStreamStatus();
    }
}

async function toggleSimulation() {
    const btnSim = document.getElementById('btn-toggle-sim');
    if (btnSim) btnSim.disabled = true;

    const targetState = !SOC_STATE.isSimulationActive;
    try {
        const resp = await fetch(`/api/v1/simulation/toggle?active=${targetState}`, {
            method: 'POST',
            headers: getApiHeaders()
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            showToast(`Failed to update simulation: ${err.detail || resp.statusText}`);
            return;
        }
        const data = await resp.json();
        updateMonitoringUI(data);
        showToast(SOC_STATE.isSimulationActive ? 'Demonstration simulation active' : 'Demonstration simulation paused');
    } catch (e) {
        showToast('Network error updating simulation status');
    } finally {
        if (btnSim) btnSim.disabled = false;
    }
}

// Re-synchronize authoritative status when tab/window gains focus
window.addEventListener('focus', () => {
    initStreamStatus();
});

// --------------------------------------------------------------------------
// 7. Alert Playground Modal (Curated Samples & Custom Ingest)
// --------------------------------------------------------------------------
function openPlaygroundModal() {
    const backdrop = document.getElementById('playground-modal');
    if (backdrop) {
        backdrop.classList.add('open');
        loadPlaygroundSample('mixed');
        const textarea = document.getElementById('playground-json-editor');
        if (textarea) textarea.focus();
    }
}

function loadPlaygroundSample(sampleType) {
    const textarea = document.getElementById('playground-json-editor');
    if (!textarea) return;

    let sampleData = [];
    if (sampleType === 'mixed' || sampleType === 'wazuh') {
        sampleData = [
            {
                "timestamp": new Date().toISOString(),
                "rule": { "level": 13, "description": "sshd: Multiple failed SSH login attempts from same source", "id": "5710", "groups": ["authentication_failed"] },
                "agent": { "id": "001", "name": "ubuntu-server", "ip": "192.168.1.10" },
                "data": { "srcip": "192.168.1.45", "dstuser": "root", "srcport": 54321, "attempt_count": 37 }
            },
            {
                "timestamp": new Date().toISOString(),
                "rule": { "level": 12, "description": "Rootcheck: Hidden process or suspicious kernel rootkit detected", "id": "510", "groups": ["rootcheck"] },
                "agent": { "id": "001", "name": "ubuntu-server", "ip": "192.168.1.10" },
                "full_log": "Rootcheck anomaly: process ID 3144 hidden from /proc filesystem"
            }
        ];
    }
    if (sampleType === 'mixed' || sampleType === 'suricata') {
        sampleData.push({
            "timestamp": new Date().toISOString(),
            "event_type": "alert",
            "src_ip": "198.51.100.22",
            "src_port": 44125,
            "dest_ip": "192.168.1.10",
            "dest_port": 8080,
            "proto": "TCP",
            "alert": { "action": "allowed", "gid": 1, "signature_id": 2018444, "rev": 2, "signature": "ET EXPLOIT Apache Struts Remote Code Execution Vulnerability CVE-2017-5638", "category": "Attempted Administrator Privilege Gain", "severity": 1 }
        });
    }

    textarea.value = JSON.stringify(sampleData, null, 2);
    hidePlaygroundError();
}

function handlePlaygroundFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (file.size > 2 * 1024 * 1024) {
        showPlaygroundError('File exceeds the 2 MB maximum size limit.');
        return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
        const textarea = document.getElementById('playground-json-editor');
        if (textarea) {
            textarea.value = e.target.result;
            hidePlaygroundError();
        }
    };
    reader.onerror = () => showPlaygroundError('Unable to read uploaded file.');
    reader.readAsText(file);
}

async function parsePlaygroundData() {
    const textarea = document.getElementById('playground-json-editor');
    if (!textarea) return;

    const raw = textarea.value.trim();
    if (!raw) {
        showPlaygroundError('Please provide JSON array, JSON object, or JSONL records to parse.');
        return;
    }

    try {
        // Upload to server using Blob so alerts persist in database
        const blob = new Blob([raw], { type: 'application/json' });
        const formData = new FormData();
        formData.append('file', blob, 'playground_import.json');
        formData.append('source_type', 'auto');

        const resp = await fetch('/api/v1/alerts/upload', {
            method: 'POST',
            headers: getApiHeaders(),
            body: formData
        });
        const data = await resp.json();

        if (resp.ok) {
            closeAllModals();
            showToast(`Imported ${data.alerts_count} alerts!`);
            await fetchAlertsFromApi();
        } else if (resp.status === 401) {
            showPlaygroundError('Analyst clearance is required to import security logs. Please sign in with your access key.');
            showToast('Analyst access required to import log files.');
        } else if (resp.status === 403) {
            showPlaygroundError('Your current role does not have permission to import logs.');
        } else {
            showPlaygroundError(data.detail || 'Upload failed.');
        }
    } catch (err) {
        showPlaygroundError(`Parsing failed: ${err.message}`);
    }
}

function showPlaygroundError(msg) {
    const errorEl = document.getElementById('playground-error-banner');
    if (errorEl) {
        errorEl.textContent = msg;
        errorEl.classList.add('visible');
    }
}

function hidePlaygroundError() {
    const errorEl = document.getElementById('playground-error-banner');
    if (errorEl) {
        errorEl.classList.remove('visible');
        errorEl.textContent = '';
    }
}

// --------------------------------------------------------------------------
// 8. Help Dialog & Modals
// --------------------------------------------------------------------------
function openHelpModal() {
    const backdrop = document.getElementById('help-modal');
    if (backdrop) backdrop.classList.add('open');
}

function openAuthModal() {
    const modal = document.getElementById('auth-modal');
    if (modal) {
        modal.classList.add('open');
        modal.style.display = 'flex';
        const feedback = document.getElementById('auth-feedback-banner');
        if (feedback) feedback.style.display = 'none';
        checkAuthStatus();
        setTimeout(() => {
            const input = document.getElementById('auth-key-input');
            if (input) input.focus();
        }, 120);
    }
}

function closeAuthModal() {
    const modal = document.getElementById('auth-modal');
    if (modal) {
        modal.classList.remove('open');
        setTimeout(() => { modal.style.display = 'none'; }, 150);
    }
}

function toggleAuthKeyVisibility() {
    const input = document.getElementById('auth-key-input');
    const icon = document.getElementById('eye-icon');
    if (!input) return;
    if (input.type === 'password') {
        input.type = 'text';
        if (icon) {
            icon.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>';
        }
    } else {
        input.type = 'password';
        if (icon) {
            icon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
        }
    }
}

async function checkAuthStatus() {
    const roleBadge = document.getElementById('auth-role-badge');
    const userDesc = document.getElementById('auth-user-desc');
    const permTriage = document.getElementById('perm-triage');
    const permAdmin = document.getElementById('perm-admin');
    const btnLogout = document.getElementById('btn-auth-logout');
    const btnSubmit = document.getElementById('btn-auth-submit');
    const headerBtn = document.getElementById('header-auth-btn');
    const headerLabel = document.getElementById('header-auth-label');

    try {
        const resp = await apiFetch('/api/v1/auth/me');
        if (resp && resp.ok) {
            const data = await resp.json();
            const role = data.role || 'VIEWER';
            const isAuth = Boolean(data.authenticated);

            if (data.csrf_token) {
                SOC_STATE.csrfToken = data.csrf_token;
            }

            if (headerLabel) {
                headerLabel.textContent = `Role: ${role.charAt(0) + role.slice(1).toLowerCase()}`;
            }
            if (headerBtn) {
                headerBtn.className = 'btn-header-auth';
                if (role === 'ADMIN') headerBtn.classList.add('role-admin');
                else if (role === 'ANALYST') headerBtn.classList.add('role-analyst');
            }

            if (roleBadge) {
                roleBadge.textContent = role;
                roleBadge.className = `auth-role-pill ${role.toLowerCase()}`;
            }

            if (userDesc) {
                if (role === 'ADMIN') {
                    userDesc.textContent = `Authenticated as Administrator (${data.username}). Full administrative control including alert purging, system configuration, and audit management.`;
                } else if (role === 'ANALYST') {
                    userDesc.textContent = `Authenticated as Cybersecurity Analyst (${data.username}). Authorized for log ingestion, alert triage, incident updates, and simulation drills.`;
                } else {
                    userDesc.textContent = `Currently operating in unauthenticated guest mode. Read-only inspection of dashboards, alerts, and incidents is permitted.`;
                }
            }

            if (permTriage) {
                if (role === 'ADMIN' || role === 'ANALYST') {
                    permTriage.className = 'auth-perm-item active';
                    permTriage.innerHTML = '<span>✓</span> Triage / Upload';
                } else {
                    permTriage.className = 'auth-perm-item';
                    permTriage.innerHTML = '<span>—</span> Triage / Upload';
                }
            }

            if (permAdmin) {
                if (role === 'ADMIN') {
                    permAdmin.className = 'auth-perm-item active';
                    permAdmin.innerHTML = '<span>✓</span> Purge / Delete';
                } else {
                    permAdmin.className = 'auth-perm-item';
                    permAdmin.innerHTML = '<span>—</span> Purge / Delete';
                }
            }

            if (btnLogout) {
                btnLogout.style.display = isAuth ? 'inline-flex' : 'none';
            }
            if (btnSubmit) {
                btnSubmit.textContent = isAuth ? 'Switch Key' : 'Sign In';
            }
        }
    } catch (e) {
        if (headerLabel) headerLabel.textContent = 'Role: Offline';
    }
}

async function submitAuthKey() {
    const input = document.getElementById('auth-key-input');
    const feedback = document.getElementById('auth-feedback-banner');
    const btnSubmit = document.getElementById('btn-auth-submit');
    const key = input ? input.value.trim() : '';

    if (!key) {
        if (feedback) {
            feedback.className = 'auth-feedback-banner error';
            feedback.innerHTML = '⚠️ Please enter your security access key.';
            feedback.style.display = 'flex';
        }
        showToast('Please enter your security access key.');
        return;
    }

    if (btnSubmit) {
        btnSubmit.disabled = true;
        btnSubmit.textContent = 'Verifying key...';
    }

    try {
        const resp = await fetch('/api/v1/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ api_key: key })
        });

        if (resp.ok) {
            const data = await resp.json();
            if (data.csrf_token) {
                SOC_STATE.csrfToken = data.csrf_token;
            }
            sessionStorage.removeItem('soc_api_key');
            localStorage.removeItem('soc_api_key');

            if (feedback) {
                feedback.className = 'auth-feedback-banner success';
                feedback.innerHTML = `✅ Signed in successfully as <strong>${data.role}</strong> (${data.username}).`;
                feedback.style.display = 'flex';
            }
            showToast(`Signed in successfully as ${data.role}.`);
            if (input) input.value = '';
            await checkAuthStatus();
            if (typeof initThreatStream === 'function') initThreatStream();
            setTimeout(() => {
                closeAuthModal();
            }, 750);
        } else {
            const err = await resp.json().catch(() => ({}));
            const msg = err.detail || 'Access key not recognized. Please check your credentials.';
            if (feedback) {
                feedback.className = 'auth-feedback-banner error';
                feedback.innerHTML = `❌ ${escapeHtml(msg)}`;
                feedback.style.display = 'flex';
            }
            showToast(`Sign in failed: ${msg}`);
        }
    } catch (e) {
        if (feedback) {
            feedback.className = 'auth-feedback-banner error';
            feedback.innerHTML = `❌ Network connection failed: ${escapeHtml(e.message)}`;
            feedback.style.display = 'flex';
        }
        showToast(`Connection error: ${e.message}`);
    } finally {
        if (btnSubmit) {
            btnSubmit.disabled = false;
            btnSubmit.textContent = 'Sign In';
        }
    }
}

async function clearAuthKey() {
    const headers = getApiHeaders();
    try {
        await fetch('/api/v1/auth/logout', {
            method: 'POST',
            credentials: 'same-origin',
            headers: headers
        });
    } catch (e) {}
    SOC_STATE.csrfToken = null;
    showToast('Signed out of session.');
    await checkAuthStatus();
    closeAuthModal();
}

function closeAllModals() {
    document.querySelectorAll('.modal-backdrop, .modal-dialog-backdrop').forEach((m) => {
        m.classList.remove('open');
        m.style.display = 'none';
    });
}

function resetDemo() {
    if (!confirm('Reset dashboard view and re-audit host?')) return;
    SOC_STATE.sessionReviewed.clear();
    SOC_STATE.checklistProgress = {};
    saveSessionStorage();
    clearAllFilters();
    runHostAudit();
}

// --------------------------------------------------------------------------
// 9. Utilities & Clipboard
// --------------------------------------------------------------------------
function copyAlertJson(alertId) {
    const alert = SOC_STATE.alerts.find((a) => a.id === alertId);
    if (!alert) return;

    const text = typeof alert.raw_log === 'object' ? JSON.stringify(alert.raw_log, null, 2) : String(alert.raw_log || JSON.stringify(alert, null, 2));
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text)
            .then(() => showToast('Event JSON copied to clipboard'))
            .catch(() => prompt('Copy event JSON manually:', text));
    } else {
        prompt('Copy event JSON manually:', text);
    }
}

function showToast(message) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    let icon = '🛡️';
    let cleanMessage = (message || '').trim();
    // Detect and extract any leading emoji so it never doubles with the shield icon
    const emojiMatch = cleanMessage.match(/^(\p{Extended_Pictographic}+|\p{Emoji_Presentation}+)\s*/u);
    if (emojiMatch) {
        icon = emojiMatch[1];
        cleanMessage = cleanMessage.slice(emojiMatch[0].length);
    }

    const toast = document.createElement('div');
    toast.className = 'toast-message';
    toast.setAttribute('role', 'status');
    toast.setAttribute('aria-live', 'polite');
    toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(cleanMessage)}</span>`;

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('toast-fading');
        setTimeout(() => toast.remove(), 250);
    }, 4200);
}

function formatUtcTimestamp(isoStr) {
    if (!isoStr) return 'N/A';
    try {
        const d = new Date(isoStr);
        if (isNaN(d.getTime())) return isoStr;
        return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    } catch (e) {
        return isoStr;
    }
}

function getSeverityGuidance(sev) {
    switch (sev) {
        case 'CRITICAL': return 'Investigate first (Risk score 75–100)';
        case 'HIGH': return 'Review promptly (Risk score 50–74)';
        case 'MEDIUM': return 'Check the context (Risk score 25–49)';
        case 'LOW': return 'Usually routine (Risk score 0–24)';
        default: return 'Review alert context';
    }
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function sanitizeUrl(url) {
    if (!url) return '#';
    const trimmed = String(url).trim();
    if (/^https?:\/\//i.test(trimmed)) {
        return escapeHtml(trimmed);
    }
    return '#';
}

