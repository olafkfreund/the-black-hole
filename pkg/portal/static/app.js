// MCP API Gateway - Portal Frontend Logic

// Global fetch interceptor to handle expired sessions (e.g. on server restart)
const originalFetch = window.fetch;
window.fetch = async function(...args) {
    const res = await originalFetch(...args);
    if (res.status === 401 && !args[0].includes('/api/auth/login')) {
        localStorage.removeItem('mcp_gateway_token');
        localStorage.removeItem('mcp_gateway_username');
        window.location.reload();
    }
    return res;
};

const STATE = {
    token: localStorage.getItem('mcp_gateway_token') || '',
    username: localStorage.getItem('mcp_gateway_username') || '',
    connections: [],
    endpoints: [],
    logs: [],
    tokens: []
};

// Setup Authorization headers
function getHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${STATE.token}`
    };
}

// Show toast notifications
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    toast.innerText = message;
    toast.className = `toast ${type}`;
    toast.classList.remove('hidden');
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 4000);
}

// Check authentication on launch
function initAuth() {
    // Check if token lies in URL hash (from SSO callback)
    const hash = window.location.hash;
    if (hash.startsWith('#token=')) {
        const params = new URLSearchParams(hash.substring(1));
        const token = params.get('token');
        const username = params.get('username');
        if (token) {
            localStorage.setItem('mcp_gateway_token', token);
            localStorage.setItem('mcp_gateway_username', username || 'SSO User');
            STATE.token = token;
            STATE.username = username || 'SSO User';
            window.location.hash = '#dashboard';
        }
    }

    if (STATE.token) {
        document.getElementById('login-container').classList.add('hidden');
        document.getElementById('app-shell').classList.remove('hidden');
        document.getElementById('display-user').innerText = STATE.username;
        bootstrapApp();
    } else {
        document.getElementById('login-container').classList.remove('hidden');
        document.getElementById('app-shell').classList.add('hidden');
    }
}

// Bootstrap all views and router
function bootstrapApp() {
    setupRouter();
    loadDashboardStats();
    loadConnections();
    loadEndpoints();
    loadAuditLogs();
    loadVaultSecrets();
    loadSettingsConfig();
    loadOpenAPIDocs();
    loadClientTokens();
    
    // Set dynamic URL info
    const currentHost = window.location.host;
    const isHTTPS = window.location.protocol === 'https:';
    const proto = isHTTPS ? 'https' : 'http';
    document.getElementById('config-sse-url').innerText = `${proto}://${currentHost}/sse?token=secure-mcp-gateway-token-123456`;
}

// Single Page Application Router
function setupRouter() {
    const handleRoute = () => {
        let route = window.location.hash || '#dashboard';
        
        // Redirect legacy vault and openapi hash routes to settings page
        if (route === '#vault' || route === '#openapi') {
            window.location.hash = '#settings';
            return;
        }
        
        // Hide all views
        document.querySelectorAll('.content-section').forEach(section => {
            section.classList.add('hidden');
        });
        
        // Remove active class from menu
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });

        // Resolve active target
        const targetView = 'view-' + route.substring(1);
        const targetNav = 'nav-' + route.substring(1);
        
        const viewEl = document.getElementById(targetView);
        const navEl = document.getElementById(targetNav);
        
        if (viewEl) {
            viewEl.classList.remove('hidden');
            document.getElementById('page-title').innerText = navEl ? navEl.innerText.replace(/[^\w\s]/g, '').trim() : 'Dashboard';
        }
        if (navEl) navEl.classList.add('active');

        // Route specific fetch triggers
        if (route === '#dashboard') loadDashboardStats();
        if (route === '#connections') loadConnections();
        if (route === '#endpoints') loadEndpoints();
        if (route === '#tokens') loadClientTokens();
        if (route === '#telemetry') loadTelemetry();
        if (route === '#logs') loadAuditLogs();
        if (route === '#settings') {
            loadSettingsConfig();
            loadVaultSecrets();
            loadOpenAPIDocs();
        }
    };

    window.addEventListener('hashchange', handleRoute);
    handleRoute(); // Execute for initial load
}

// Load views data
async function loadDashboardStats() {
    if (!STATE.token) return;
    try {
        const connsRes = await fetch('/api/connections', { headers: getHeaders() });
        const epsRes = await fetch('/api/endpoints', { headers: getHeaders() });
        const logsRes = await fetch('/api/logs', { headers: getHeaders() });
        const opRes = await fetch('/api/operational-stats', { headers: getHeaders() });

        if (connsRes.ok && epsRes.ok && logsRes.ok) {
            STATE.connections = await connsRes.json() || [];
            STATE.endpoints = await epsRes.json() || [];
            STATE.logs = await logsRes.json() || [];

            document.getElementById('stat-connections').innerText = STATE.connections.length;
            document.getElementById('stat-tools').innerText = STATE.endpoints.length;
            document.getElementById('stat-requests').innerText = STATE.logs.length;

            // Calculate latency average
            if (STATE.logs.length > 0) {
                const total = STATE.logs.reduce((sum, l) => sum + l.duration_ms, 0);
                document.getElementById('stat-latency').innerText = `${Math.round(total / STATE.logs.length)}ms`;
            } else {
                document.getElementById('stat-latency').innerText = '0ms';
            }
        }

        if (opRes && opRes.ok) {
            const opData = await opRes.json();
            const sessionsEl = document.getElementById('config-active-sessions');
            const queriesEl = document.getElementById('config-active-queries');
            const tbody = document.getElementById('config-api-health-body');

            if (sessionsEl) sessionsEl.innerText = `${opData.connected_users} Connected`;
            if (queriesEl) queriesEl.innerText = `${opData.active_queries} Running`;

            if (tbody) {
                tbody.innerHTML = '';
                if (opData.connections_health && opData.connections_health.length > 0) {
                    opData.connections_health.forEach(h => {
                        const row = document.createElement('tr');
                        const isOK = h.status.startsWith('OK');
                        const isDisabled = h.status === 'DISABLED';
                        
                        const statusStyle = isOK ? 'color: var(--success); font-weight: 500;' : (isDisabled ? 'color: var(--text-muted);' : 'color: var(--danger); font-weight: 500;');
                        const latencyText = isDisabled ? 'N/A' : `${h.latency_ms}ms`;

                        row.innerHTML = `
                            <td><strong>${escapeHtml(h.name)}</strong></td>
                            <td><code style="font-size: 0.8rem;">${escapeHtml(h.url)}</code></td>
                            <td><span style="${statusStyle}">${escapeHtml(h.status)}</span></td>
                            <td class="text-secondary">${latencyText}</td>
                        `;
                        tbody.appendChild(row);
                    });
                } else {
                    tbody.innerHTML = '<tr><td colspan="4" class="text-muted text-center">No active API connections.</td></tr>';
                }
            }
        }
    } catch (e) {
        console.error('Failed to load stats:', e);
    }
}

async function loadConnections() {
    if (!STATE.token) return;
    const grid = document.getElementById('connections-grid');
    grid.innerHTML = '<p class="text-muted">Loading configured API connections...</p>';

    try {
        const res = await fetch('/api/connections', { headers: getHeaders() });
        if (!res.ok) throw new Error('Failed to fetch');
        
        STATE.connections = await res.json() || [];
        grid.innerHTML = '';

        if (STATE.connections.length === 0) {
            grid.innerHTML = `
                <div class="card glass text-center" style="grid-column: 1 / -1;">
                    <h3>No API connections configured</h3>
                    <p class="text-muted mt-2">Connect your internal databases or web services to get started.</p>
                </div>
            `;
            return;
        }

        STATE.connections.forEach(conn => {
            const card = document.createElement('div');
            card.className = 'conn-card glass';
            
            const toolCount = STATE.endpoints.filter(e => e.connection_id === conn.id).length;

            card.innerHTML = `
                <div>
                    <div class="conn-card-header">
                        <h3>${escapeHtml(conn.name)}</h3>
                        <span class="badge-status ${conn.enabled ? 'active' : 'disabled'}">
                            ${conn.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                    </div>
                    <p>${escapeHtml(conn.description || 'No description provided')}</p>
                    <div class="mt-4">
                        <span class="conn-url-badge">${escapeHtml(conn.base_url)}</span>
                    </div>
                </div>
                <div>
                    <div class="flex-justify mt-4">
                        <span class="badge">${toolCount} MCP Tools</span>
                        <div class="conn-actions">
                            <button class="btn-secondary btn-edit-conn" data-id="${conn.id}">Edit</button>
                            <button class="btn-danger btn-delete-conn" data-id="${conn.id}">Delete</button>
                        </div>
                    </div>
                </div>
            `;
            grid.appendChild(card);
        });

        // Add event listeners for edit and delete buttons
        document.querySelectorAll('.btn-edit-conn').forEach(btn => {
            btn.onclick = (e) => openConnectionModal(e.target.dataset.id);
        });
        document.querySelectorAll('.btn-delete-conn').forEach(btn => {
            btn.onclick = (e) => deleteConnection(e.target.dataset.id);
        });

    } catch (e) {
        grid.innerHTML = `<p class="text-danger">Error loading API connections: ${e.message}</p>`;
    }
}

async function loadEndpoints() {
    if (!STATE.token) return;
    const tbody = document.getElementById('endpoints-table-body');
    tbody.innerHTML = '<tr><td colspan="6" class="text-muted">Loading endpoints mapping...</td></tr>';

    // Ensure connections are loaded first so tool names have correct prefixes
    if (STATE.connections.length === 0) {
        try {
            const connRes = await fetch('/api/connections', { headers: getHeaders() });
            if (connRes.ok) {
                STATE.connections = await connRes.json() || [];
            }
        } catch (e) {
            console.error('Failed to pre-load connections for endpoints view', e);
        }
    }

    try {
        const res = await fetch('/api/endpoints', { headers: getHeaders() });
        if (!res.ok) throw new Error('Failed to fetch');
        
        STATE.endpoints = await res.json() || [];
        tbody.innerHTML = '';

        if (STATE.endpoints.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No MCP tools defined. Add a tool to link a route to LLM queries.</td></tr>';
            return;
        }

        STATE.endpoints.forEach(ep => {
            const conn = STATE.connections.find(c => c.id === ep.connection_id);
            const connName = conn ? conn.name : 'Unknown API';
            const prefix = conn ? conn.tool_prefix : '';
            const resolvedToolName = prefix ? `${prefix}${ep.tool_name}` : ep.tool_name;
            const row = document.createElement('tr');
            
            row.innerHTML = `
                <td>
                    <strong>${escapeHtml(resolvedToolName)}</strong>
                    ${prefix ? `<br><small class="text-muted" style="font-size:0.75rem;">(raw: ${escapeHtml(ep.tool_name)})</small>` : ''}
                </td>
                <td>${escapeHtml(connName)}</td>
                <td><code>${escapeHtml(ep.path)}</code></td>
                <td><span class="badge">${escapeHtml(ep.method)}</span></td>
                <td><span class="text-secondary">${escapeHtml(ep.tool_description)}</span></td>
                <td>
                    <div style="display: flex; gap: 0.5rem;">
                        <button class="btn-secondary btn-edit-ep" data-id="${ep.id}">Edit</button>
                        <button class="btn-danger btn-delete-ep" data-id="${ep.id}">Delete</button>
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });

        // Add event listeners
        document.querySelectorAll('.btn-edit-ep').forEach(btn => {
            btn.onclick = (e) => openEndpointModal(e.target.dataset.id);
        });
        document.querySelectorAll('.btn-delete-ep').forEach(btn => {
            btn.onclick = (e) => deleteEndpoint(e.target.dataset.id);
        });

        // Namespace conflict audits
        const resolvedNames = new Map();
        STATE.endpoints.forEach(ep => {
            const conn = STATE.connections.find(c => c.id === ep.connection_id);
            const prefix = conn ? conn.tool_prefix : '';
            const fullName = prefix + ep.tool_name;
            if (resolvedNames.has(fullName)) {
                resolvedNames.get(fullName).push(conn ? conn.name : 'Unknown');
            } else {
                resolvedNames.set(fullName, [conn ? conn.name : 'Unknown']);
            }
        });

        let clashing = [];
        resolvedNames.forEach((sources, key) => {
            if (sources.length > 1) {
                clashing.push(`"${key}" (APIs: ${sources.join(', ')})`);
            }
        });

        if (clashing.length > 0) {
            showToast(`Namespace Conflict Detected: ${clashing.join('; ')}. Set unique tool prefix names in connections configs.`, 'error');
        }

    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-danger">Error loading endpoints: ${e.message}</td></tr>`;
    }
}

async function loadAuditLogs() {
    if (!STATE.token) return;
    const tbody = document.getElementById('logs-table-body');
    tbody.innerHTML = '<tr><td colspan="6" class="text-muted">Loading audit entries...</td></tr>';

    try {
        const res = await fetch('/api/logs', { headers: getHeaders() });
        if (!res.ok) throw new Error('Failed to fetch');

        STATE.logs = await res.json() || [];
        tbody.innerHTML = '';

        if (STATE.logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Audit log is empty. Generate queries from your AI clients to log events.</td></tr>';
            return;
        }

        STATE.logs.forEach(log => {
            const row = document.createElement('tr');
            const date = new Date(log.timestamp).toLocaleString();
            const statusClass = log.status === 'success' ? 'badge-status active' : 'badge-status disabled';
            const errorSnippet = log.error_message ? `<code class="text-danger">${escapeHtml(log.error_message)}</code>` : '<span class="text-muted">-</span>';

            row.innerHTML = `
                <td>${date}</td>
                <td><code>${escapeHtml(log.client_identity)}</code></td>
                <td><strong>${escapeHtml(log.tool_name)}</strong></td>
                <td><span class="${statusClass}">${log.status}</span></td>
                <td><code>${log.duration_ms}ms</code></td>
                <td>${errorSnippet}</td>
            `;
            tbody.appendChild(row);
        });

    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-danger">Error fetching logs: ${e.message}</td></tr>`;
    }
}

async function loadVaultSecrets() {
    if (!STATE.token) return;
    const tbody = document.getElementById('vault-table-body');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="2" class="text-muted">Loading vault secrets...</td></tr>';

    try {
        const res = await fetch('/api/vault', { headers: getHeaders() });
        if (!res.ok) throw new Error('Failed to fetch vault keys');

        const keys = await res.json() || [];
        tbody.innerHTML = '';

        if (keys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="2" class="text-center text-muted">No secrets registered. Put credentials into the vault form to populate.</td></tr>';
            return;
        }

        keys.forEach(key => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><code>${escapeHtml(key)}</code></td>
                <td>
                    <button class="btn-danger btn-delete-secret" data-key="${escapeHtml(key)}">Delete</button>
                </td>
            `;
            tbody.appendChild(row);
        });

        document.querySelectorAll('.btn-delete-secret').forEach(btn => {
            btn.onclick = (e) => deleteVaultSecret(e.target.dataset.key);
        });

    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="2" class="text-danger">Error loading vault: ${e.message}</td></tr>`;
    }
}

async function deleteVaultSecret(key) {
    if (!confirm(`Are you sure you want to delete secret key reference "${key}"?`)) return;
    try {
        const res = await fetch(`/api/vault?key=${encodeURIComponent(key)}`, {
            method: 'DELETE',
            headers: getHeaders()
        });
        if (res.ok) {
            showToast('Secret deleted from vault successfully');
            loadVaultSecrets();
        } else {
            showToast('Failed to delete secret from vault', 'error');
        }
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function loadSettingsConfig() {
    if (!STATE.token) return;
    try {
        const res = await fetch('/api/settings', { headers: getHeaders() });
        if (!res.ok) throw new Error('Failed to load settings configuration');

        const data = await res.json();
        
        document.getElementById('settings-port').innerText = data.port || '8080';
        document.getElementById('settings-db-path').innerText = data.database_path || '-';
        document.getElementById('settings-vault-provider').innerText = data.vault_provider || 'local';
        document.getElementById('settings-vault-local-path').innerText = data.vault_local_path || '-';
        
        document.getElementById('settings-oidc-status').innerHTML = data.oidc_issuer ? 
            `<span class="badge-status active">SSO Enabled</span> <code>${escapeHtml(data.oidc_client_id)}</code>` : 
            `<span class="badge-status disabled">SSO Disabled</span> (Using default Admin credentials)`;
            
        document.getElementById('settings-tls-status').innerHTML = data.tls_cert_path ? 
            `<span class="badge-status active">TLS Active (HTTPS)</span>` : 
            `<span class="badge-status disabled">Unencrypted (HTTP)</span> (Set TLS_CERT_PATH to secure)`;

        document.getElementById('settings-mtls-status').innerHTML = data.client_ca_path ? 
            `<span class="badge-status active">mTLS Enforced</span>` : 
            `<span class="badge-status disabled">mTLS Disabled</span> (Clients authenticated via HTTP Token only)`;

    } catch (e) {
        console.error(e);
        showToast('Failed to retrieve server configurations', 'error');
    }
}

async function loadOpenAPIDocs() {
    if (!STATE.token) return;
    const block = document.getElementById('openapi-code-block');
    if (!block) return;
    block.innerText = 'Resolving active routes documentation...';

    // Set token dynamically to navigation links so user doesn't hit a 401 when navigating to Swagger view
    const swaggerBtn = document.getElementById('btn-interactive-swagger');
    if (swaggerBtn) {
        swaggerBtn.href = `/swagger.html?token=${encodeURIComponent(STATE.token)}`;
    }

    try {
        const res = await fetch('/api/openapi.json', { headers: getHeaders() });
        if (!res.ok) throw new Error('Failed to retrieve openapi specs');

        const spec = await res.json();
        block.innerText = JSON.stringify(spec, null, 2);
    } catch (e) {
        block.innerText = `Error: ${e.message}`;
    }
}

// Connection Modal Control
function openConnectionModal(id = null) {
    const modal = document.getElementById('connection-modal');
    const form = document.getElementById('connection-form');
    document.getElementById('connection-modal-title').innerText = id ? 'Edit API Connection' : 'Configure API Connection';
    form.reset();

    if (id) {
        const conn = STATE.connections.find(c => c.id === id);
        if (conn) {
            document.getElementById('connection-id').value = conn.id;
            document.getElementById('conn-name').value = conn.name;
            document.getElementById('conn-desc').value = conn.description;
            document.getElementById('conn-prefix').value = conn.tool_prefix || '';
            document.getElementById('conn-url').value = conn.base_url;
            document.getElementById('conn-auth').value = conn.auth_type;
            document.getElementById('conn-secret').value = conn.auth_secret_ref;
            document.getElementById('conn-enabled').checked = conn.enabled;
        }
    } else {
        document.getElementById('connection-id').value = '';
        document.getElementById('conn-prefix').value = '';
    }

    modal.classList.remove('hidden');
}

async function deleteConnection(id) {
    if (!confirm('Are you sure you want to delete this API connection? All associated MCP tools will be removed.')) return;
    try {
        const res = await fetch(`/api/connections/${id}`, {
            method: 'DELETE',
            headers: getHeaders()
        });
        if (res.ok) {
            showToast('API Connection deleted successfully');
            loadConnections();
            loadEndpoints();
        } else {
            showToast('Failed to delete connection', 'error');
        }
    } catch (e) {
        showToast(e.message, 'error');
    }
}

// Endpoint Modal Control
function openEndpointModal(id = null) {
    const modal = document.getElementById('endpoint-modal');
    const form = document.getElementById('endpoint-form');
    document.getElementById('endpoint-modal-title').innerText = id ? 'Edit MCP Tool Endpoint' : 'Configure MCP Tool Endpoint';
    form.reset();

    // Populate Connection dropdown
    const select = document.getElementById('ep-conn-id');
    select.innerHTML = '<option value="" disabled selected>Select an API source</option>';
    STATE.connections.forEach(c => {
        select.innerHTML += `<option value="${c.id}">${escapeHtml(c.name)}</option>`;
    });

    if (id) {
        const ep = STATE.endpoints.find(e => e.id === id);
        if (ep) {
            document.getElementById('endpoint-id').value = ep.id;
            document.getElementById('ep-conn-id').value = ep.connection_id;
            document.getElementById('ep-tool-name').value = ep.tool_name;
            document.getElementById('ep-tool-desc').value = ep.tool_description;
            document.getElementById('ep-path').value = ep.path;
            document.getElementById('ep-method').value = ep.method;
            document.getElementById('ep-schema').value = ep.parameters_schema;
            document.getElementById('ep-template').value = ep.template;
        }
    } else {
        document.getElementById('endpoint-id').value = '';
    }

    modal.classList.remove('hidden');
}

async function deleteEndpoint(id) {
    if (!confirm('Are you sure you want to delete this MCP Tool?')) return;
    try {
        const res = await fetch(`/api/endpoints/${id}`, {
            method: 'DELETE',
            headers: getHeaders()
        });
        if (res.ok) {
            showToast('MCP Tool deleted successfully');
            loadEndpoints();
        } else {
            showToast('Failed to delete tool', 'error');
        }
    } catch (e) {
        showToast(e.message, 'error');
    }
}

// Form Submission Actions
document.getElementById('login-form').onsubmit = async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await res.json();
        if (res.ok && data.token) {
            localStorage.setItem('mcp_gateway_token', data.token);
            localStorage.setItem('mcp_gateway_username', data.username);
            STATE.token = data.token;
            STATE.username = data.username;
            initAuth();
            showToast('Authenticated successfully');
        } else {
            showToast(data.error || 'Invalid username or password', 'error');
        }
    } catch (err) {
        showToast('Server authentication connection failed', 'error');
    }
};

document.getElementById('sso-btn').onclick = () => {
    window.location.href = '/api/auth/sso/login';
};

document.getElementById('logout-btn').onclick = () => {
    localStorage.removeItem('mcp_gateway_token');
    localStorage.removeItem('mcp_gateway_username');
    window.location.reload();
};

document.getElementById('connection-form').onsubmit = async (e) => {
    e.preventDefault();
    const id = document.getElementById('connection-id').value;
    const name = document.getElementById('conn-name').value;
    const description = document.getElementById('conn-desc').value;
    const tool_prefix = document.getElementById('conn-prefix').value;
    const base_url = document.getElementById('conn-url').value;
    const auth_type = document.getElementById('conn-auth').value;
    const auth_secret_ref = document.getElementById('conn-secret').value;
    const enabled = document.getElementById('conn-enabled').checked;

    try {
        const res = await fetch('/api/connections', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ id, name, description, tool_prefix, base_url, auth_type, auth_secret_ref, enabled })
        });

        if (res.ok) {
            showToast('API Connection saved successfully');
            document.getElementById('connection-modal').classList.add('hidden');
            loadConnections();
            loadEndpoints();
            loadOpenAPIDocs();
        } else {
            const data = await res.json();
            showToast(data.error || 'Failed to save connection', 'error');
        }
    } catch (err) {
        showToast(err.message, 'error');
    }
};

document.getElementById('endpoint-form').onsubmit = async (e) => {
    e.preventDefault();
    const id = document.getElementById('endpoint-id').value;
    const connection_id = document.getElementById('ep-conn-id').value;
    const tool_name = document.getElementById('ep-tool-name').value;
    const tool_description = document.getElementById('ep-tool-desc').value;
    const path = document.getElementById('ep-path').value;
    const method = document.getElementById('ep-method').value;
    const parameters_schema = document.getElementById('ep-schema').value;
    const template = document.getElementById('ep-template').value;

    try {
        const res = await fetch('/api/endpoints', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ id, connection_id, tool_name, tool_description, path, method, parameters_schema, template })
        });

        if (res.ok) {
            showToast('MCP Tool saved successfully');
            document.getElementById('endpoint-modal').classList.add('hidden');
            loadEndpoints();
        } else {
            const data = await res.json();
            showToast(data.error || 'Failed to save tool', 'error');
        }
    } catch (err) {
        showToast(err.message, 'error');
    }
};

document.getElementById('vault-form').onsubmit = async (e) => {
    e.preventDefault();
    const key = document.getElementById('vault-key').value;
    const value = document.getElementById('vault-value').value;

    try {
        const res = await fetch('/api/vault', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ key, value })
        });

        if (res.ok) {
            showToast(`Secret stored in vault as: ${key}`);
            document.getElementById('vault-form').reset();
            loadVaultSecrets();
        } else {
            const data = await res.json();
            showToast(data.error || 'Failed to delegate secret to vault', 'error');
        }
    } catch (err) {
        showToast(err.message, 'error');
    }
};

// Client Access Tokens Management
async function loadClientTokens() {
    if (!STATE.token) return;
    const tbody = document.getElementById('tokens-table-body');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Loading client tokens...</td></tr>';

    try {
        const res = await fetch('/api/tokens', { headers: getHeaders() });
        if (!res.ok) throw new Error('Failed to fetch tokens');
        STATE.tokens = await res.json() || [];
        tbody.innerHTML = '';

        if (STATE.tokens.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No client tokens registered yet.</td></tr>';
            return;
        }

        STATE.tokens.forEach(t => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${escapeHtml(t.client_name)}</strong></td>
                <td><code style="background: hsla(0,0%,100%,0.08); padding: 0.2rem 0.4rem; border-radius: 4px;">${escapeHtml(t.token)}</code></td>
                <td><span class="badge ${t.client_role === 'admin' ? '' : 'badge-disabled'}">${escapeHtml(t.client_role)}</span></td>
                <td><code>${escapeHtml(t.scopes || '*')}</code></td>
                <td>
                    <span class="badge-status ${t.enabled ? 'active' : 'disabled'}">
                        ${t.enabled ? 'Active' : 'Disabled'}
                    </span>
                </td>
                <td>
                    <button class="btn-icon text-danger" onclick="deleteClientToken('${escapeHtml(t.token)}')">Delete</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Error: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function openTokenModal() {
    const modal = document.getElementById('token-modal');
    document.getElementById('token-form').reset();
    modal.classList.remove('hidden');
}

async function deleteClientToken(token) {
    if (!confirm('Are you sure you want to delete this Client Token?')) return;
    try {
        const res = await fetch(`/api/tokens?token=${encodeURIComponent(token)}`, {
            method: 'DELETE',
            headers: getHeaders()
        });
        if (res.ok) {
            showToast('Client Token deleted successfully');
            loadClientTokens();
        } else {
            showToast('Failed to delete client token', 'error');
        }
    } catch (e) {
        showToast(e.message, 'error');
    }
}

document.getElementById('token-form').onsubmit = async (e) => {
    e.preventDefault();
    const client_name = document.getElementById('token-client-name').value;
    const token = document.getElementById('token-value').value;
    const client_role = document.getElementById('token-role').value;
    const scopes = document.getElementById('token-scopes').value;
    const enabled = document.getElementById('token-enabled').checked;

    try {
        const res = await fetch('/api/tokens', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ client_name, token, client_role, scopes, enabled })
        });

        if (res.ok) {
            showToast('Client Token saved successfully');
            document.getElementById('token-modal').classList.add('hidden');
            loadClientTokens();
        } else {
            const data = await res.json();
            showToast(data.error || 'Failed to save token', 'error');
        }
    } catch (err) {
        showToast(err.message, 'error');
    }
};

document.getElementById('btn-generate-token-val').onclick = () => {
    const randHex = Array.from(crypto.getRandomValues(new Uint8Array(20)))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    document.getElementById('token-value').value = `mcp_client_${randHex}`;
};

// Modal toggle utilities
document.getElementById('btn-new-connection').onclick = () => openConnectionModal();
document.getElementById('btn-new-endpoint').onclick = () => openEndpointModal();
document.getElementById('btn-new-token').onclick = () => openTokenModal();
document.getElementById('btn-close-conn-modal').onclick = () => document.getElementById('connection-modal').classList.add('hidden');
document.getElementById('btn-close-ep-modal').onclick = () => document.getElementById('endpoint-modal').classList.add('hidden');
document.getElementById('btn-close-token-modal').onclick = () => document.getElementById('token-modal').classList.add('hidden');

// Schema Modal Controls
document.getElementById('btn-show-schema').onclick = () => document.getElementById('schema-modal').classList.remove('hidden');
document.getElementById('btn-card-show-schema').onclick = () => document.getElementById('schema-modal').classList.remove('hidden');
document.getElementById('btn-close-schema-modal').onclick = () => document.getElementById('schema-modal').classList.add('hidden');
document.getElementById('btn-modal-close-schema').onclick = () => document.getElementById('schema-modal').classList.add('hidden');

// Copy JSON to Clipboard
document.getElementById('btn-modal-copy-schema').onclick = () => {
    const code = document.getElementById('openapi-code-block').innerText;
    navigator.clipboard.writeText(code).then(() => {
        showToast('OpenAPI JSON copied to clipboard');
    }).catch(err => {
        showToast('Failed to copy text', 'error');
    });
};

// Download JSON Spec
const triggerDownload = () => {
    const code = document.getElementById('openapi-code-block').innerText;
    if (code.startsWith('Error:') || code.startsWith('Resolving') || code.startsWith('Loading')) {
        showToast('Schema not fully loaded yet', 'error');
        return;
    }
    const blob = new Blob([code], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'openapi.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('OpenAPI schema download started');
};

document.getElementById('btn-download-openapi').onclick = (e) => {
    e.preventDefault();
    triggerDownload();
};
document.getElementById('btn-card-download-schema').onclick = () => triggerDownload();
document.getElementById('btn-modal-download-schema').onclick = () => triggerDownload();

// OpenTelemetry Dashboard Rendering
async function loadTelemetry() {
    if (!STATE.token) return;

    try {
        // Fetch raw metrics
        const metricsRes = await fetch('/metrics', { headers: getHeaders() });
        let metricsText = '';
        let metricsCount = 0;
        if (metricsRes.ok) {
            metricsText = await metricsRes.text();
            const rawEl = document.getElementById('telemetry-raw-prom');
            if (rawEl) rawEl.innerText = metricsText;
            metricsCount = metricsText.split('\n').filter(line => line.trim() && !line.startsWith('#')).length;
            document.getElementById('telemetry-scraped-count').innerText = metricsCount;
        }

        // Fetch logs for graphing
        const logsRes = await fetch('/api/logs', { headers: getHeaders() });
        if (logsRes.ok) {
            const logs = await logsRes.json() || [];
            
            // Calculate Success Rate
            if (logs.length > 0) {
                const successes = logs.filter(l => l.status === 'success').length;
                const successRate = Math.round((successes / logs.length) * 100);
                document.getElementById('telemetry-success-rate').innerText = `${successRate}%`;
            } else {
                document.getElementById('telemetry-success-rate').innerText = '0%';
            }

            // Calculate P95 Latency
            if (logs.length > 0) {
                const durations = logs.map(l => l.duration_ms).sort((a, b) => a - b);
                const p95Idx = Math.floor(durations.length * 0.95);
                document.getElementById('telemetry-p95-latency').innerText = `${durations[p95Idx]}ms`;
            } else {
                document.getElementById('telemetry-p95-latency').innerText = '0ms';
            }

            // Draw SVG charts
            renderLatencyChart(logs);
            renderFrequencyChart(logs);
        }
    } catch (e) {
        console.error('Failed to load telemetry dashboard:', e);
        showToast('Error loading telemetry dashboard data', 'error');
    }
}

function renderLatencyChart(logs) {
    const wrapper = document.getElementById('latency-chart-wrapper');
    if (!wrapper) return;

    // Take last 20 requests in chronological order
    const data = [...logs].slice(0, 20).reverse();
    if (data.length === 0) {
        wrapper.innerHTML = '<p class="text-center text-muted" style="line-height:220px;">No execution data available</p>';
        return;
    }

    const width = wrapper.clientWidth || 400;
    const height = 220;
    const paddingLeft = 40;
    const paddingRight = 10;
    const paddingTop = 20;
    const paddingBottom = 30;

    const chartWidth = width - paddingLeft - paddingRight;
    const chartHeight = height - paddingTop - paddingBottom;

    // Find max latency
    const maxVal = Math.max(...data.map(d => d.duration_ms), 50);

    // Map points
    const points = data.map((d, i) => {
        const x = paddingLeft + (i / (data.length - 1 || 1)) * chartWidth;
        const y = paddingTop + chartHeight - (d.duration_ms / maxVal) * chartHeight;
        return { x, y, val: d.duration_ms, name: d.tool_name };
    });

    // Build path
    let pathD = '';
    let areaD = '';
    if (points.length > 0) {
        pathD = `M ${points[0].x} ${points[0].y}`;
        areaD = `M ${points[0].x} ${paddingTop + chartHeight} L ${points[0].x} ${points[0].y}`;
        for (let i = 1; i < points.length; i++) {
            pathD += ` L ${points[i].x} ${points[i].y}`;
            areaD += ` L ${points[i].x} ${points[i].y}`;
        }
        areaD += ` L ${points[points.length - 1].x} ${paddingTop + chartHeight} Z`;
    }

    // Build SVG
    let svgHtml = `
    <svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <linearGradient id="area-grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="var(--primary-color)" stop-opacity="0.3"/>
                <stop offset="100%" stop-color="var(--primary-color)" stop-opacity="0.0"/>
            </linearGradient>
        </defs>
        <!-- Horizontal grid lines -->
        <line x1="${paddingLeft}" y1="${paddingTop}" x2="${width - paddingRight}" y2="${paddingTop}" stroke="hsla(0,0%,100%,0.08)" stroke-dasharray="3,3"/>
        <line x1="${paddingLeft}" y1="${paddingTop + chartHeight / 2}" x2="${width - paddingRight}" y2="${paddingTop + chartHeight / 2}" stroke="hsla(0,0%,100%,0.08)" stroke-dasharray="3,3"/>
        <line x1="${paddingLeft}" y1="${paddingTop + chartHeight}" x2="${width - paddingRight}" y2="${paddingTop + chartHeight}" stroke="hsla(0,0%,100%,0.15)"/>
        
        <!-- Y-axis labels -->
        <text x="${paddingLeft - 8}" y="${paddingTop + 4}" fill="var(--text-secondary)" font-size="10" text-anchor="end">${Math.round(maxVal)}ms</text>
        <text x="${paddingLeft - 8}" y="${paddingTop + chartHeight / 2 + 4}" fill="var(--text-secondary)" font-size="10" text-anchor="end">${Math.round(maxVal / 2)}ms</text>
        <text x="${paddingLeft - 8}" y="${paddingTop + chartHeight + 4}" fill="var(--text-secondary)" font-size="10" text-anchor="end">0ms</text>

        <!-- Area chart -->
        <path d="${areaD}" fill="url(#area-grad)"/>

        <!-- Line chart -->
        <path d="${pathD}" fill="none" stroke="var(--primary-color)" stroke-width="2.5" stroke-linecap="round"/>

        <!-- Data dots -->
    `;

    points.forEach((p, i) => {
        svgHtml += `
        <circle cx="${p.x}" cy="${p.y}" r="4" fill="hsl(220, 15%, 15%)" stroke="var(--primary-color)" stroke-width="2" style="cursor: pointer;">
            <title>${escapeHtml(p.name)}\nLatency: ${p.val}ms</title>
        </circle>
        `;
    });

    svgHtml += `</svg>`;
    wrapper.innerHTML = svgHtml;
}

function renderFrequencyChart(logs) {
    const wrapper = document.getElementById('frequency-chart-wrapper');
    if (!wrapper) return;

    // Aggregate counts
    const freqMap = {};
    logs.forEach(l => {
        freqMap[l.tool_name] = (freqMap[l.tool_name] || 0) + 1;
    });

    const data = Object.entries(freqMap)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5); // top 5 tools

    if (data.length === 0) {
        wrapper.innerHTML = '<p class="text-center text-muted" style="line-height:220px;">No execution data available</p>';
        return;
    }

    const width = wrapper.clientWidth || 400;
    const height = 220;
    const paddingLeft = 140; // larger padding for tool names
    const paddingRight = 20;
    const paddingTop = 10;
    const paddingBottom = 20;

    const chartWidth = width - paddingLeft - paddingRight;
    const chartHeight = height - paddingTop - paddingBottom;

    const maxCount = Math.max(...data.map(d => d.count), 5);
    const rowHeight = chartHeight / data.length;

    let svgHtml = `
    <svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">
    `;

    data.forEach((d, i) => {
        const y = paddingTop + i * rowHeight + (rowHeight - 14) / 2;
        const barWidth = (d.count / maxCount) * chartWidth;
        const displayName = d.name.length > 22 ? d.name.substring(0, 19) + '...' : d.name;

        svgHtml += `
        <!-- Tool Name label -->
        <text x="${paddingLeft - 10}" y="${y + 11}" fill="var(--text-secondary)" font-size="11" text-anchor="end">${escapeHtml(displayName)}</text>
        
        <!-- Bar Background -->
        <rect x="${paddingLeft}" y="${y}" width="${chartWidth}" height="14" rx="3" fill="hsla(0,0%,100%,0.03)" />
        
        <!-- Bar Fill with orange glow -->
        <rect x="${paddingLeft}" y="${y}" width="${barWidth}" height="14" rx="3" fill="var(--primary-color)" opacity="0.85">
            <title>Calls: ${d.count}</title>
        </rect>
        
        <!-- Bar Label -->
        <text x="${paddingLeft + barWidth + 8}" y="${y + 11}" fill="var(--text-primary)" font-size="11">${d.count}</text>
        `;
    });

    svgHtml += `</svg>`;
    wrapper.innerHTML = svgHtml;
}

// Helper to escape HTML characters
function escapeHtml(text) {
    if (!text) return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

// Searchable Help & Docs logic
const searchInput = document.getElementById('docs-search-input');
if (searchInput) {
    searchInput.oninput = (e) => {
        const query = e.target.value.toLowerCase().trim();
        document.querySelectorAll('.docs-section').forEach(section => {
            const title = section.querySelector('h3').innerText.toLowerCase();
            const text = section.innerText.toLowerCase();
            const keywords = section.dataset.keywords ? section.dataset.keywords.toLowerCase() : '';
            if (title.includes(query) || text.includes(query) || keywords.includes(query)) {
                section.classList.remove('hidden');
            } else {
                section.classList.add('hidden');
            }
        });
    };
}

// Theme Toggle logic
const themeToggleBtn = document.getElementById('theme-toggle-btn');
if (themeToggleBtn) {
    themeToggleBtn.onclick = () => {
        document.documentElement.classList.toggle('light');
        const currentTheme = document.documentElement.classList.contains('light') ? 'light' : 'dark';
        localStorage.setItem('portal-theme', currentTheme);
    };
}

// Boot strap app
window.onload = initAuth;
