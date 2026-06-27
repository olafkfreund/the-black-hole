// MCP API Gateway - Portal Frontend Logic

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
        const route = window.location.hash || '#dashboard';
        
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
        if (route === '#openapi') loadOpenAPIDocs();
        if (route === '#vault') loadVaultSecrets();
        if (route === '#tokens') loadClientTokens();
        if (route === '#logs') loadAuditLogs();
        if (route === '#settings') loadSettingsConfig();
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

    // Set token dynamically to navigation links so user doesn't hit a 401 when navigating to Swagger or Raw JSON view
    const swaggerBtn = document.getElementById('btn-interactive-swagger');
    if (swaggerBtn) {
        swaggerBtn.href = `/swagger.html?token=${encodeURIComponent(STATE.token)}`;
    }
    const rawBtn = document.getElementById('btn-raw-openapi');
    if (rawBtn) {
        rawBtn.href = `/api/openapi.json?token=${encodeURIComponent(STATE.token)}`;
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

// Boot strap app
window.onload = initAuth;
