let token = localStorage.getItem('token');
let severityChart = null;


document.addEventListener('DOMContentLoaded', () => {
    if (token) {
        document.getElementById('login-overlay').style.display = 'none';
        startApp();
    }
});

async function handleLogin() {
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;
    const errorMsg = document.getElementById('login-error');

    const formData = new FormData();
    formData.append('username', user);
    formData.append('password', pass);

    try {
        const response = await fetch('/token', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const data = await response.json();
            token = data.access_token;
            localStorage.setItem('token', token);
            document.getElementById('login-overlay').style.display = 'none';
            startApp();
        } else {
            errorMsg.style.display = 'block';
        }
    } catch (e) {
        errorMsg.style.display = 'block';
    }
}

function handleLogout() {
    localStorage.removeItem('token');
    window.location.href = '/';
}

function startApp() {
    loadUserProfile();

    if (typeof PAGE_ID === 'undefined') return;

    if (PAGE_ID === 'dashboard') {
        loadStats();

        setInterval(loadStats, 30000);
    } else if (PAGE_ID === 'logs') {
        loadLogs();
    } else if (PAGE_ID === 'rules') {
        loadRules();
    } else if (PAGE_ID === 'reports') {
        loadReports();
    }

    initWebSocket();
}

async function apiFetch(url, options = {}) {
    options.headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`
    };
    const response = await fetch(url, options);
    if (response.status === 401) handleLogout();
    return response.json();
}

async function loadStats() {
    const stats = await apiFetch('/api/stats');
    if (!stats) return;

    document.getElementById('stat-total').innerText = stats.total_events;
    document.getElementById('stat-critical').innerText = stats.severity_distribution.CRITICAL || 0;
    document.getElementById('stat-risk').innerText = stats.risk_level;

    const riskBadge = document.getElementById('risk-badge');
    if (riskBadge) {
        riskBadge.innerText = `System ${stats.risk_level}`;
        riskBadge.className = `severity-pill sev-${stats.risk_level.toLowerCase()}`;
    }

    // Update Chart
    updateChart(stats.severity_distribution);

    // Update Recent Events Table
    const tbody = document.querySelector('#recent-events-table tbody');
    if (tbody) {
        tbody.innerHTML = '';
        stats.recent_events.forEach(event => {
            const row = `<tr>
                <td>${new Date(event.timestamp).toLocaleTimeString()}</td>
                <td>${event.rule_name}</td>
                <td><span class="severity-pill sev-${event.severity.toLowerCase()}">${event.severity}</span></td>
                <td>${event.remote_ip || 'Internal'}</td>
            </tr>`;
            tbody.innerHTML += row;
        });
    }
}

function updateChart(data) {
    const ctx = document.getElementById('severity-chart');
    if (!ctx) return;

    const labels = Object.keys(data);
    const values = Object.values(data);

    if (severityChart) severityChart.destroy();

    severityChart = new Chart(ctx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: ['#f85149', '#d29922', '#58a6ff', '#3fb950'],
                borderWidth: 0
            }]
        },
        options: {
            plugins: { legend: { position: 'bottom', labels: { color: '#8b949e' } } }
        }
    });
}

async function exportLogs() {
    const sev = document.getElementById('severity-filter').value;
    const url = `/api/logs/export${sev ? '?severity=' + sev : ''}`;

    try {
        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.status === 401) {
            handleLogout();
            return;
        }

        if (response.ok) {
            const blob = await response.blob();
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = downloadUrl;

            // Try to get filename from header
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = 'logs_export.csv';
            if (contentDisposition) {
                const parts = contentDisposition.split('filename=');
                if (parts.length === 2) filename = parts[1].replace(/"/g, '');
            }

            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(downloadUrl);
        } else {
            console.error("Export failed");
        }
    } catch (e) {
        console.error("Export error:", e);
    }
}

async function loadLogs() {
    const sev = document.getElementById('severity-filter').value;
    const logs = await apiFetch(`/api/logs${sev ? '?severity=' + sev : ''}`);
    const tbody = document.querySelector('#all-logs-table tbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    logs.forEach(log => {
        const row = `<tr>
            <td>${new Date(log.timestamp).toLocaleString()}</td>
            <td>${log.category}</td>
            <td>${log.rule_name}</td>
            <td>${log.remote_ip || '-'}</td>
            <td>${log.message}</td>
            <td><span class="severity-pill sev-${log.severity.toLowerCase()}">${log.severity}</span></td>
        </tr>`;
        tbody.innerHTML += row;
    });
}

async function loadRules() {
    const rules = await apiFetch('/api/rules');
    const tbody = document.querySelector('#rules-table tbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    rules.forEach(rule => {
        const row = `<tr>
            <td>${rule.rule_key}</td>
            <td><code>${rule.pattern}</code></td>
            <td>${rule.severity}</td>
            <td>${rule.is_active ? 'Aktif' : 'Pasif'}</td>
            <td>
                <button onclick="toggleRule(${rule.id}, ${!rule.is_active})" style="padding: 0.2rem 0.5rem; width: auto;">
                    ${rule.is_active ? 'Devre Dışı Bırak' : 'Etkinleştir'}
                </button>
            </td>
        </tr>`;
        tbody.innerHTML += row;
    });


}

async function toggleRule(id, newState) {
    await apiFetch(`/api/rules/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_active: newState })
    });
    loadRules();
}

async function loadReports() {
    const reports = await apiFetch('/api/reports');
    const tbody = document.getElementById('reports-list');
    if (!tbody) return;

    tbody.innerHTML = '';


    reports.forEach(report => {
        const isObj = typeof report === 'object';
        const filename = isObj ? report.filename : report;
        const date = isObj ? new Date(report.created_at).toLocaleString() : 'Legacy';
        const user = isObj ? report.created_by : 'Unknown';

        const row = `<tr>
            <td>${date}</td>
            <td>${filename}</td>
            <td>${user}</td>
        </tr>`;
        tbody.innerHTML += row;
    });
}

async function handleCreateUser() {
    const user = document.getElementById('new-username').value;
    const pass = document.getElementById('new-password').value;
    const msg = document.getElementById('user-msg');

    if (!user || !pass) {
        msg.innerText = "Kullanıcı adı ve şeifre gereklidir.";
        msg.style.color = 'var(--accent-red)';
        msg.style.display = 'block';
        return;
    }

    try {
        const response = await fetch('/api/users', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username: user, password: pass })
        });

        if (response.ok) {
            msg.innerText = "Kullanıcı başarıyla oluşturuldu.";
            msg.style.color = 'var(--accent-green)';
            document.getElementById('new-username').value = '';
            document.getElementById('new-password').value = '';
        } else {
            const data = await response.json();
            msg.innerText = "Hata: " + data.detail;
            msg.style.color = 'var(--accent-red)';
        }
        msg.style.display = 'block';
    } catch (e) {
        msg.innerText = "Bir hata oluştu.";
        msg.style.color = 'var(--accent-red)';
        msg.style.display = 'block';
    }
}

async function loadUserProfile() {
    try {
        const user = await apiFetch('/api/me');
        if (user) {
            const userDisplay = document.getElementById('display-user');
            if (userDisplay) {
                userDisplay.innerHTML = `${user.username} <span style="font-size: 0.7rem; background: var(--accent-purple); padding: 2px 6px; border-radius: 4px; margin-left: 5px;">${user.role}</span>`;
            }


            const addUserCard = document.getElementById('add-user-card');
            if (addUserCard) {
                if (user.role !== 'admin') {
                    addUserCard.style.display = 'none';
                } else {
                    addUserCard.style.display = 'block';
                }
            }
        }
    } catch (e) {
        console.error("Failed to load user profile", e);
    }
}

function initWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${location.host}/ws/events`);

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);



        if (PAGE_ID === 'dashboard') {
            loadStats();
        }

        if (PAGE_ID === 'logs') {
            loadLogs();
        }
    };

    ws.onclose = () => {
        setTimeout(initWebSocket, 5000);
    };
}
