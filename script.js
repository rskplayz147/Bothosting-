// static/script.js
document.addEventListener('DOMContentLoaded', () => {
    // Common variables
    const baseUrl = window.location.origin;
    const flashMessages = document.querySelector('.flash-messages');
    let ws = null; // WebSocket for live logs

    // Utility to show flash messages
    function showFlashMessage(message, category = 'success') {
        if (!flashMessages) return;
        const flashDiv = document.createElement('div');
        flashDiv.className = `flash-${category}`;
        flashDiv.textContent = message;
        flashMessages.appendChild(flashDiv);
        setTimeout(() => flashDiv.remove(), 5000);
    }

    // Form validation for login/register
    function validateForm(form) {
        const inputs = form.querySelectorAll('input[required]');
        let valid = true;
        inputs.forEach(input => {
            if (!input.value.trim()) {
                valid = false;
                input.classList.add('error');
                showFlashMessage(`${input.name} is required`, 'error');
            } else {
                input.classList.remove('error');
            }
        });
        return valid;
    }

    // Handle form submissions (login/register)
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', async (e) => {
            if (!validateForm(form)) {
                e.preventDefault();
                return;
            }
            // Add CSRF token if needed (implement server-side CSRF first)
        });
    });

    // File upload handling
    const fileUploadInput = document.getElementById('file-upload');
    if (fileUploadInput) {
        fileUploadInput.addEventListener('change', () => {
            const fileName = fileUploadInput.files[0]?.name || 'No file selected';
            const label = document.querySelector('.file-upload-label span');
            label.textContent = fileName;
        });
    }

    // Initialize WebSocket for live logs
    function initWebSocket(fileId) {
        if (ws) ws.close();
        ws = new WebSocket(`ws://${window.location.host}/ws/logs/${fileId}`);
        ws.onopen = () => console.log('WebSocket connected for logs');
        ws.onmessage = (event) => {
            const logData = JSON.parse(event.data);
            updateLogsDisplay(fileId, logData);
        };
        ws.onerror = (error) => console.error('WebSocket error:', error);
        ws.onclose = () => console.log('WebSocket closed');
    }

    // Update logs display
    function updateLogsDisplay(fileId, logs) {
        const logContainer = document.getElementById(`logs-${fileId}`);
        if (logContainer) {
            logContainer.textContent = logs.join('\n');
            logContainer.scrollTop = logContainer.scrollHeight;
        }
    }

    // Fetch and update file status
    async function updateFileStatus(fileId) {
        try {
            const response = await fetch(`${baseUrl}/api/status/${fileId}`, {
                headers: { 'Authorization': `Bearer ${localStorage.getItem('token') || ''}` }
            });
            const data = await response.json();
            if (data.error) {
                showFlashMessage(data.error, 'error');
                return;
            }
            const statusBadge = document.getElementById(`status-${fileId}`);
            if (statusBadge) {
                statusBadge.textContent = data.status;
                statusBadge.className = `status-badge ${data.status}`;
                const fileCard = statusBadge.closest('.file-card');
                fileCard.className = `file-card ${data.status}`;
                updateActionButtons(fileId, data.status);
            }
        } catch (error) {
            showFlashMessage('Error fetching status', 'error');
        }
    }

    // Update action buttons based on status
    function updateActionButtons(fileId, status) {
        const startBtn = document.getElementById(`start-${fileId}`);
        const stopBtn = document.getElementById(`stop-${fileId}`);
        if (startBtn && stopBtn) {
            startBtn.style.display = status === 'running' ? 'none' : 'inline-flex';
            stopBtn.style.display = status === 'running' ? 'inline-flex' : 'none';
        }
    }

    // Fetch logs for a file
    async function fetchLogs(fileId) {
        try {
            const response = await fetch(`${baseUrl}/logs/${fileId}`, {
                headers: { 'Authorization': `Bearer ${localStorage.getItem('token') || ''}` }
            });
            const logs = await response.json();
            if (logs.error) {
                showFlashMessage(logs.error, 'error');
                return;
            }
            updateLogsDisplay(fileId, logs);
            initWebSocket(fileId); // Start live log streaming
        } catch (error) {
            showFlashMessage('Error fetching logs', 'error');
        }
    }

    // Control file actions (start, stop, restart, lock, unlock)
    async function controlFile(fileId, action) {
        try {
            const response = await fetch(`${baseUrl}/control/${fileId}/${action}`, {
                headers: { 'Authorization': `Bearer ${localStorage.getItem('token') || ''}` }
            });
            const data = await response.json();
            if (data.success) {
                showFlashMessage(data.message, 'success');
                updateFileStatus(fileId);
            } else {
                showFlashMessage(data.error, 'error');
            }
        } catch (error) {
            showFlashMessage(`Error performing ${action}`, 'error');
        }
    }

    // Initialize analytics chart
    function initAnalyticsChart() {
        const analyticsCanvas = document.getElementById('analytics-chart');
        if (!analyticsCanvas) return;

        fetch(`${baseUrl}/api/analytics`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token') || ''}` }
        })
            .then(response => response.json())
            .then(data => {
                const actions = {};
                data.forEach(entry => {
                    actions[entry.action] = (actions[entry.action] || 0) + 1;
                });

                new Chart(analyticsCanvas, {
                    type: 'bar',
                    data: {
                        labels: Object.keys(actions),
                        datasets: [{
                            label: 'User Actions',
                            data: Object.values(actions),
                            backgroundColor: 'rgba(125, 48, 233, 0.6)',
                            borderColor: 'rgba(125, 48, 233, 1)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });
            })
            .catch(error => showFlashMessage('Error loading analytics', 'error'));
    }

    // Schedule file execution
    function scheduleFile(fileId) {
        const scheduleInput = document.getElementById(`schedule-${fileId}`);
        if (!scheduleInput || !scheduleInput.value.match(/^\d{2}:\d{2}$/)) {
            showFlashMessage('Invalid schedule format (use HH:MM)', 'error');
            return;
        }

        const formData = new FormData();
        formData.append('schedule', scheduleInput.value);

        fetch(`${baseUrl}/schedule/${fileId}`, {
            method: 'POST',
            body: formData,
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token') || ''}` }
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showFlashMessage('Task scheduled successfully', 'success');
                } else {
                    showFlashMessage(data.error, 'error');
                }
            })
            .catch(error => showFlashMessage('Error scheduling task', 'error'));
    }

    // Initialize dashboard
    function initDashboard() {
        const fileCards = document.querySelectorAll('.file-card');
        fileCards.forEach(card => {
            const fileId = card.dataset.fileId;
            // Update status periodically
            setInterval(() => updateFileStatus(fileId), 10000);

            // Event listeners for buttons
            const startBtn = document.getElementById(`start-${fileId}`);
            const stopBtn = document.getElementById(`stop-${fileId}`);
            const logsBtn = document.getElementById(`logs-${fileId}-btn`);
            const restartBtn = document.getElementById(`restart-${fileId}`);
            const lockBtn = document.getElementById(`lock-${fileId}`);
            const unlockBtn = document.getElementById(`unlock-${fileId}`);
            const scheduleBtn = document.getElementById(`schedule-btn-${fileId}`);

            if (startBtn) startBtn.addEventListener('click', () => controlFile(fileId, 'start'));
            if (stopBtn) stopBtn.addEventListener('click', () => controlFile(fileId, 'stop'));
            if (logsBtn) logsBtn.addEventListener('click', () => fetchLogs(fileId));
            if (restartBtn) restartBtn.addEventListener('click', () => controlFile(fileId, 'restart'));
            if (lockBtn) lockBtn.addEventListener('click', () => controlFile(fileId, 'lock'));
            if (unlockBtn) unlockBtn.addEventListener('click', () => controlFile(fileId, 'unlock'));
            if (scheduleBtn) scheduleBtn.addEventListener('click', () => scheduleFile(fileId));
        });

        initAnalyticsChart();
    }

    // Initialize based on page
    if (document.querySelector('.dashboard')) {
        initDashboard();
    }
});