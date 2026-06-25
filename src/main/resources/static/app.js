// Formatting helpers
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Chart.js Configuration
const ctx = document.getElementById('protocolChart').getContext('2d');
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = 'Inter';

const protocolChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['TCP', 'UDP', 'Other'],
        datasets: [{
            data: [0, 0, 0],
            backgroundColor: [
                '#38bdf8', // TCP - light blue
                '#818cf8', // UDP - indigo
                '#475569'  // Other - slate
            ],
            borderWidth: 0,
            hoverOffset: 4
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
            legend: {
                position: 'bottom',
                labels: { padding: 20, usePointStyle: true }
            }
        },
        animation: {
            duration: 500 // smooth, fast updates
        }
    }
});

// Update DOM elements
const elTotalPackets = document.getElementById('total-packets');
const elTotalBytes = document.getElementById('total-bytes');
const elActiveConns = document.getElementById('active-conns');
const elBlockedPackets = document.getElementById('blocked-packets');
const elLogsContainer = document.getElementById('logs-container');

let lastLogCount = 0;

// Fetch and update data
async function updateDashboard() {
    try {
        // Fetch Stats
        const statsRes = await fetch('/api/stats');
        const stats = await statsRes.json();
        
        if (!stats.error) {
            elTotalPackets.textContent = stats.totalPackets.toLocaleString();
            elTotalBytes.textContent = formatBytes(stats.totalBytes);
            elActiveConns.textContent = stats.activeConnections.toLocaleString();
            elBlockedPackets.textContent = stats.droppedPackets.toLocaleString();

            // Update Chart
            protocolChart.data.datasets[0].data = [
                stats.tcpPackets,
                stats.udpPackets,
                stats.otherPackets
            ];
            protocolChart.update();
        }

        // Fetch Logs
        const logsRes = await fetch('/api/logs');
        const logs = await logsRes.json();
        
        if (logs.length > 0 && logs.length !== lastLogCount) {
            lastLogCount = logs.length;
            renderLogs(logs);
        }

    } catch (err) {
        console.error("Failed to fetch dashboard data:", err);
    }
}

function renderLogs(logs) {
    elLogsContainer.innerHTML = ''; // clear
    // Reverse so newest is at the top
    const reversedLogs = [...logs].reverse();
    
    reversedLogs.forEach(log => {
        const div = document.createElement('div');
        div.className = 'log-entry';
        
        // Add timestamp if missing
        const time = new Date().toLocaleTimeString();
        div.textContent = `[${time}] ${log}`;
        
        elLogsContainer.appendChild(div);
    });
}

// Initial fetch and set interval (poll every 1 second)
updateDashboard();
setInterval(updateDashboard, 1000);
