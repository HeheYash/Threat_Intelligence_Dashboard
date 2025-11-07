// Cyber Threat Intelligence Dashboard JavaScript

// Global variables
let trendsChart = null;
let typeChart = null;
let currentTrendsData = null;
let refreshInterval = null;

// API base URL
const API_BASE = '/api';

// Initialize dashboard
function initializeDashboard() {
    console.log('Initializing CTI Dashboard...');

    // Set up event listeners
    setupEventListeners();

    // Load initial data
    loadDashboardData();

    // Set up auto-refresh (every 5 minutes)
    startAutoRefresh();
}

// Set up event listeners
function setupEventListeners() {
    // Quick search form
    document.getElementById('quickSearchForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const searchTerm = document.getElementById('quickSearchInput').value.trim();
        if (searchTerm) {
            performQuickLookup(searchTerm);
        }
    });

    // Real-time search input
    const searchInput = document.getElementById('quickSearchInput');
    let searchTimeout;
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        const value = this.value.trim();
        if (value.length >= 3) {
            searchTimeout = setTimeout(() => {
                showSearchSuggestions(value);
            }, 300);
        } else {
            hideSearchSuggestions();
        }
    });

    // Hide suggestions when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('#quickSearchInput') && !e.target.closest('#searchSuggestions')) {
            hideSearchSuggestions();
        }
    });
}

// Load all dashboard data
async function loadDashboardData() {
    showLoading();

    try {
        // Load data in parallel
        const [stats, trends, feedStatus] = await Promise.all([
            fetchAPI('/stats'),
            fetchAPI('/trends?days=30'),
            fetchAPI('/feeds/status')
        ]);

        // Update UI components
        updateStatistics(stats.data);
        updateTrendsChart(trends.data);
        updateTypeDistribution(stats.data);
        updateFeedStatus(feedStatus.data);
        updateTopThreats();
        updateRecentActivity();
        updateRecentIOCs();

        // Update last update timestamp
        updateLastUpdateTime();

    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showNotification('Error loading dashboard data', 'danger');
    } finally {
        hideLoading();
    }
}

// API helper function
async function fetchAPI(endpoint, options = {}) {
    const defaultOptions = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    };

    const response = await fetch(API_BASE + endpoint, { ...defaultOptions, ...options });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return await response.json();
}

// Update statistics cards
function updateStatistics(stats) {
    document.getElementById('totalIOCs').textContent = formatNumber(stats.total_iocs || 0);
    document.getElementById('highThreatIOCs').textContent = formatNumber(stats.high_threat || 0);
    document.getElementById('activeFeeds').textContent = Object.keys(stats.by_type || {}).length;

    // Calculate new today (simplified - would need proper date filtering)
    const todayNew = Math.floor((stats.total_iocs || 0) * 0.05); // Rough estimate
    document.getElementById('todayNew').textContent = formatNumber(todayNew);
}

// Update trends chart
function updateTrendsChart(trendsData) {
    const ctx = document.getElementById('trendsChart').getContext('2d');

    // Destroy existing chart if it exists
    if (trendsChart) {
        trendsChart.destroy();
    }

    trendsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: trendsData.dates || [],
            datasets: [{
                label: 'IOCs Discovered',
                data: trendsData.counts || [],
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of IOCs'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Date'
                    }
                }
            }
        }
    });

    currentTrendsData = trendsData;
}

// Update IOC type distribution chart
function updateTypeDistribution(stats) {
    const ctx = document.getElementById('typeChart').getContext('2d');

    // Destroy existing chart if it exists
    if (typeChart) {
        typeChart.destroy();
    }

    const typeData = stats.by_type || {};
    const labels = Object.keys(typeData);
    const data = Object.values(typeData);

    typeChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.map(label => label.charAt(0).toUpperCase() + label.slice(1)),
            datasets: [{
                data: data,
                backgroundColor: [
                    '#FF6384',
                    '#36A2EB',
                    '#FFCE56',
                    '#4BC0C0',
                    '#9966FF'
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Update feed status in navigation
function updateFeedStatus(feedStatus) {
    const dropdown = document.getElementById('feedStatusDropdown');
    dropdown.innerHTML = '';

    let activeCount = 0;

    Object.entries(feedStatus).forEach(([feedId, feed]) => {
        const statusClass = feed.enabled ? 'status-active' : 'status-inactive';
        const statusText = feed.enabled ? 'Active' : 'Disabled';

        if (feed.enabled) activeCount++;

        const item = document.createElement('li');
        item.innerHTML = `
            <a class="dropdown-item" href="#">
                <span class="status-indicator ${statusClass}"></span>
                ${feed.name}: ${statusText}
            </a>
        `;
        dropdown.appendChild(item);
    });

    // Update active feeds count
    document.getElementById('activeFeeds').textContent = activeCount;
}

// Update top threats table
async function updateTopThreats() {
    try {
        const response = await fetchAPI('/search?min_score=70&limit=10');
        const threats = response.data.results || [];

        const tbody = document.querySelector('#topThreatsTable tbody');
        tbody.innerHTML = '';

        threats.forEach(threat => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="text-truncate" style="max-width: 120px;" title="${threat.value}">
                    ${threat.value.substring(0, 15)}${threat.value.length > 15 ? '...' : ''}
                </td>
                <td>
                    <span class="badge threat-${getThreatLevel(threat.threat_score)}">
                        ${threat.threat_score}
                    </span>
                </td>
                <td>
                    <span class="badge bg-secondary">
                        ${threat.ioc_type.toUpperCase()}
                    </span>
                </td>
            `;
            tbody.appendChild(row);
        });

    } catch (error) {
        console.error('Error loading top threats:', error);
    }
}

// Update recent activity
function updateRecentActivity() {
    const activityContainer = document.getElementById('recentActivity');

    // Sample activity data (would come from API)
    const activities = [
        { type: 'ioc_added', message: 'New IOC: malware.com', time: '2 minutes ago' },
        { type: 'feed_refresh', message: 'VirusTotal feed refreshed', time: '15 minutes ago' },
        { type: 'ioc_updated', message: 'IOC 192.168.1.1 updated', time: '1 hour ago' },
        { type: 'threat_detected', message: 'High threat IOC detected', time: '2 hours ago' }
    ];

    activityContainer.innerHTML = activities.map(activity => `
        <div class="d-flex align-items-center mb-2">
            <i class="fas ${getActivityIcon(activity.type)} text-muted me-2"></i>
            <div class="flex-grow-1">
                <small class="text-muted">${activity.message}</small>
            </div>
            <small class="text-muted">${activity.time}</small>
        </div>
    `).join('');
}

// Update recent IOCs table
async function updateRecentIOCs() {
    try {
        const response = await fetchAPI('/search?limit=20&sort=last_seen:desc');
        const iocs = response.data.results || [];

        const tbody = document.querySelector('#recentIOCsTable tbody');
        tbody.innerHTML = '';

        iocs.forEach(ioc => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="ioc-value text-truncate" style="max-width: 200px;" title="${ioc.value}">
                    ${ioc.value}
                </td>
                <td>
                    <span class="badge bg-secondary">${ioc.ioc_type.toUpperCase()}</span>
                </td>
                <td>
                    <span class="badge threat-${getThreatLevel(ioc.threat_score)}">
                        ${ioc.threat_score}
                    </span>
                </td>
                <td>
                    <span class="badge bg-${getThreatLevelColor(ioc.threat_level)}">
                        ${ioc.threat_level.toUpperCase()}
                    </span>
                </td>
                <td>
                    ${ioc.sources.map(source => `<span class="badge source-${source} me-1">${source}</span>`).join('')}
                </td>
                <td>
                    <small>${formatDate(ioc.last_seen)}</small>
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="viewIOC('${ioc.value}')">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });

    } catch (error) {
        console.error('Error loading recent IOCs:', error);
    }
}

// Quick IOC lookup
function performQuickLookup(iocValue) {
    window.location.href = `/lookup?value=${encodeURIComponent(iocValue)}`;
}

// View IOC details
function viewIOC(iocValue) {
    window.location.href = `/lookup?value=${encodeURIComponent(iocValue)}`;
}

// Update trends with different time periods
async function updateTrends(days) {
    try {
        showLoading();
        const response = await fetchAPI(`/trends?days=${days}`);
        updateTrendsChart(response.data);

        // Update active button
        document.querySelectorAll('.btn-group .btn').forEach(btn => {
            btn.classList.remove('active');
        });
        event.target.classList.add('active');

    } catch (error) {
        console.error('Error updating trends:', error);
        showNotification('Error updating trends', 'danger');
    } finally {
        hideLoading();
    }
}

// Refresh dashboard data
function refreshData() {
    loadDashboardData();
}

// Export data
async function exportData(format) {
    try {
        const params = new URLSearchParams({
            format: format,
            days: 30
        });

        const response = await fetch(`${API_BASE}/export?${params}`);

        if (format === 'csv') {
            // Handle CSV download
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `cti_export_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            window.URL.revokeObjectURL(url);
        } else {
            // Handle JSON download
            const data = await response.json();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `cti_export_${new Date().toISOString().split('T')[0]}.json`;
            a.click();
            window.URL.revokeObjectURL(url);
        }

        showNotification(`Data exported as ${format.toUpperCase()}`, 'success');

    } catch (error) {
        console.error('Error exporting data:', error);
        showNotification('Error exporting data', 'danger');
    }
}

// Search suggestions
async function showSearchSuggestions(query) {
    try {
        const response = await fetchAPI(`/search?q=${query}&limit=5`);
        const suggestions = response.data.results || [];

        const container = document.getElementById('searchSuggestions');

        if (suggestions.length > 0) {
            container.innerHTML = suggestions.map(suggestion => `
                <div class="suggestion-item" onclick="selectSuggestion('${suggestion.value}')">
                    <div class="d-flex justify-content-between align-items-center">
                        <span>${suggestion.value}</span>
                        <small class="text-muted">${suggestion.ioc_type}</small>
                    </div>
                </div>
            `).join('');
            container.style.display = 'block';
        } else {
            hideSearchSuggestions();
        }
    } catch (error) {
        console.error('Error loading suggestions:', error);
        hideSearchSuggestions();
    }
}

function hideSearchSuggestions() {
    document.getElementById('searchSuggestions').style.display = 'none';
}

function selectSuggestion(value) {
    document.getElementById('quickSearchInput').value = value;
    hideSearchSuggestions();
    performQuickLookup(value);
}

// Utility functions
function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function getThreatLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
}

function getThreatLevelColor(level) {
    const colors = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'success'
    };
    return colors[level] || 'secondary';
}

function getActivityIcon(type) {
    const icons = {
        'ioc_added': 'fa-plus-circle text-success',
        'feed_refresh': 'fa-sync-alt text-primary',
        'ioc_updated': 'fa-edit text-info',
        'threat_detected': 'fa-exclamation-triangle text-danger'
    };
    return icons[type] || 'fa-info-circle text-muted';
}

function updateLastUpdateTime() {
    const now = new Date();
    document.getElementById('lastUpdate').textContent = now.toLocaleTimeString();
}

// Loading and notifications
function showLoading() {
    document.getElementById('loadingOverlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;

    document.body.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

// Auto-refresh functionality
function startAutoRefresh() {
    refreshInterval = setInterval(() => {
        loadDashboardData();
    }, 5 * 60 * 1000); // 5 minutes
}

function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    stopAutoRefresh();
});