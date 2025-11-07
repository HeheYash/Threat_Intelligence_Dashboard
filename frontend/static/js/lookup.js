// IOC Lookup Page JavaScript

// Global variables
let currentIOC = null;
let searchTimeout = null;

// API base URL
const API_BASE = '/api';

// Initialize lookup page
function initializeLookup() {
    console.log('Initializing IOC Lookup page...');

    // Set up event listeners
    setupEventListeners();

    // Check for URL parameters (pre-filled search)
    checkURLParameters();
}

// Set up event listeners
function setupEventListeners() {
    // Main lookup form
    document.getElementById('iocLookupForm').addEventListener('submit', function(e) {
        e.preventDefault();
        performLookup();
    });

    // Real-time search input
    const input = document.getElementById('iocInput');
    input.addEventListener('input', function() {
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
        if (!e.target.closest('#iocInput') && !e.target.closest('#searchSuggestions')) {
            hideSearchSuggestions();
        }
    });

    // Enter key to select first suggestion
    input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            const firstSuggestion = document.querySelector('.suggestion-item');
            if (firstSuggestion) {
                firstSuggestion.click();
            } else {
                performLookup();
            }
        }
    });
}

// Check URL parameters for pre-filled search
function checkURLParameters() {
    const urlParams = new URLSearchParams(window.location.search);
    const iocValue = urlParams.get('value');
    const iocType = urlParams.get('type');

    if (iocValue) {
        document.getElementById('iocInput').value = iocValue;
        if (iocType) {
            document.getElementById('iocType').value = iocType;
        }
        // Auto-perform lookup if pre-filled
        setTimeout(() => performLookup(), 500);
    }
}

// Perform IOC lookup
async function performLookup() {
    const iocValue = document.getElementById('iocInput').value.trim();
    const iocType = document.getElementById('iocType').value;

    if (!iocValue) {
        showNotification('Please enter an IOC value', 'warning');
        return;
    }

    showLoading('Searching...');

    try {
        let endpoint = `/lookup?value=${encodeURIComponent(iocValue)}`;
        if (iocType) {
            endpoint += `&type=${iocType}`;
        }

        const response = await fetchAPI(endpoint);

        if (response.success && response.data) {
            currentIOC = response.data;
            displayIOCResults(response.data);
        } else {
            showNoResults();
        }

    } catch (error) {
        console.error('Lookup error:', error);
        showNotification('Error performing IOC lookup', 'danger');
        showNoResults();
    } finally {
        hideLoading();
    }
}

// Display IOC results
function displayIOCResults(ioc) {
    // Show results section, hide no results
    document.getElementById('resultsSection').style.display = 'block';
    document.getElementById('noResults').style.display = 'none';

    // Update IOC overview card
    updateIOCOverview(ioc);

    // Update detailed sections
    updateThreatAnalysis(ioc);
    updateSourceAttribution(ioc);
    updateIOCMetadata(ioc);
    updateIOCTimeline(ioc);
    updateExternalLinks(ioc);

    // Scroll to results
    document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
}

// Update IOC overview card
function updateIOCOverview(ioc) {
    const card = document.getElementById('iocOverviewCard');
    const threatLevel = getThreatLevel(ioc.threat_score);
    const threatLevelClass = `threat-${threatLevel}`;

    card.innerHTML = `
        <div class="card-body">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <div class="d-flex align-items-center mb-3">
                        <h4 class="ioc-value me-3">${ioc.value}</h4>
                        <span class="badge ${threatLevelClass} fs-6">${ioc.threat_score}/100</span>
                    </div>
                    <div class="row">
                        <div class="col-md-3">
                            <small class="text-muted">Type</small>
                            <div><strong>${ioc.ioc_type.toUpperCase()}</strong></div>
                        </div>
                        <div class="col-md-3">
                            <small class="text-muted">Threat Level</small>
                            <div><span class="badge bg-${getThreatLevelColor(threatLevel)}">${threatLevel.toUpperCase()}</span></div>
                        </div>
                        <div class="col-md-3">
                            <small class="text-muted">First Seen</small>
                            <div><strong>${formatDate(ioc.first_seen)}</strong></div>
                        </div>
                        <div class="col-md-3">
                            <small class="text-muted">Last Seen</small>
                            <div><strong>${formatDate(ioc.last_seen)}</strong></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 text-end">
                    <div class="mb-2">
                        <small class="text-muted">Data Sources</small>
                        <div>
                            ${ioc.sources.map(source => `<span class="badge source-${source} me-1">${source}</span>`).join('')}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Update threat analysis section
function updateThreatAnalysis(ioc) {
    const container = document.getElementById('threatAnalysis');
    const threatLevel = getThreatLevel(ioc.threat_score);
    const reputation = ioc.meta.reputation || {};

    let analysisHTML = `
        <div class="mb-3">
            <div class="d-flex justify-content-between align-items-center mb-2">
                <span>Overall Threat Score</span>
                <span class="badge threat-${threatLevel} fs-6">${ioc.threat_score}/100</span>
            </div>
            <div class="progress" style="height: 20px;">
                <div class="progress-bar bg-${getThreatLevelColor(threatLevel)}"
                     style="width: ${ioc.threat_score}%">
                    ${ioc.threat_score}%
                </div>
            </div>
        </div>
    `;

    // Add reputation details if available
    if (Object.keys(reputation).length > 0) {
        analysisHTML += '<h6 class="mt-3 mb-2">Reputation Details</h6>';

        if (reputation.malicious !== undefined) {
            analysisHTML += `
                <div class="mb-2">
                    <small class="text-muted">Malicious Detections</small>
                    <div class="d-flex justify-content-between">
                        <span>${reputation.malicious} / ${reputation.total_engines || 'N/A'}</span>
                        <div class="progress" style="width: 100px; height: 8px;">
                            <div class="progress-bar bg-danger" style="width: ${(reputation.malicious / reputation.total_engines * 100) || 0}%"></div>
                        </div>
                    </div>
                </div>
            `;
        }

        if (reputation.abuse_confidence_score !== undefined) {
            analysisHTML += `
                <div class="mb-2">
                    <small class="text-muted">Abuse Confidence</small>
                    <div class="d-flex justify-content-between">
                        <span>${reputation.abuse_confidence_score}%</span>
                        <div class="progress" style="width: 100px; height: 8px;">
                            <div class="progress-bar bg-warning" style="width: ${reputation.abuse_confidence_score}%"></div>
                        </div>
                    </div>
                </div>
            `;
        }
    }

    // Add tags if available
    if (ioc.meta.tags && ioc.meta.tags.length > 0) {
        analysisHTML += `
            <div class="mt-3">
                <small class="text-muted">Threat Tags</small>
                <div class="mt-1">
                    ${ioc.meta.tags.map(tag => `<span class="badge bg-secondary me-1">${tag}</span>`).join('')}
                </div>
            </div>
        `;
    }

    container.innerHTML = analysisHTML;
}

// Update source attribution
function updateSourceAttribution(ioc) {
    const container = document.getElementById('sourceAttribution');

    let attributionHTML = '';

    ioc.sources.forEach(source => {
        const sourceInfo = getSourceInfo(source);
        const sourceData = getSourceSpecificData(ioc, source);

        attributionHTML += `
            <div class="mb-3 p-3 border rounded">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <h6 class="mb-0">${sourceInfo.name}</h6>
                    <span class="badge source-${source}">${source}</span>
                </div>
                <p class="small text-muted mb-2">${sourceInfo.description}</p>
                ${sourceData ? `<div class="small">${sourceData}</div>` : ''}
            </div>
        `;
    });

    container.innerHTML = attributionHTML || '<p class="text-muted">No source attribution available</p>';
}

// Update IOC metadata
function updateIOCMetadata(ioc) {
    const container = document.getElementById('iocMetadata');
    const meta = ioc.meta || {};

    let metadataHTML = '';

    // Common metadata fields
    const fields = [
        { key: 'country', label: 'Country', format: (val) => val || 'Unknown' },
        { key: 'asn', label: 'ASN', format: (val) => val || 'Unknown' },
        { key: 'as_owner', label: 'AS Owner', format: (val) => val || 'Unknown' },
        { key: 'isp', label: 'ISP', format: (val) => val || 'Unknown' },
        { key: 'domain', label: 'Domain', format: (val) => val || 'Unknown' },
        { key: 'usage_type', label: 'Usage Type', format: (val) => val || 'Unknown' }
    ];

    fields.forEach(field => {
        if (meta[field.key]) {
            metadataHTML += `
                <div class="metadata-item">
                    <small class="text-muted d-block">${field.label}</small>
                    <strong>${field.format(meta[field.key])}</strong>
                </div>
            `;
        }
    });

    container.innerHTML = metadataHTML || '<p class="mb-0">No additional metadata available</p>';
}

// Update IOC timeline
function updateIOCTimeline(ioc) {
    const container = document.getElementById('iocTimeline');

    const events = [
        {
            date: ioc.first_seen,
            title: 'First Detected',
            description: `IOC first discovered in ${ioc.sources.join(', ')} feeds`,
            type: 'detection'
        },
        {
            date: ioc.last_seen,
            title: 'Last Seen',
            description: 'Most recent detection of this IOC',
            type: 'update'
        },
        {
            date: ioc.created_at,
            title: 'Added to Database',
            description: 'IOC was added to our threat intelligence database',
            type: 'addition'
        }
    ];

    // Sort events by date
    events.sort((a, b) => new Date(b.date) - new Date(a.date));

    let timelineHTML = events.map(event => `
        <div class="timeline-item">
            <div class="d-flex justify-content-between align-items-start mb-1">
                <h6 class="mb-0">${event.title}</h6>
                <small class="text-muted">${formatDate(event.date)}</small>
            </div>
            <p class="small text-muted mb-0">${event.description}</p>
        </div>
    `).join('');

    container.innerHTML = timelineHTML;
}

// Update external links
function updateExternalLinks(ioc) {
    const container = document.getElementById('externalLinks');
    let linksHTML = '';

    // VirusTotal link
    if (ioc.sources.includes('virustotal')) {
        const vtURL = getVirusTotalURL(ioc.value, ioc.ioc_type);
        linksHTML += `
            <a href="${vtURL}" target="_blank" class="btn btn-outline-primary me-2 mb-2">
                <i class="fas fa-external-link-alt"></i> View on VirusTotal
            </a>
        `;
    }

    // AbuseIPDB link
    if (ioc.sources.includes('abuseipdb') && ioc.ioc_type === 'ip') {
        const abuseURL = `https://www.abuseipdb.com/check/${ioc.value}`;
        linksHTML += `
            <a href="${abuseURL}" target="_blank" class="btn btn-outline-danger me-2 mb-2">
                <i class="fas fa-external-link-alt"></i> View on AbuseIPDB
            </a>
        `;
    }

    // OTX link
    if (ioc.sources.includes('otx')) {
        const otxURL = `https://otx.alienvault.com/indicator/${ioc.ioc_type}/${ioc.value}`;
        linksHTML += `
            <a href="${otxURL}" target="_blank" class="btn btn-outline-success me-2 mb-2">
                <i class="fas fa-external-link-alt"></i> View on OTX
            </a>
        `;
    }

    // Generic search links
    const searchURLs = [
        { name: 'Google Search', url: `https://www.google.com/search?q=${encodeURIComponent(ioc.value)}`, class: 'outline-info' },
        { name: 'VirusHunter', url: `https://virushunter.pwc.com/en/search?q=${encodeURIComponent(ioc.value)}`, class: 'outline-secondary' }
    ];

    searchURLs.forEach(search => {
        linksHTML += `
            <a href="${search.url}" target="_blank" class="btn btn-${search.class} me-2 mb-2">
                <i class="fas fa-search"></i> ${search.name}
            </a>
        `;
    });

    container.innerHTML = linksHTML || '<p class="text-muted mb-0">No external links available</p>';
}

// Show no results message
function showNoResults() {
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('noResults').style.display = 'block';
}

// Export IOC data
function exportIOC(format) {
    if (!currentIOC) {
        showNotification('No IOC data to export', 'warning');
        return;
    }

    try {
        let data, filename, mimeType;

        if (format === 'json') {
            data = JSON.stringify(currentIOC, null, 2);
            filename = `ioc_${currentIOC.value}_${new Date().toISOString().split('T')[0]}.json`;
            mimeType = 'application/json';
        } else if (format === 'csv') {
            data = convertIOCToCSV(currentIOC);
            filename = `ioc_${currentIOC.value}_${new Date().toISOString().split('T')[0]}.csv`;
            mimeType = 'text/csv';
        }

        const blob = new Blob([data], { type: mimeType });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        window.URL.revokeObjectURL(url);

        showNotification(`IOC exported as ${format.toUpperCase()}`, 'success');

    } catch (error) {
        console.error('Export error:', error);
        showNotification('Error exporting IOC data', 'danger');
    }
}

// Share IOC
function shareIOC() {
    if (!currentIOC) return;

    const shareURL = `${window.location.origin}/lookup?value=${encodeURIComponent(currentIOC.value)}`;

    if (navigator.share) {
        navigator.share({
            title: 'IOC Analysis',
            text: `Analysis of ${currentIOC.value} (${currentIOC.ioc_type}) - Threat Score: ${currentIOC.threat_score}/100`,
            url: shareURL
        });
    } else {
        // Fallback: copy to clipboard
        navigator.clipboard.writeText(shareURL).then(() => {
            showNotification('IOC link copied to clipboard', 'success');
        }).catch(() => {
            showNotification('Failed to copy IOC link', 'danger');
        });
    }
}

// Add to watchlist (placeholder)
function addToWatchlist() {
    if (!currentIOC) return;

    // This would integrate with a watchlist system
    showNotification('Watchlist feature coming soon', 'info');
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
                        <div>
                            <div>${suggestion.value}</div>
                            <small class="text-muted">Score: ${suggestion.threat_score}</small>
                        </div>
                        <div class="text-end">
                            <span class="badge bg-secondary">${suggestion.ioc_type}</span>
                        </div>
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
    document.getElementById('iocInput').value = value;
    hideSearchSuggestions();
    performLookup();
}

// Clear search
function clearSearch() {
    document.getElementById('iocInput').value = '';
    document.getElementById('iocType').value = '';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('noResults').style.display = 'none';
    currentIOC = null;
    hideSearchSuggestions();
}

// Utility functions
function fetchAPI(endpoint, options = {}) {
    const defaultOptions = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    };

    return fetch(API_BASE + endpoint, { ...defaultOptions, ...options })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        });
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

function getSourceInfo(source) {
    const sources = {
        'virustotal': { name: 'VirusTotal', description: 'Online virus scanning and URL analysis service' },
        'abuseipdb': { name: 'AbuseIPDB', description: 'IP address abuse reporting and reputation database' },
        'otx': { name: 'AlienVault OTX', description: 'Open threat intelligence platform' },
        'phishtank': { name: 'PhishTank', description: 'Community-based anti-phishing service' },
        'malwaredomains': { name: 'Malware Domain List', description: 'List of known malware domains' },
        'abuse_ch_ssl': { name: 'Abuse.ch SSL', description: 'SSL certificate blacklist' },
        'feodo_tracker': { name: 'Feodo Tracker', description: 'C2 infrastructure tracking' }
    };
    return sources[source] || { name: source, description: 'Unknown source' };
}

function getSourceSpecificData(ioc, source) {
    const meta = ioc.meta || {};

    if (source === 'virustotal' && meta.reputation) {
        const rep = meta.reputation;
        return `Malicious: ${rep.malicious || 0}/${rep.total_engines || 0} engines`;
    }

    if (source === 'abuseipdb' && meta.reputation && meta.reputation.abuse_confidence_score !== undefined) {
        return `Abuse Confidence: ${meta.reputation.abuse_confidence_score}%`;
    }

    return null;
}

function getVirusTotalURL(value, type) {
    const baseURL = 'https://www.virustotal.com/gui';
    switch (type) {
        case 'ip': return `${baseURL}/ip-address/${value}`;
        case 'domain': return `${baseURL}/domain/${value}`;
        case 'url': return `${baseURL}/url/${btoa(value)}`;
        case 'hash': return `${baseURL}/file/${value}`;
        default: return `${baseURL}/search/${value}`;
    }
}

function convertIOCToCSV(ioc) {
    const headers = ['IOC', 'Type', 'Threat Score', 'Threat Level', 'Sources', 'First Seen', 'Last Seen'];
    const row = [
        ioc.value,
        ioc.ioc_type,
        ioc.threat_score,
        ioc.threat_level,
        ioc.sources.join('; '),
        ioc.first_seen,
        ioc.last_seen
    ];

    return [headers.join(','), row.join(',')].join('\n');
}

// Loading and notifications
function showLoading(message = 'Loading...') {
    document.getElementById('loadingOverlay').style.display = 'flex';
    document.querySelector('.loading-spinner').innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${message}`;
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}