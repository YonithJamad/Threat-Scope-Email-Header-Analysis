function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// UI Elements
const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');
const analyzeRawBtn = document.getElementById('analyze-raw-btn');
const rawHeadersInput = document.getElementById('raw-headers');
const fileInput = document.getElementById('file-input');
const dropzone = document.getElementById('file-dropzone');

const inputSection = document.getElementById('input-section');
const resultsSection = document.getElementById('results-section');

let map; // Leaflet map instance
let currentMarker; // Keep track of the marker



// Tab Switching
tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        tabBtns.forEach(b => b.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        
        btn.classList.add('active');
        const tabId = btn.getAttribute('data-tab');
        document.getElementById(`tab-${tabId}`).classList.add('active');
    });
});

// Sidebar Navigation
const navNew = document.getElementById('nav-new');
const navHistory = document.getElementById('nav-history');
const navIntel = document.getElementById('nav-intel');
const navSettings = document.getElementById('nav-settings');
const navAbout = document.getElementById('nav-about');

const historySection = document.getElementById('history-section');
const intelSection = document.getElementById('intel-section');
const settingsSection = document.getElementById('settings-section');
const aboutSection = document.getElementById('about-section');
const autosaveToggle = document.getElementById('autosave-toggle');
const clearHistoryBtn = document.getElementById('clear-history-btn');

function setActiveNav(id) {
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const activeNav = document.getElementById(id);
    if (activeNav) activeNav.classList.add('active');
}

if (navNew) {
    navNew.addEventListener('click', (e) => {
        e.preventDefault();
        // UI reset for new analysis
        tabBtns.forEach(b => b.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        document.querySelector('[data-tab="raw"]').classList.add('active');
        document.getElementById('tab-raw').classList.add('active');
        
        inputSection.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        if (historySection) historySection.classList.add('hidden');
        if (intelSection) intelSection.classList.add('hidden');
        if (settingsSection) settingsSection.classList.add('hidden');
        if (aboutSection) aboutSection.classList.add('hidden');
        
        setActiveNav('nav-new');
        
        // Clear inputs
        rawHeadersInput.value = '';
        fileInput.value = '';
    });
}

if (navHistory) {
    navHistory.addEventListener('click', (e) => {
        e.preventDefault();
        inputSection.classList.add('hidden');
        resultsSection.classList.add('hidden');
        if (intelSection) intelSection.classList.add('hidden');
        if (settingsSection) settingsSection.classList.add('hidden');
        if (aboutSection) aboutSection.classList.add('hidden');
        if (historySection) historySection.classList.remove('hidden');
        setActiveNav('nav-history');
        loadHistory();
    });
}

if (navIntel) {
    navIntel.addEventListener('click', (e) => {
        e.preventDefault();
        inputSection.classList.add('hidden');
        resultsSection.classList.add('hidden');
        if (historySection) historySection.classList.add('hidden');
        if (settingsSection) settingsSection.classList.add('hidden');
        if (aboutSection) aboutSection.classList.add('hidden');
        if (intelSection) intelSection.classList.remove('hidden');
        setActiveNav('nav-intel');
        loadThreatFeed();
    });
}

if (navSettings) {
    navSettings.addEventListener('click', (e) => {
        e.preventDefault();
        inputSection.classList.add('hidden');
        resultsSection.classList.add('hidden');
        if (historySection) historySection.classList.add('hidden');
        if (intelSection) intelSection.classList.add('hidden');
        if (aboutSection) aboutSection.classList.add('hidden');
        if (settingsSection) settingsSection.classList.remove('hidden');
        setActiveNav('nav-settings');
        
        // Initialize settings states in UI
        const currentTheme = localStorage.getItem('threatscope_theme') || 'system';
        const currentColor = localStorage.getItem('threatscope_color') || '#06B6D4';
        const currentAutosave = localStorage.getItem('threatscope_autosave') !== 'false';
        
        document.querySelectorAll('.theme-btn').forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-theme') === currentTheme);
        });
        
        document.querySelectorAll('.color-btn').forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-color') === currentColor);
        });
        
        if (autosaveToggle) {
            autosaveToggle.checked = currentAutosave;
        }

        const vtApiKeyInput = document.getElementById('vt-api-key');
        if (vtApiKeyInput) {
            vtApiKeyInput.value = localStorage.getItem('threatscope_vt_api_key') || '';
        }
    });
}

if (navAbout) {
    navAbout.addEventListener('click', (e) => {
        e.preventDefault();
        inputSection.classList.add('hidden');
        resultsSection.classList.add('hidden');
        if (historySection) historySection.classList.add('hidden');
        if (intelSection) intelSection.classList.add('hidden');
        if (settingsSection) settingsSection.classList.add('hidden');
        if (aboutSection) aboutSection.classList.remove('hidden');
        setActiveNav('nav-about');
    });
}



// Drag and Drop functionality
dropzone.addEventListener('click', () => fileInput.click());

dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
});

dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
});

dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
        handleFile(e.dataTransfer.files[0]);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length) {
        handleFile(e.target.files[0]);
    }
});

function handleFile(file) {
    if (file.name.endsWith('.eml') || file.name.endsWith('.msg')) {
        processFile(file);
    } else {
        alert("Please upload a .eml or .msg file.");
    }
}

// Raw Text Analysis
analyzeRawBtn.addEventListener('click', async () => {
    const rawText = rawHeadersInput.value.trim();
    if (!rawText) {
        alert("Please paste email headers first.");
        return;
    }
    await processRaw(rawText);
});

async function processRaw(rawText) {
    showLoading();
    try {
        const headers = {
            'Content-Type': 'application/json'
        };
        const vtApiKey = localStorage.getItem('threatscope_vt_api_key') || '';
        if (vtApiKey) {
            headers['X-VT-API-Key'] = vtApiKey;
        }
        
        const response = await fetch('/api/analyze/raw', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ raw: rawText })
        });
        if (!response.ok) throw new Error("Analysis failed");
        const data = await response.json();
        renderResults(data);
    } catch (error) {
        alert("Error analyzing headers.");
        console.error(error);
        resetUI();
    }
}

async function processFile(file) {
    showLoading();
    try {
        const formData = new FormData();
        formData.append('file', file);
        
        const headers = {};
        const vtApiKey = localStorage.getItem('threatscope_vt_api_key') || '';
        if (vtApiKey) {
            headers['X-VT-API-Key'] = vtApiKey;
        }
        
        const response = await fetch('/api/analyze/file', {
            method: 'POST',
            headers: headers,
            body: formData
        });
        if (!response.ok) throw new Error("File analysis failed");
        const data = await response.json();
        renderResults(data);
    } catch (error) {
        alert("Error analyzing file.");
        console.error(error);
        resetUI();
    }
}

function showLoading() {
    inputSection.classList.add('hidden');
    resultsSection.classList.remove('hidden');
    if (historySection) historySection.classList.add('hidden');
    if (intelSection) intelSection.classList.add('hidden');
    if (aboutSection) aboutSection.classList.add('hidden');
    document.getElementById('threat-score').textContent = "...";
    document.getElementById('sender-ip').textContent = "Loading...";
    document.getElementById('ai-explanation').textContent = "Analyzing headers...";
}

function resetUI() {
    inputSection.classList.remove('hidden');
    resultsSection.classList.add('hidden');
    if (historySection) historySection.classList.add('hidden');
    if (intelSection) intelSection.classList.add('hidden');
    if (aboutSection) aboutSection.classList.add('hidden');
}

async function renderResults(data, fromHistory = false) {
    if (!map) {
        initMap();
    }
    
    updateAuthBadges(data.auth);
    renderTimeline(data.hops);
    updateThreatScore(data.score);
    
    // IP Intelligence
    document.getElementById('sender-ip').textContent = data.origin_ip || "Unknown";
    
    if (currentMarker) {
        map.removeLayer(currentMarker);
        currentMarker = null;
    }
    
    if (data.ip_data) {
        const ipd = data.ip_data;
        const senderLocEl = document.getElementById('sender-location');
        senderLocEl.innerHTML = '';
        const locIcon = document.createElement('i');
        locIcon.className = 'fa-solid fa-location-dot';
        senderLocEl.appendChild(locIcon);
        senderLocEl.appendChild(document.createTextNode(` ${ipd.city || ''}, ${ipd.country || 'Unknown'}`));
        
        if (ipd.latitude && ipd.longitude) {
            const latLng = [ipd.latitude, ipd.longitude];
            map.setView(latLng, 4);
            
            const popupContent = document.createElement('div');
            const boldIp = document.createElement('b');
            boldIp.textContent = 'Origin IP: ';
            popupContent.appendChild(boldIp);
            popupContent.appendChild(document.createTextNode(data.origin_ip || ''));
            popupContent.appendChild(document.createElement('br'));
            popupContent.appendChild(document.createTextNode(`${ipd.city || ''}, ${ipd.country || ''}`));
            
            currentMarker = L.marker(latLng).addTo(map)
                .bindPopup(popupContent)
                .openPopup();
        } else {
            map.setView([20, 0], 2);
        }
    } else {
        const senderLocEl = document.getElementById('sender-location');
        senderLocEl.innerHTML = '';
        const warnIcon = document.createElement('i');
        warnIcon.className = 'fa-solid fa-circle-exclamation';
        senderLocEl.appendChild(warnIcon);
        senderLocEl.appendChild(document.createTextNode(' Location Unknown'));
        map.setView([20, 0], 2);
    }
    
    renderMetadata(data.metadata);
    renderCheckpoints(data.checkpoints, data.iocs);
    renderIOCs(data.iocs);

    // AI Explanation
    document.getElementById('ai-explanation').textContent = data.ai_explanation;
    
    // Save to history
    if (!fromHistory) {
        const autoSave = localStorage.getItem('threatscope_autosave') !== 'false';
        if (autoSave) {
            saveToHistory(data);
        }
    }
}

function updateAuthBadges(results) {
    ['spf', 'dkim', 'dmarc'].forEach(protocol => {
        const badge = document.getElementById(`badge-${protocol}`);
        const statusSpan = badge.querySelector('.auth-status');
        
        let val = '';
        if (protocol === 'spf') val = results.spf;
        else if (protocol === 'dkim') val = results.dkim;
        else if (protocol === 'dmarc') val = results.dmarc;
        
        const valStr = String(val || '');
        const valLower = valStr.toLowerCase();
        
        badge.className = 'auth-badge ' + (valLower === 'pass' ? 'pass' : valLower === 'fail' ? 'fail' : '');
        statusSpan.className = 'auth-status ' + (valLower === 'pass' ? 'pass' : valLower === 'fail' ? 'fail' : 'pending');
        statusSpan.textContent = valStr.toUpperCase();
    });
}

function renderTimeline(hops) {
    const container = document.getElementById('routing-timeline');
    container.innerHTML = '';
    
    // Display hops
    // The array received is top-down (first received is last hop usually, or first hop?)
    // In standard email headers, the topmost Received is the LAST hop (closest to recipient).
    // The bottom-most Received is the FIRST hop (originating server).
    // Let's reverse it to show the originating server first.
    const chronologicalHops = [...hops].reverse();
    
    chronologicalHops.forEach((hop, i) => {
        const item = document.createElement('div');
        item.className = 'timeline-item';
        
        const dot = document.createElement('div');
        dot.className = 'timeline-dot';
        
        const content = document.createElement('div');
        content.className = 'timeline-content';
        
        const h4 = document.createElement('h4');
        h4.appendChild(document.createTextNode(`Hop ${i + 1} `));
        if (hop.ip) {
            const ipSpan = document.createElement('span');
            ipSpan.style.color = 'var(--accent-primary)';
            ipSpan.appendChild(document.createTextNode(`[${hop.ip}]`));
            h4.appendChild(ipSpan);
        }
        
        const p = document.createElement('p');
        const clockIcon = document.createElement('i');
        clockIcon.className = 'fa-regular fa-clock';
        p.appendChild(clockIcon);
        p.appendChild(document.createTextNode(` ${hop.time || ''}`));
        
        content.appendChild(h4);
        content.appendChild(p);
        
        item.appendChild(dot);
        item.appendChild(content);
        container.appendChild(item);
    });
}

function updateThreatScore(score) {
    const scoreEl = document.getElementById('threat-score');
    scoreEl.textContent = score;
    scoreEl.className = '';
    const levelEl = document.getElementById('threat-level');
    const iconEl = document.querySelector('.stat-card').querySelector('.stat-icon'); // first icon
    
    iconEl.className = 'stat-icon';
    if (score < 20) {
        levelEl.textContent = 'Safe';
        levelEl.className = 'text-success';
        scoreEl.className = 'text-success';
        iconEl.classList.add('threat-low');
        iconEl.innerHTML = '<i class="fa-solid fa-shield-check"></i>';
    } else if (score < 60) {
        levelEl.textContent = 'Suspicious';
        levelEl.className = 'text-warning';
        scoreEl.className = 'text-warning';
        iconEl.classList.add('threat-med');
        iconEl.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
    } else {
        levelEl.textContent = 'High Risk';
        levelEl.className = 'text-danger';
        scoreEl.className = 'text-danger';
        iconEl.classList.add('threat-high');
        iconEl.innerHTML = '<i class="fa-solid fa-skull-crossbones"></i>';
    }
}

function renderMetadata(metadata) {
    const grid = document.getElementById('metadata-grid');
    grid.innerHTML = '';
    
    for (const [key, value] of Object.entries(metadata)) {
        const el = document.createElement('div');
        el.className = 'meta-item fade-in';
        
        const labelDiv = document.createElement('div');
        labelDiv.className = 'meta-label';
        labelDiv.textContent = key;
        
        const valueDiv = document.createElement('div');
        valueDiv.className = 'meta-value';
        
        if (key === 'Domain DNS (MX)') {
            valueDiv.style.color = value === 'Valid' ? 'var(--success)' : 'var(--warning)';
            const icon = document.createElement('i');
            icon.className = value === 'Valid' ? 'fa-solid fa-check' : 'fa-solid fa-triangle-exclamation';
            valueDiv.appendChild(icon);
            valueDiv.appendChild(document.createTextNode(value === 'Valid' ? ' Valid' : ' Missing/Invalid'));
        } else if (key === 'X-Microsoft-Antispam-Mailbox-Delivery') {
            if (value === 'Missing') {
                valueDiv.style.color = 'var(--danger)';
                const icon = document.createElement('i');
                icon.className = 'fa-solid fa-circle-exclamation';
                valueDiv.appendChild(icon);
                valueDiv.appendChild(document.createTextNode(' Section missing from email header'));
            } else {
                valueDiv.className = 'meta-value code-font';
                valueDiv.textContent = String(value || '');
            }
        } else {
            if (key === 'Message-ID' || key === 'References' || key === 'In-Reply-To') {
                valueDiv.className = 'meta-value code-font';
            }
            valueDiv.textContent = String(value || '');
        }
        
        el.appendChild(labelDiv);
        el.appendChild(valueDiv);
        grid.appendChild(el);
    }
}

function initMap() {
    map = L.map('route-map').setView([20, 0], 2);
    
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
        subdomains: 'abcd',
        maxZoom: 20
    }).addTo(map);
}

// Local Storage History Logic
function saveToHistory(data) {
    try {
        let history = JSON.parse(localStorage.getItem('threatscope_history')) || [];
        
        const entry = {
            id: Date.now(),
            date: new Date().toLocaleString(),
            subject: data.metadata['Subject'] || 'No Subject',
            sender_ip: data.origin_ip || 'Unknown',
            score: data.score,
            full_data: data
        };
        
        history.unshift(entry); // add to beginning
        
        // Keep only last 50
        if (history.length > 50) history = history.slice(0, 50);
        
        localStorage.setItem('threatscope_history', JSON.stringify(history));
    } catch (e) {
        console.error('Error saving history', e);
    }
}

function loadHistory() {
    const container = document.getElementById('history-list');
    if (!container) return;
    
    container.innerHTML = '';
    
    try {
        const history = JSON.parse(localStorage.getItem('threatscope_history')) || [];
        
        if (history.length === 0) {
            container.innerHTML = '<div class="empty-history">No past analyses found.</div>';
            return;
        }
        
        history.forEach(item => {
            const el = document.createElement('div');
            el.className = 'history-item fade-in';
            
            let colorClass = 'text-success';
            if (item.score >= 60) colorClass = 'text-danger';
            else if (item.score >= 20) colorClass = 'text-warning';
            
            const mainDiv = document.createElement('div');
            mainDiv.className = 'history-main';
            
            const dateSpan = document.createElement('span');
            dateSpan.className = 'history-date';
            dateSpan.textContent = item.date;
            
            const subjSpan = document.createElement('span');
            subjSpan.className = 'history-subject';
            subjSpan.textContent = item.subject;
            
            const senderSpan = document.createElement('span');
            senderSpan.className = 'history-sender';
            const serverIcon = document.createElement('i');
            serverIcon.className = 'fa-solid fa-server';
            senderSpan.appendChild(serverIcon);
            senderSpan.appendChild(document.createTextNode(` ${item.sender_ip}`));
            
            mainDiv.appendChild(dateSpan);
            mainDiv.appendChild(subjSpan);
            mainDiv.appendChild(senderSpan);
            
            const scoreDiv = document.createElement('div');
            scoreDiv.className = 'history-score';
            
            const labelSpan = document.createElement('span');
            labelSpan.style.fontSize = '11px';
            labelSpan.style.textTransform = 'uppercase';
            labelSpan.style.color = 'var(--text-secondary)';
            labelSpan.textContent = 'Score';
            
            const valSpan = document.createElement('span');
            valSpan.className = `history-score-val ${colorClass}`;
            valSpan.textContent = `${item.score}/100`;
            
            scoreDiv.appendChild(labelSpan);
            scoreDiv.appendChild(valSpan);
            
            el.appendChild(mainDiv);
            el.appendChild(scoreDiv);
            
            el.style.cursor = "pointer";
            el.addEventListener('click', () => {
                if (!item.full_data) {
                    alert("Sorry, full details are not available for this older scan. Please run a new scan.");
                    return;
                }
                
                const hSec = document.getElementById('history-section');
                const rSec = document.getElementById('results-section');
                if (hSec) hSec.classList.add('hidden');
                if (rSec) rSec.classList.remove('hidden');
                
                // Update nav highlighting
                setActiveNav('nav-new');
                
                renderResults(item.full_data, true);
            });
            
            container.appendChild(el);
        });
    } catch (e) {
        console.error('Error loading history', e);
        container.innerHTML = '<div class="empty-history">Error loading history.</div>';
    }
}

// Threat Intel Logic
let feedInterval;

async function loadThreatFeed(force = false) {
    const grid = document.getElementById('intel-feed-grid');
    if (!force && grid.getAttribute('data-loaded') === 'true') return; 
    
    try {
        const response = await fetch(`/api/intel/feed?t=${Date.now()}`);
        if (!response.ok) throw new Error("Feed fetch failed");
        const data = await response.json();
        
        if (data.success && data.feed.length > 0) {
            grid.innerHTML = '';
            data.feed.forEach(item => {
                const card = document.createElement('a');
                card.href = item.link;
                card.target = "_blank";
                card.className = "feed-card fade-in";
                
                // Truncate title if too long
                const titleText = item.title.length > 60 ? item.title.substring(0, 60) + "..." : item.title;
                
                const titleDiv = document.createElement('div');
                titleDiv.className = 'feed-title';
                titleDiv.textContent = titleText;
                
                const dateDiv = document.createElement('div');
                dateDiv.className = 'feed-date';
                const clockIcon = document.createElement('i');
                clockIcon.className = 'fa-regular fa-clock';
                dateDiv.appendChild(clockIcon);
                dateDiv.appendChild(document.createTextNode(` ${item.published}`));
                
                const summaryDiv = document.createElement('div');
                summaryDiv.className = 'feed-summary';
                summaryDiv.textContent = item.summary;
                
                card.appendChild(titleDiv);
                card.appendChild(dateDiv);
                card.appendChild(summaryDiv);
                
                grid.appendChild(card);
            });
            grid.setAttribute('data-loaded', 'true');
            
            // Set up auto-refresh every 5 minutes (300,000 ms)
            if (!feedInterval) {
                feedInterval = setInterval(() => {
                    loadThreatFeed(true);
                }, 300000);
            }
        } else {
            grid.innerHTML = '<div class="empty-history">No threats found in feed.</div>';
        }
    } catch (e) {
        console.error(e);
        grid.innerHTML = '<div class="empty-history">Failed to load threat feed.</div>';
    }
}



const intelSearchBtn = document.getElementById('intel-search-btn');
const intelSearchInput = document.getElementById('intel-search-input');
const intelSearchResults = document.getElementById('intel-search-results');

if (intelSearchInput) {
    intelSearchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            if (intelSearchBtn) intelSearchBtn.click();
        }
    });
}

if (intelSearchBtn) {
    intelSearchBtn.addEventListener('click', async () => {
        const rawInput = intelSearchInput ? intelSearchInput.value.trim() : '';
        if (!rawInput) return;

        intelSearchResults.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Searching...';
        intelSearchResults.classList.remove('hidden');

        try {
            const response = await fetch(`/api/intel/ip/${rawInput}`);
            const data = await response.json();

            if (data.success && data.data && data.data.success) {
                const res = data.data;
                intelSearchResults.innerHTML = '';

                const containerDiv = document.createElement('div');
                containerDiv.className = 'intel-search-result-card fade-in';

                // IP header
                const ipDiv = document.createElement('div');
                ipDiv.className = 'intel-search-result-ip';
                ipDiv.textContent = res.ip;
                containerDiv.appendChild(ipDiv);

                // Grid: Location / ISP / ASN / Type
                const gridDiv = document.createElement('div');
                gridDiv.className = 'intel-search-result-grid';

                const makeRow = (labelText, valueNode) => {
                    const row = document.createElement('div');
                    const lbl = document.createElement('strong');
                    lbl.style.color = 'var(--text-secondary)';
                    lbl.style.fontWeight = 'bold';
                    lbl.style.marginRight = '6px';
                    lbl.textContent = labelText;
                    row.appendChild(lbl);
                    if (typeof valueNode === 'string') {
                        row.appendChild(document.createTextNode(valueNode));
                    } else {
                        row.appendChild(valueNode);
                    }
                    return row;
                };

                // Location (with flag)
                const locFrag = document.createDocumentFragment();
                locFrag.appendChild(document.createTextNode(` ${res.city || ''}, ${res.country || 'Unknown'} `));
                if (res.flag && res.flag.img) {
                    const img = document.createElement('img');
                    img.src = res.flag.img;
                    img.width = 16;
                    img.style.verticalAlign = 'middle';
                    locFrag.appendChild(img);
                }
                const locRow = makeRow('Location:', '');
                locRow.lastChild.remove();
                locRow.appendChild(locFrag);

                gridDiv.appendChild(locRow);
                gridDiv.appendChild(makeRow('ISP:', ` ${res.connection ? res.connection.isp : 'Unknown'}`));
                gridDiv.appendChild(makeRow('ASN:', ` ${res.connection ? res.connection.asn : 'Unknown'}`));
                gridDiv.appendChild(makeRow('Type:', ` ${res.type || 'Unknown'}`));

                containerDiv.appendChild(gridDiv);
                intelSearchResults.appendChild(containerDiv);
            } else {
                intelSearchResults.innerHTML = '';
                const warningDiv = document.createElement('div');
                warningDiv.style.color = 'var(--warning)';
                warningDiv.textContent = 'No data found. Make sure you entered a valid public IP address.';
                intelSearchResults.appendChild(warningDiv);
            }
        } catch (error) {
            intelSearchResults.innerHTML = '';
            const warningDiv = document.createElement('div');
            warningDiv.style.color = 'var(--danger)';
            warningDiv.textContent = 'Error fetching IP intelligence details.';
            intelSearchResults.appendChild(warningDiv);
            console.error(error);
        }
    });
}


// Theme Logic for direct system theme application on boot
function applyTheme(theme) {
    if (theme === 'system') {
        const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
        document.body.classList.toggle('light-mode', prefersLight);
    } else {
        document.body.classList.toggle('light-mode', theme === 'light');
    }
}
function applyColor(colorHex) {
    document.documentElement.style.setProperty('--accent-primary', colorHex);
    document.documentElement.style.setProperty('--accent-glow', colorHex + '80');
}
const savedTheme = localStorage.getItem('threatscope_theme') || 'system';
applyTheme(savedTheme);
const savedColor = localStorage.getItem('threatscope_color') || '#06B6D4';
applyColor(savedColor);

window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', e => {
    if ((localStorage.getItem('threatscope_theme') || 'system') === 'system') {
        document.body.classList.toggle('light-mode', e.matches);
    }
});

// Settings Interactive Controls
document.querySelectorAll('.theme-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const theme = btn.getAttribute('data-theme');
        localStorage.setItem('threatscope_theme', theme);
        applyTheme(theme);
        
        document.querySelectorAll('.theme-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        showSettingsStatus("Theme updated successfully!", "success");
    });
});

document.querySelectorAll('.color-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const color = btn.getAttribute('data-color');
        localStorage.setItem('threatscope_color', color);
        applyColor(color);
        
        document.querySelectorAll('.color-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        showSettingsStatus("Accent color updated successfully!", "success");
    });
});

if (autosaveToggle) {
    autosaveToggle.addEventListener('change', () => {
        localStorage.setItem('threatscope_autosave', autosaveToggle.checked ? 'true' : 'false');
        showSettingsStatus("Auto-save settings saved!", "success");
    });
}

if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', () => {
        if (confirm("Are you sure you want to permanently delete all your saved analysis history? This action cannot be undone.")) {
            localStorage.removeItem('threatscope_history');
            showSettingsStatus("All saved analysis history has been deleted.", "success");
            loadHistory();
        }
    });
}

function showSettingsStatus(message, type) {
    const banner = document.getElementById('settings-status-banner');
    if (!banner) return;
    banner.textContent = message;
    banner.className = `settings-status ${type} fade-in`;
    banner.classList.remove('hidden');
    
    setTimeout(() => {
        banner.classList.add('hidden');
    }, 3000);
}

// VirusTotal API key setting persistence
const vtApiKeyInput = document.getElementById('vt-api-key');
const saveVtKeyBtn = document.getElementById('save-vt-key-btn');

function saveVtApiKey() {
    if (vtApiKeyInput) {
        const keyValue = vtApiKeyInput.value.trim();
        localStorage.setItem('threatscope_vt_api_key', keyValue);
        if (keyValue) {
            showSettingsStatus("VirusTotal API Key saved successfully!", "success");
        } else {
            showSettingsStatus("VirusTotal API Key removed. Reputation lookups will be limited.", "error");
        }
    }
}

if (vtApiKeyInput) {
    vtApiKeyInput.addEventListener('change', saveVtApiKey);
    vtApiKeyInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            saveVtApiKey();
        }
    });
}

if (saveVtKeyBtn) {
    saveVtKeyBtn.addEventListener('click', saveVtApiKey);
}



// IOCs tab switching
document.addEventListener('click', (e) => {
    const btn = e.target.closest('.ioc-tab-btn');
    if (btn) {
        document.querySelectorAll('.ioc-tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.ioc-tab-content').forEach(c => c.classList.remove('active'));
        
        btn.classList.add('active');
        const tabId = btn.getAttribute('data-ioc-tab');
        const activeTabContent = document.getElementById(`ioc-tab-${tabId}`);
        if (activeTabContent) {
            activeTabContent.classList.add('active');
        }
    }
});

function renderCheckpoints(checkpoints, iocs) {
    const container = document.getElementById('checkpoints-grid');
    if (!container) return;
    container.innerHTML = '';
    
    for (const [key, cp] of Object.entries(checkpoints)) {
        const col = document.createElement('div');
        col.className = 'checkpoint-col fade-in';
        
        const header = document.createElement('div');
        header.className = 'checkpoint-header';
        
        const titleSpan = document.createElement('span');
        titleSpan.className = 'checkpoint-title';
        let countSuffix = '';
        if (key === 'B' && iocs && iocs.urls) {
            const count = iocs.urls.length;
            countSuffix = ` (${count} link${count !== 1 ? 's' : ''} extracted)`;
        } else if (key === 'C' && iocs && iocs.attachments) {
            const count = iocs.attachments.length;
            countSuffix = ` (${count} file${count !== 1 ? 's' : ''} found)`;
        }
        titleSpan.appendChild(document.createTextNode(`Checkpoint ${key}: ${cp.name}${countSuffix}`));
        header.appendChild(titleSpan);
        
        const statusBadge = document.createElement('span');
        statusBadge.className = `checkpoint-badge ${cp.triggered ? 'triggered' : 'passed'}`;
        statusBadge.textContent = cp.triggered ? 'Triggered' : 'Passed';
        header.appendChild(statusBadge);
        
        col.appendChild(header);
        
        const list = document.createElement('ul');
        list.className = 'checkpoint-rule-list';
        
        cp.rules.forEach(rule => {
            const item = document.createElement('li');
            item.className = `rule-item ${rule.triggered ? 'triggered' : 'passed'}`;
            if (rule.status === 'skipped') item.classList.add('skipped');
            
            const icon = document.createElement('i');
            if (rule.triggered && rule.penalty > 0) {
                icon.className = 'fa-solid fa-circle-exclamation rule-icon';
            } else if (rule.status === 'skipped') {
                icon.className = 'fa-solid fa-circle-minus rule-icon';
            } else {
                icon.className = 'fa-solid fa-circle-check rule-icon';
            }
            item.appendChild(icon);
            
            const infoDiv = document.createElement('div');
            infoDiv.className = 'rule-info';
            
            const nameDiv = document.createElement('div');
            nameDiv.className = 'rule-name';
            nameDiv.textContent = rule.name;
            infoDiv.appendChild(nameDiv);
            
            const descDiv = document.createElement('div');
            descDiv.className = 'rule-desc';
            descDiv.textContent = rule.description;
            infoDiv.appendChild(descDiv);
            
            item.appendChild(infoDiv);
            
            if (rule.penalty > 0) {
                const penaltySpan = document.createElement('span');
                penaltySpan.className = 'rule-penalty';
                penaltySpan.textContent = `+${rule.penalty}`;
                item.appendChild(penaltySpan);
            }
            
            list.appendChild(item);
        });
        
        col.appendChild(list);
        container.appendChild(col);
    }
}

function computeHeuristicScore(ioc) {
    let score = 0;
    const flags = [];
    const val = ioc.toLowerCase();

    const badTLDs = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click','.loan','.work','.date','.racing','.win','.download','.stream'];
    const urlShorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','adf.ly','shorte.st','cutt.ly'];
    const suspiciousBrands = ['paypal','amazon','microsoft','apple','google','netflix','facebook','instagram','wellsfargo','chase','bankofamerica'];

    if (badTLDs.some(t => val.endsWith(t) || val.includes(t + '/'))) {
        score += 30; flags.push('Suspicious TLD');
    }
    if (/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(val)) {
        score += 35; flags.push('IP-based URL');
    }
    if (urlShorteners.some(s => val.includes(s))) {
        score += 20; flags.push('URL Shortener');
    }
    const domainPart = val.replace(/^https?:\/\//, '').split('/')[0];
    const subdomains = domainPart.split('.').length - 2;
    if (subdomains > 3) {
        score += 20; flags.push(`Excessive subdomains (${subdomains})`);
    }
    if (/[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}/.test(val)) {
        score += 15; flags.push('Hash-like string in URL');
    }
    if ((val.match(/%[0-9a-f]{2}/g) || []).length > 4) {
        score += 15; flags.push('Excessive URL encoding');
    }
    if (/:\d{4,5}\//.test(val)) {
        score += 10; flags.push('Unusual port in URL');
    }
    if (val.includes('login') || val.includes('signin') || val.includes('verify') || val.includes('update') || val.includes('secure')) {
        const hasSuspiciousBrand = suspiciousBrands.some(b => val.includes(b));
        if (hasSuspiciousBrand) { score += 25; flags.push('Brand impersonation keyword'); }
        else { score += 5; flags.push('Auth-related keyword'); }
    }
    if (domainPart.replace(/\.[^.]+$/, '').replace(/[a-z0-9]/gi, '').length > 3) {
        score += 10; flags.push('Non-standard characters in domain');
    }

    return { score: Math.min(score, 100), flags };
}

async function checkIOCReputation(ioc, resultContainer, btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';

    let serverData = null;
    try {
        const resp = await fetch(`/api/ioc/check?ioc=${encodeURIComponent(ioc)}`);
        const json = await resp.json();
        if (json.success) serverData = json.data;
    } catch (_) {}

    let totalScore = 0;
    let allFlags = [];

    if (serverData) {
        totalScore = serverData.score;
        allFlags = serverData.flags || [];
    } else {
        // Fallback to client-side heuristics if backend check fails
        const heuristic = computeHeuristicScore(ioc);
        totalScore = heuristic.score;
        allFlags = heuristic.flags;
    }

    // Verdict
    let verdict, verdictColor, verdictBg;
    if (totalScore >= 60) {
        verdict = 'High Risk'; verdictColor = 'var(--danger)'; verdictBg = 'rgba(239,68,68,0.12)';
    } else if (totalScore >= 25) {
        verdict = 'Suspicious'; verdictColor = 'var(--warning)'; verdictBg = 'rgba(245,158,11,0.12)';
    } else {
        verdict = 'Clean'; verdictColor = 'var(--success)'; verdictBg = 'rgba(16,185,129,0.12)';
    }

    // Render result
    resultContainer.innerHTML = '';
    resultContainer.style.cssText = `margin-top:8px;padding:10px 14px;border-radius:8px;background:${verdictBg};border:1px solid ${verdictColor}40;font-size:13px;`;

    const topRow = document.createElement('div');
    topRow.style.cssText = 'display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap;';

    const scoreEl = document.createElement('span');
    scoreEl.style.cssText = `font-weight:700;font-size:15px;color:${verdictColor};`;
    scoreEl.textContent = `Risk Score: ${totalScore}/100`;

    const verdictBadge = document.createElement('span');
    verdictBadge.style.cssText = `padding:2px 10px;border-radius:20px;font-size:11px;font-weight:700;background:${verdictBg};color:${verdictColor};border:1px solid ${verdictColor}60;`;
    verdictBadge.textContent = verdict;

    topRow.appendChild(scoreEl);
    topRow.appendChild(verdictBadge);
    resultContainer.appendChild(topRow);

    if (allFlags.length > 0) {
        const flagsEl = document.createElement('div');
        flagsEl.style.cssText = 'display:flex;flex-wrap:wrap;gap:5px;';
        allFlags.forEach(f => {
            const tag = document.createElement('span');
            tag.style.cssText = 'font-size:11px;padding:2px 8px;border-radius:4px;background:rgba(255,255,255,0.06);color:var(--text-secondary);border:1px solid rgba(255,255,255,0.1);';
            tag.textContent = f;
            flagsEl.appendChild(tag);
        });
        resultContainer.appendChild(flagsEl);
    } else {
        const okEl = document.createElement('span');
        okEl.style.cssText = 'font-size:12px;color:var(--text-secondary);';
        okEl.textContent = 'No suspicious indicators detected.';
        resultContainer.appendChild(okEl);
    }

    btn.style.display = 'none';
}

function addRepBtn(li, ioc) {
    const wrap = document.createElement('div');
    wrap.style.cssText = 'margin-top:4px;';
    const btn = document.createElement('button');
    btn.className = 'primary-btn';
    btn.style.cssText = 'padding:3px 10px;font-size:11.5px;cursor:pointer;margin-left:24px;';
    btn.innerHTML = '<i class="fa-solid fa-shield-halved"></i> Check Reputation';
    const resultContainer = document.createElement('div');
    btn.addEventListener('click', () => checkIOCReputation(ioc, resultContainer, btn));
    wrap.appendChild(btn);
    wrap.appendChild(resultContainer);
    li.appendChild(wrap);
}

function renderIOCs(iocs) {
    // IPs
    const ipsList = document.getElementById('ioc-list-ips');
    if (ipsList) {
        ipsList.innerHTML = '';
        if (!iocs.ips || iocs.ips.length === 0) {
            ipsList.innerHTML = '<li class="ioc-empty">No IPs extracted.</li>';
        } else {
            iocs.ips.forEach(ip => {
                const li = document.createElement('li');
                li.className = 'ioc-item';
                li.innerHTML = `<i class="fa-solid fa-network-wired"></i> <span class="code-font">${escapeHTML(ip)}</span>`;
                addRepBtn(li, ip);
                ipsList.appendChild(li);
            });
        }
    }

    // Domains
    const domainsList = document.getElementById('ioc-list-domains');
    if (domainsList) {
        domainsList.innerHTML = '';
        if (!iocs.domains || iocs.domains.length === 0) {
            domainsList.innerHTML = '<li class="ioc-empty">No domains extracted.</li>';
        } else {
            iocs.domains.forEach(domain => {
                const li = document.createElement('li');
                li.className = 'ioc-item';
                li.innerHTML = `<i class="fa-solid fa-globe"></i> <span class="code-font">${escapeHTML(domain)}</span>`;
                addRepBtn(li, domain);
                domainsList.appendChild(li);
            });
        }
    }

    // URLs
    const urlsList = document.getElementById('ioc-list-urls');
    if (urlsList) {
        urlsList.innerHTML = '';
        if (!iocs.urls || iocs.urls.length === 0) {
            urlsList.innerHTML = '<li class="ioc-empty">No URLs extracted.</li>';
        } else {
            iocs.urls.forEach(url => {
                const li = document.createElement('li');
                li.className = 'ioc-item';
                li.innerHTML = `<i class="fa-solid fa-link"></i> <a href="${escapeHTML(url)}" target="_blank" class="code-font">${escapeHTML(url)}</a>`;
                addRepBtn(li, url);
                urlsList.appendChild(li);
            });
        }
    }

    // Attachments
    const attBody = document.getElementById('ioc-attachments-body');
    if (attBody) {
        attBody.innerHTML = '';
        if (!iocs.attachments || iocs.attachments.length === 0) {
            attBody.innerHTML = '<tr><td colspan="6" class="ioc-empty">No attachments found.</td></tr>';
        } else {
            iocs.attachments.forEach(att => {
                const tr = document.createElement('tr');
                
                const tdName = document.createElement('td');
                tdName.className = 'code-font';
                tdName.textContent = att.filename;
                tr.appendChild(tdName);
                
                const tdSize = document.createElement('td');
                tdSize.textContent = formatBytes(att.size);
                tr.appendChild(tdSize);
                
                const tdHash = document.createElement('td');
                tdHash.className = 'code-font';
                tdHash.style.fontSize = '12px';
                tdHash.textContent = att.sha256;
                tr.appendChild(tdHash);
                
                const tdFormat = document.createElement('td');
                tdFormat.className = 'code-font';
                tdFormat.textContent = att.magic_bytes_type.toUpperCase();
                if (att.magic_bytes_mismatch) {
                    tdFormat.className += ' text-danger';
                    tdFormat.innerHTML += ` <i class="fa-solid fa-triangle-exclamation" title="${escapeHTML(att.magic_bytes_mismatch)}"></i>`;
                }
                tr.appendChild(tdFormat);
                
                const tdDouble = document.createElement('td');
                if (att.double_extension) {
                    tdDouble.innerHTML = '<span class="status-badge alert-danger">YES</span>';
                } else {
                    tdDouble.innerHTML = '<span class="status-badge alert-success">NO</span>';
                }
                tr.appendChild(tdDouble);
                
                const tdMacro = document.createElement('td');
                if (att.has_macros) {
                    tdMacro.innerHTML = '<span class="status-badge alert-danger">MACROS FOUND</span>';
                } else {
                    if (att.magic_bytes_type === 'zip/office') {
                        tdMacro.innerHTML = '<span class="status-badge alert-success">CLEAN</span>';
                    } else {
                        tdMacro.innerHTML = '<span style="color: var(--text-secondary);">N/A</span>';
                    }
                }
                tr.appendChild(tdMacro);
                
                tr.className = 'fade-in';
                attBody.appendChild(tr);
            });
        }
    }
}

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

