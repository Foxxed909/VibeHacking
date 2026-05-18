// Shielder+ Popup Script (v1.1.0 - Security Suite)

// Storage Polyfill for non-extension environment
const storage = (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) ? chrome.storage.local : {
    get: (keys, callback) => {
        const result = {};
        const keyList = Array.isArray(keys) ? keys : [keys];
        keyList.forEach(key => {
            const val = localStorage.getItem('shielder_' + key);
            result[key] = val ? JSON.parse(val) : undefined;
        });
        setTimeout(() => callback(result), 0);
    },
    set: (data, callback) => {
        Object.keys(data).forEach(key => {
            localStorage.setItem('shielder_' + key, JSON.stringify(data[key]));
        });
        if (callback) setTimeout(callback, 0);
    }
};

// State
let stats = { adsBlocked: 0, bandwidthSaved: 0, trackersBlocked: 0, timeSaved: 0 };
let settings = { blockAds: true, privacyMode: false, cookieConsent: false, whitelist: [], tier: 'pro' };
let passwords = [];

// DOM Elements
const tabs = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

// Initialization
storage.get(['stats', 'settings', 'passwords'], (result) => {
    if (result.stats) stats = result.stats;
    if (result.settings) settings = result.settings;
    if (result.passwords) passwords = result.passwords;
    
    updateStatsDisplay();
    loadSettings();
    renderPasswordList();
});

// Tab Switching
tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const target = tab.dataset.tab;
        
        tabs.forEach(t => t.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        
        tab.classList.add('active');
        document.getElementById(`${target}Tab`).classList.add('active');
    });
});

// Stats Display
function updateStatsDisplay() {
    document.getElementById('adsBlocked').textContent = formatNumber(stats.adsBlocked);
    document.getElementById('bandwidthSaved').textContent = formatBytes(stats.bandwidthSaved);
    document.getElementById('trackersBlocked').textContent = formatNumber(stats.trackersBlocked);
    document.getElementById('timeSaved').textContent = formatTime(stats.timeSaved);
}

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function formatBytes(bytes) {
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
    return bytes + ' B';
}

function formatTime(seconds) {
    const minutes = Math.floor(seconds / 60);
    if (minutes >= 60) return Math.floor(minutes / 60) + 'h';
    return minutes + 'm';
}

// Settings Logic
function loadSettings() {
    document.getElementById('blockAdsToggle').classList.toggle('active', settings.blockAds);
    document.getElementById('privacyToggle').classList.toggle('active', settings.privacyMode);
    document.getElementById('cookieToggle').classList.toggle('active', settings.cookieConsent);
    
    document.querySelectorAll('.membership-tier').forEach(tier => {
        tier.classList.toggle('active', tier.dataset.tier === settings.tier);
    });
}

document.querySelectorAll('.toggle').forEach(toggle => {
    toggle.addEventListener('click', function() {
        this.classList.toggle('active');
        const active = this.classList.contains('active');
        
        if (this.id === 'blockAdsToggle') settings.blockAds = active;
        else if (this.id === 'privacyToggle') settings.privacyMode = active;
        else if (this.id === 'cookieToggle') settings.cookieConsent = active;
        
        saveSettings();
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
            chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', settings });
        }
    });
});

function saveSettings() {
    storage.set({ settings });
}

// Vault Logic
const vaultForm = document.getElementById('vaultForm');
const passwordList = document.getElementById('passwordList');

document.getElementById('showAddForm').addEventListener('click', () => {
    vaultForm.style.display = 'flex';
});

document.getElementById('closeForm').addEventListener('click', () => {
    vaultForm.style.display = 'none';
});

document.getElementById('savePassword').addEventListener('click', () => {
    const site = document.getElementById('passSite').value.trim();
    const user = document.getElementById('passUser').value.trim();
    const pass = document.getElementById('passValue').value.trim();
    
    if (site && user && pass) {
        passwords.push({ id: Date.now(), site, user, pass });
        storage.set({ passwords }, () => {
            renderPasswordList();
            vaultForm.style.display = 'none';
            clearForm();
            showToast('Password Saved!');
        });
    }
});

function clearForm() {
    document.getElementById('passSite').value = '';
    document.getElementById('passUser').value = '';
    document.getElementById('passValue').value = '';
}

function renderPasswordList() {
    if (passwords.length === 0) {
        passwordList.innerHTML = `<div style="text-align: center; opacity: 0.5; padding: 20px; font-size: 13px;">No passwords saved yet.</div>`;
        return;
    }
    
    passwordList.innerHTML = '';
    passwords.forEach(p => {
        const item = document.createElement('div');
        item.className = 'password-item';
        item.innerHTML = `
            <div class="pass-site">${p.site}</div>
            <div class="pass-user">${p.user}</div>
            <div class="pass-actions">
                <button class="action-btn" onclick="copyToClipboard('${p.pass}')">Copy</button>
                <button class="action-btn" style="color: #fc8181;" onclick="deletePassword(${p.id})">Delete</button>
            </div>
        `;
        passwordList.appendChild(item);
    });
}

window.copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Password Copied!');
    });
};

window.deletePassword = (id) => {
    passwords = passwords.filter(p => p.id !== id);
    storage.set({ passwords }, () => {
        renderPasswordList();
        showToast('Deleted');
    });
};

// Password Generator
document.getElementById('generateBtn').addEventListener('click', () => {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
    let retVal = "";
    for (let i = 0, n = charset.length; i < 16; ++i) {
        retVal += charset.charAt(Math.floor(Math.random() * n));
    }
    document.getElementById('genResult').textContent = retVal;
});

// Toast / Notifications
function showToast(message) {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        bottom: 70px;
        left: 50%;
        transform: translateX(-50%);
        background: #48bb78;
        color: white;
        padding: 8px 16px;
        border-radius: 20px;
        font-size: 12px;
        z-index: 1000;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2000);
}

// Whitelist Quick Add
document.getElementById('addToWhitelist').addEventListener('click', () => {
    const input = document.getElementById('whitelistInput');
    const domain = input.value.trim();
    if (domain && !settings.whitelist.includes(domain)) {
        settings.whitelist.push(domain);
        saveSettings();
        input.value = '';
        showToast('Added to whitelist');
    }
});

// Tier selection
document.querySelectorAll('.membership-tier').forEach(tier => {
    tier.addEventListener('click', function() {
        document.querySelectorAll('.membership-tier').forEach(t => t.classList.remove('active'));
        this.classList.add('active');
        settings.tier = this.dataset.tier;
        saveSettings();
    });
});

// Upgrade button
document.getElementById('upgradeBtn').addEventListener('click', () => {
    const url = 'https://shielder.app/upgrade';
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url });
    } else {
        window.open(url, '_blank');
    }
});

// Check if current site is whitelisted
if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].url && tabs[0].url.startsWith('http')) {
            try {
                const url = new URL(tabs[0].url);
                const isWhitelisted = settings.whitelist.some(domain => 
                    url.hostname.includes(domain)
                );
                
                if (isWhitelisted) {
                    showToast('Shielder+ is disabled on this site');
                }
            } catch (e) {
                console.log('Context check skipped');
            }
        }
    });
}

