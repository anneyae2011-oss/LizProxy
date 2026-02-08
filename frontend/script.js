/**
 * AI Proxy - Frontend JavaScript
 * Handles Discord OAuth login, API key display, and usage stats
 */

// Constants
const STORAGE_KEY_PREFIX = 'ai_proxy_key_prefix';
const STORAGE_FULL_KEY = 'ai_proxy_full_key';

// State
let currentKeyPrefix = null;
let fullKey = null;
let userEmail = null;

// DOM Elements
const noKeyView = document.getElementById('no-key-view');
const hasKeyView = document.getElementById('has-key-view');
const keyPrefixEl = document.getElementById('key-prefix');
const fullKeyDisplay = document.getElementById('full-key-display');
const fullKeyText = document.getElementById('full-key-text');
const usageSection = document.getElementById('usage-section');
const statusMessage = document.getElementById('status-message');
const userEmailEl = document.getElementById('user-email');

// RPM elements
const rpmProgress = document.getElementById('rpm-progress');
const rpmUsed = document.getElementById('rpm-used');
const rpmLimit = document.getElementById('rpm-limit');

// RPD elements
const rpdProgress = document.getElementById('rpd-progress');
const rpdUsed = document.getElementById('rpd-used');
const rpdLimit = document.getElementById('rpd-limit');

// Total tokens
const totalTokens = document.getElementById('total-tokens');

/**
 * Initialize the application
 */
async function init() {
    // Check URL params for OAuth callback data
    const urlParams = new URLSearchParams(window.location.search);
    
    // Handle OAuth callback
    if (urlParams.has('key')) {
        // New key generated - show it!
        const key = urlParams.get('key');
        const keyPrefix = urlParams.get('key_prefix');
        const email = urlParams.get('email');
        
        fullKey = key;
        currentKeyPrefix = keyPrefix;
        userEmail = email;
        
        localStorage.setItem(STORAGE_FULL_KEY, key);
        localStorage.setItem(STORAGE_KEY_PREFIX, keyPrefix);
        
        showHasKeyView();
        showFullKey(key);
        showStatus('Your new API key has been generated! Save it now - you won\'t see it again.', 'success');
        
        // Clean URL
        window.history.replaceState({}, document.title, '/');
        
        await fetchUsage();
        return;
    }
    
    if (urlParams.has('key_prefix') && urlParams.has('existing')) {
        // Existing user logged in
        const keyPrefix = urlParams.get('key_prefix');
        const email = urlParams.get('email');
        
        currentKeyPrefix = keyPrefix;
        userEmail = email;
        localStorage.setItem(STORAGE_KEY_PREFIX, keyPrefix);
        
        showHasKeyView();
        showStatus('Welcome back! Your existing key is still active.', 'success');
        
        // Clean URL
        window.history.replaceState({}, document.title, '/');
        
        await fetchUsage();
        return;
    }
    
    if (urlParams.has('error')) {
        const error = urlParams.get('error');
        const limit = urlParams.get('limit');
        let message;
        if (error === 'too_many_keys') {
            message = limit
                ? `This IP already has ${limit} active API keys. If you're on a shared network (VPN, university, etc.), please contact support to get access.`
                : 'This IP already has the maximum number of active API keys. If you\'re on a shared network, please contact support.';
        } else if (error === 'oauth_failed') {
            message = 'Discord login failed. Please try again.';
        } else if (error === 'no_discord_id') {
            message = 'Could not retrieve your Discord account info. Please try again.';
        } else {
            message = urlParams.get('message') || error;
            message = `Login failed: ${message}`;
        }
        showStatus(message, 'error');
        window.history.replaceState({}, document.title, '/');
    }
    
    // Check if user is logged in via cookie
    await checkLoggedIn();
}

/**
 * Check if user is logged in via /api/me endpoint
 */
async function checkLoggedIn() {
    try {
        const response = await fetch('/api/me', {
            credentials: 'include'  // Include cookies
        });
        
        if (response.ok) {
            const data = await response.json();
            
            currentKeyPrefix = data.key_prefix;
            userEmail = data.discord_email;
            
            // Check if account is pending approval (disabled)
            if (data.enabled === false) {
                showPendingApprovalView();
                return;
            }
            
            // Store full key if returned
            if (data.full_key) {
                fullKey = data.full_key;
                localStorage.setItem(STORAGE_FULL_KEY, data.full_key);
            }
            
            localStorage.setItem(STORAGE_KEY_PREFIX, data.key_prefix);
            
            showHasKeyView();
            
            // Show full key if we have it
            if (fullKey || localStorage.getItem(STORAGE_FULL_KEY)) {
                showFullKey(fullKey || localStorage.getItem(STORAGE_FULL_KEY));
            }
            
            await fetchUsage();
        } else {
            // Not logged in
            showNoKeyView();
        }
    } catch (error) {
        console.error('Error checking login status:', error);
        showNoKeyView();
    }
}

/**
 * Fetch and display usage statistics
 */
async function fetchUsage() {
    try {
        const response = await fetch('/api/me', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            updateUsageDisplay(data);
            if (usageSection) usageSection.classList.remove('hidden');
        } else if (response.status === 404 || response.status === 401) {
            if (usageSection) usageSection.classList.add('hidden');
        }
    } catch (error) {
        console.error('Error fetching usage:', error);
    }
}

/**
 * Update the usage display with new data (RPM, tokens per day, total tokens)
 */
function updateUsageDisplay(data) {
    const rpmLimitVal = 10;
    const rpdLimitVal = data.tokens_per_day_limit ?? 150000;
    
    // Update RPM
    const rpm = data.current_rpm ?? 0;
    const rpmPercent = rpmLimitVal > 0 ? (rpm / rpmLimitVal) * 100 : 0;
    rpmProgress.style.width = `${Math.min(rpmPercent, 100)}%`;
    rpmUsed.textContent = rpm;
    rpmLimit.textContent = rpmLimitVal;
    
    // Update tokens per day (current_rpd = tokens used today)
    const rpd = data.current_rpd ?? 0;
    const rpdPercent = rpdLimitVal > 0 ? (rpd / rpdLimitVal) * 100 : 0;
    rpdProgress.style.width = `${Math.min(rpdPercent, 100)}%`;
    rpdUsed.textContent = typeof rpd === 'number' ? rpd.toLocaleString() : String(rpd);
    rpdLimit.textContent = typeof rpdLimitVal === 'number' ? rpdLimitVal.toLocaleString() : rpdLimitVal;
    
    // Total tokens used (all time)
    if (totalTokens) {
        const total = data.total_tokens ?? 0;
        totalTokens.textContent = typeof total === 'number' ? total.toLocaleString() : total;
    }
}

/**
 * Copy API key to clipboard
 */
async function copyKey() {
    let keyToCopy = localStorage.getItem(STORAGE_FULL_KEY) || fullKey;
    
    if (!keyToCopy || keyToCopy.length < 10) {
        showStatus('Full key not available. It was only shown once during generation.', 'error');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(keyToCopy);
        showStatus(`API key copied! (${keyToCopy.length} chars)`, 'success');
        
        const copyBtn = document.getElementById('copy-btn');
        const originalText = copyBtn.textContent;
        copyBtn.textContent = 'Copied!';
        setTimeout(() => {
            copyBtn.textContent = originalText;
        }, 2000);
    } catch (error) {
        console.error('Error copying to clipboard:', error);
        
        // Fallback
        const textArea = document.createElement('textarea');
        textArea.value = keyToCopy;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            document.execCommand('copy');
            showStatus(`API key copied!`, 'success');
        } catch (err) {
            showStatus('Failed to copy. Please copy manually.', 'error');
        }
        
        document.body.removeChild(textArea);
    }
}

/**
 * Show the "no key" view (login prompt)
 */
function showNoKeyView() {
    noKeyView.classList.remove('hidden');
    hasKeyView.classList.add('hidden');
    if (usageSection) usageSection.classList.add('hidden');
}

/**
 * Show the "pending approval" view for disabled accounts
 */
function showPendingApprovalView() {
    noKeyView.classList.add('hidden');
    hasKeyView.classList.add('hidden');
    if (usageSection) usageSection.classList.add('hidden');
    
    // Show or create the pending approval view
    let pendingView = document.getElementById('pending-approval-view');
    if (!pendingView) {
        pendingView = document.createElement('div');
        pendingView.id = 'pending-approval-view';
        pendingView.className = 'key-view';
        pendingView.innerHTML = `
            <div class="pending-approval-message" style="text-align: center;">
                <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">⏳</div>
                <h2 style="margin-bottom: 0.5rem;">Account Pending Approval</h2>
                <p class="info-text">
                    Your application has been submitted and is waiting for admin review.
                    Once approved, your API key will be activated.
                </p>
                <p class="info-text" style="margin-top: 0.5rem;">
                    Check back later or refresh this page to see if you've been approved.
                </p>
                <div style="margin-top: 1.5rem; display: flex; gap: 1rem; justify-content: center;">
                    <button onclick="location.reload()" class="btn btn-ghost">Refresh</button>
                    <a href="/auth/logout" class="btn btn-ghost">Logout</a>
                </div>
            </div>
        `;
        const keySection = document.getElementById('key-section');
        keySection.appendChild(pendingView);
    }
    pendingView.classList.remove('hidden');
    
    // Show user email if available
    if (userEmail && userEmailEl) {
        userEmailEl.textContent = `Signed up as: ${userEmail}`;
        userEmailEl.classList.remove('hidden');
        pendingView.prepend(userEmailEl);
    }
}

/**
 * Show the "has key" view
 */
function showHasKeyView() {
    noKeyView.classList.add('hidden');
    hasKeyView.classList.remove('hidden');
    // Usage section (Per minute + Tokens per day) — keep visible so TPD is always on screen
    if (usageSection) usageSection.classList.remove('hidden');
    
    // Update key prefix display
    if (currentKeyPrefix) {
        keyPrefixEl.textContent = currentKeyPrefix;
    }
    
    // Show user email
    if (userEmail && userEmailEl) {
        userEmailEl.textContent = `Logged in as: ${userEmail}`;
        userEmailEl.classList.remove('hidden');
    }
}

/**
 * Show the full key
 */
function showFullKey(key) {
    if (!key) return;
    
    fullKeyText.textContent = key;
    fullKeyDisplay.classList.remove('hidden');
    
    fullKey = key;
    localStorage.setItem(STORAGE_FULL_KEY, key);
    
    fullKeyText.style.userSelect = 'text';
    fullKeyText.style.cursor = 'text';
}

/**
 * Show a status message
 */
function showStatus(message, type = 'info') {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`;
    statusMessage.classList.remove('hidden');
    
    setTimeout(() => {
        statusMessage.classList.add('hidden');
    }, 5000);
}

/**
 * Refresh usage data periodically
 */
function startUsageRefresh() {
    setInterval(async () => {
        if (currentKeyPrefix) {
            await fetchUsage();
        }
    }, 30000);
}

/**
 * Toggle between light and dark theme
 */
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('ai_proxy_theme', newTheme);
}

/**
 * Load saved theme preference
 */
function loadTheme() {
    const savedTheme = localStorage.getItem('ai_proxy_theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadTheme();
    init();
    startUsageRefresh();
});
