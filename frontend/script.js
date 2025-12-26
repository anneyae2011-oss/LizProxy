/**
 * AI Proxy - Frontend JavaScript
 * Handles API key generation, usage display, and model fetching
 */

// Constants
const STORAGE_KEY = 'ai_proxy_key_id';
const STORAGE_KEY_PREFIX = 'ai_proxy_key_prefix';
const STORAGE_FULL_KEY = 'ai_proxy_full_key';
const STORAGE_FINGERPRINT = 'ai_proxy_fingerprint';

// State
let currentKeyPrefix = null;
let fullKey = null;
let browserFingerprint = null;

// DOM Elements
const noKeyView = document.getElementById('no-key-view');
const hasKeyView = document.getElementById('has-key-view');
const keyPrefixEl = document.getElementById('key-prefix');
const fullKeyDisplay = document.getElementById('full-key-display');
const fullKeyText = document.getElementById('full-key-text');
const usageSection = document.getElementById('usage-section');
const modelsSection = document.getElementById('models-section');
const statusMessage = document.getElementById('status-message');

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

// Models elements
const modelsList = document.getElementById('models-list');
const modelsUl = document.getElementById('models-ul');

/**
 * Generate a browser fingerprint based on various browser characteristics.
 * This is a simple fingerprint - not meant to be cryptographically secure,
 * just unique enough to identify returning users.
 */
async function generateFingerprint() {
    const components = [];
    
    // Screen info
    components.push(screen.width + 'x' + screen.height);
    components.push(screen.colorDepth);
    components.push(window.devicePixelRatio || 1);
    
    // Timezone
    components.push(Intl.DateTimeFormat().resolvedOptions().timeZone);
    
    // Language
    components.push(navigator.language);
    components.push((navigator.languages || []).join(','));
    
    // Platform
    components.push(navigator.platform);
    
    // Hardware concurrency (CPU cores)
    components.push(navigator.hardwareConcurrency || 'unknown');
    
    // Device memory (if available)
    components.push(navigator.deviceMemory || 'unknown');
    
    // Touch support
    components.push('ontouchstart' in window ? 'touch' : 'no-touch');
    components.push(navigator.maxTouchPoints || 0);
    
    // WebGL renderer (graphics card info)
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                components.push(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL));
                components.push(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL));
            }
        }
    } catch (e) {
        components.push('no-webgl');
    }
    
    // Canvas fingerprint
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('fingerprint', 2, 2);
        components.push(canvas.toDataURL().slice(-50));
    } catch (e) {
        components.push('no-canvas');
    }
    
    // Audio context fingerprint
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        components.push(audioCtx.sampleRate);
        audioCtx.close();
    } catch (e) {
        components.push('no-audio');
    }
    
    // Join all components and hash
    const fingerprintString = components.join('|');
    
    // Simple hash function (djb2)
    let hash = 5381;
    for (let i = 0; i < fingerprintString.length; i++) {
        hash = ((hash << 5) + hash) + fingerprintString.charCodeAt(i);
        hash = hash & hash; // Convert to 32-bit integer
    }
    
    // Convert to hex string
    const fingerprint = Math.abs(hash).toString(16).padStart(8, '0');
    
    // Store for later use
    localStorage.setItem(STORAGE_FINGERPRINT, fingerprint);
    
    return fingerprint;
}

/**
 * Get or generate browser fingerprint
 */
async function getFingerprint() {
    // Check if we have a stored fingerprint
    let fingerprint = localStorage.getItem(STORAGE_FINGERPRINT);
    
    if (!fingerprint) {
        fingerprint = await generateFingerprint();
    }
    
    return fingerprint;
}

/**
 * Initialize the application
 */
async function init() {
    // Generate fingerprint on init
    browserFingerprint = await getFingerprint();
    await checkExistingKey();
}

/**
 * Check if user has an existing key for their IP
 * Verifies localStorage against current IP
 */
async function checkExistingKey() {
    const storedKeyPrefix = localStorage.getItem(STORAGE_KEY_PREFIX);
    
    if (!storedKeyPrefix) {
        showNoKeyView();
        return;
    }
    
    try {
        const response = await fetch('/api/my-key');
        
        if (response.ok) {
            const data = await response.json();
            
            // Verify the stored key matches the IP's key
            if (data.key_prefix === storedKeyPrefix) {
                currentKeyPrefix = data.key_prefix;
                showHasKeyView();
                await fetchUsage();
            } else {
                // Key doesn't match IP, clear storage
                clearStorage();
                showNoKeyView();
            }
        } else if (response.status === 404) {
            // No key for this IP
            clearStorage();
            showNoKeyView();
        } else if (response.status === 403) {
            // IP is banned
            showStatus('Your IP address has been banned.', 'error');
            showNoKeyView();
        } else {
            showNoKeyView();
        }
    } catch (error) {
        console.error('Error checking existing key:', error);
        showNoKeyView();
    }
}


/**
 * Generate a new API key
 */
async function generateKey() {
    const generateBtn = document.getElementById('generate-btn');
    generateBtn.disabled = true;
    generateBtn.textContent = 'Generating...';
    
    try {
        // Get fingerprint
        const fingerprint = await getFingerprint();
        
        const response = await fetch('/api/generate-key', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ fingerprint })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentKeyPrefix = data.key_prefix;
            
            // Store key info
            localStorage.setItem(STORAGE_KEY_PREFIX, data.key_prefix);
            
            // If this is a new key, we get the full key
            if (data.key) {
                fullKey = data.key;
                localStorage.setItem(STORAGE_FULL_KEY, data.key);
                showFullKey(data.key);
            }
            
            showHasKeyView();
            showStatus(data.message, 'success');
            await fetchUsage();
        } else if (response.status === 403) {
            showStatus('Your IP address has been banned.', 'error');
        } else {
            showStatus(data.error || 'Failed to generate key', 'error');
        }
    } catch (error) {
        console.error('Error generating key:', error);
        showStatus('Network error. Please try again.', 'error');
    } finally {
        generateBtn.disabled = false;
        generateBtn.textContent = 'Generate API Key';
    }
}

/**
 * Fetch and display usage statistics
 */
async function fetchUsage() {
    try {
        const response = await fetch('/api/my-usage');
        
        if (response.ok) {
            const data = await response.json();
            updateUsageDisplay(data);
            usageSection.classList.remove('hidden');
            modelsSection.classList.remove('hidden');
        } else if (response.status === 404) {
            usageSection.classList.add('hidden');
        }
    } catch (error) {
        console.error('Error fetching usage:', error);
    }
}

/**
 * Update the usage display with new data
 */
function updateUsageDisplay(data) {
    // Update RPM
    const rpmPercent = (data.rpm_used / data.rpm_limit) * 100;
    rpmProgress.style.width = `${Math.min(rpmPercent, 100)}%`;
    rpmUsed.textContent = data.rpm_used;
    rpmLimit.textContent = data.rpm_limit;
    
    // Update RPD
    const rpdPercent = (data.rpd_used / data.rpd_limit) * 100;
    rpdProgress.style.width = `${Math.min(rpdPercent, 100)}%`;
    rpdUsed.textContent = data.rpd_used;
    rpdLimit.textContent = data.rpd_limit;
    
    // Update total tokens
    totalTokens.textContent = formatNumber(data.total_tokens);
    
    // Color progress bars based on usage
    updateProgressBarColor(rpmProgress, rpmPercent);
    updateProgressBarColor(rpdProgress, rpdPercent);
}

/**
 * Update progress bar color based on percentage
 * Now uses consistent lavender gradient - no color changes
 */
function updateProgressBarColor(element, percent) {
    // Keep consistent lavender gradient regardless of percentage
    // The segmented style handles visual feedback
}

/**
 * Format large numbers with commas
 */
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}


/**
 * Copy API key to clipboard
 */
async function copyKey() {
    // Try to get the full key from storage or use the prefix
    const keyToCopy = localStorage.getItem(STORAGE_FULL_KEY) || currentKeyPrefix;
    
    if (!keyToCopy) {
        showStatus('No key available to copy', 'error');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(keyToCopy);
        showStatus('API key copied to clipboard!', 'success');
        
        // Visual feedback on button
        const copyBtn = document.getElementById('copy-btn');
        const originalText = copyBtn.textContent;
        copyBtn.textContent = 'Copied!';
        setTimeout(() => {
            copyBtn.textContent = originalText;
        }, 2000);
    } catch (error) {
        console.error('Error copying to clipboard:', error);
        
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = keyToCopy;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            document.execCommand('copy');
            showStatus('API key copied to clipboard!', 'success');
        } catch (err) {
            showStatus('Failed to copy. Please copy manually.', 'error');
        }
        
        document.body.removeChild(textArea);
    }
}

/**
 * Fetch and display available models
 */
async function fetchModels() {
    const fetchBtn = document.getElementById('fetch-models-btn');
    fetchBtn.disabled = true;
    fetchBtn.textContent = 'Loading...';
    
    // Get the API key for authentication
    const apiKey = localStorage.getItem(STORAGE_FULL_KEY);
    
    if (!apiKey) {
        showStatus('No API key available. Please generate a key first.', 'error');
        fetchBtn.disabled = false;
        fetchBtn.textContent = 'Fetch Models';
        return;
    }
    
    try {
        const response = await fetch('/v1/models', {
            headers: {
                'Authorization': `Bearer ${apiKey}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            displayModels(data.data || []);
        } else if (response.status === 401) {
            showStatus('Invalid API key. Please regenerate.', 'error');
        } else if (response.status === 429) {
            showStatus('Rate limit exceeded. Please wait.', 'error');
        } else {
            const errorData = await response.json().catch(() => ({}));
            showStatus(errorData.error || 'Failed to fetch models', 'error');
        }
    } catch (error) {
        console.error('Error fetching models:', error);
        showStatus('Network error. Please try again.', 'error');
    } finally {
        fetchBtn.disabled = false;
        fetchBtn.textContent = 'Fetch Models';
    }
}

/**
 * Display the list of available models
 */
function displayModels(models) {
    modelsUl.innerHTML = '';
    
    if (models.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'No models available';
        modelsUl.appendChild(li);
    } else {
        models.forEach(model => {
            const li = document.createElement('li');
            li.textContent = model.id || model;
            modelsUl.appendChild(li);
        });
    }
    
    modelsList.classList.remove('hidden');
}


/**
 * Show the "no key" view
 */
function showNoKeyView() {
    noKeyView.classList.remove('hidden');
    hasKeyView.classList.add('hidden');
    usageSection.classList.add('hidden');
    modelsSection.classList.add('hidden');
}

/**
 * Show the "has key" view
 */
function showHasKeyView() {
    noKeyView.classList.add('hidden');
    hasKeyView.classList.remove('hidden');
    
    // Update key prefix display
    if (currentKeyPrefix) {
        keyPrefixEl.textContent = currentKeyPrefix;
    }
}

/**
 * Show the full key (only on first generation)
 */
function showFullKey(key) {
    fullKeyText.textContent = key;
    fullKeyDisplay.classList.remove('hidden');
    
    // Hide after 60 seconds for security
    setTimeout(() => {
        fullKeyDisplay.classList.add('hidden');
    }, 60000);
}

/**
 * Show a status message
 */
function showStatus(message, type = 'info') {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`;
    statusMessage.classList.remove('hidden');
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        statusMessage.classList.add('hidden');
    }, 5000);
}

/**
 * Clear localStorage
 */
function clearStorage() {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(STORAGE_KEY_PREFIX);
    localStorage.removeItem(STORAGE_FULL_KEY);
    currentKeyPrefix = null;
    fullKey = null;
}

/**
 * Refresh usage data periodically
 */
function startUsageRefresh() {
    // Refresh usage every 30 seconds
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

/**
 * Add sparkle effect to copy button
 */
function addCopySparkle() {
    const copyBtn = document.getElementById('copy-btn');
    if (copyBtn) {
        copyBtn.classList.add('copied');
        setTimeout(() => {
            copyBtn.classList.remove('copied');
        }, 600);
    }
}

// Override copyKey to add sparkle
const originalCopyKey = copyKey;
copyKey = async function() {
    await originalCopyKey();
    addCopySparkle();
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadTheme();
    init();
    startUsageRefresh();
});
