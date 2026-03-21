/**
 * LizRP Frontend Logic
 */

// ===================================
// State & Configuration
// ===================================
const RP_TOKEN_KEY = 'lizrp_access_token';

let currentUser = null;
let currentChatId = null;
let currentBotId = null;
let isGenerating = false;
let myOcs = [];

// DOM Elements
const discoveryHub = document.getElementById('discovery-hub');
const botProfileView = document.getElementById('bot-profile-view');
const chatInterface = document.getElementById('chat-interface');
const botsGrid = document.getElementById('bots-grid');
const oldChatsList = document.getElementById('old-chats-list');
const menuOldChats = document.getElementById('menu-old-chats');

// Menu Settings Elements
const modelSelect = document.getElementById('menu-model-select');
const ocSelect = document.getElementById('menu-oc-select');
const chatMenuDropdown = document.getElementById('chat-menu-dropdown');
const chatMenuToggle = document.getElementById('chat-menu-toggle');

// Auth DOM
const authNavBtn = document.getElementById('auth-nav-btn');
const userProfileMenu = document.getElementById('user-profile-menu');
const navUsername = document.getElementById('nav-username');

// Profile Settings DOM
const profileModal = document.getElementById('profile-modal');
const profileUsernameInput = document.getElementById('profile-username');
const profileAvatarPreview = document.getElementById('profile-avatar-preview');
const profileAvatarPlaceholder = document.getElementById('profile-avatar-placeholder');

// Profile DOM
const profileBotAvatar = document.getElementById('profile-bot-avatar');
const profileBotName = document.getElementById('profile-bot-name');
const profileBotCreator = document.getElementById('profile-bot-creator');
const profileBotDesc = document.getElementById('profile-bot-desc');
const profileTags = document.getElementById('profile-tags');

// Chat DOM
const chatMessagesContainer = document.getElementById('chat-messages');
const chatInput = document.getElementById('chat-input');
const chatBotAvatar = document.getElementById('chat-bot-avatar');
const chatBotName = document.getElementById('chat-bot-name');
const chatBotCreator = document.getElementById('chat-bot-creator');

// ===================================
// Initialization
// ===================================

document.addEventListener('DOMContentLoaded', () => {
    loadTheme();
    initRP();
    initEventListeners();
});

function initEventListeners() {
    // Menu Toggle
    if (chatMenuToggle) {
        chatMenuToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleChatMenu();
        });
    }

    // Close menu on outside click
    document.addEventListener('click', (e) => {
        if (chatMenuDropdown && !chatMenuDropdown.classList.contains('hidden')) {
            if (!chatMenuDropdown.contains(e.target)) {
                closeChatMenu();
            }
        }
    });

    // Close menu on Escape
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeChatMenu();
            closeModal('auth-modal');
            closeModal('bot-modal');
            closeModal('oc-modal');
            closeModal('profile-modal');
        }
    });
}

async function initRP() {
    // 1. Check Auth Status
    await checkAuth();
    
    // 2. Load Public Content (Bots & Models)
    await loadPublicModels();
    await loadDiscoveryHub();
    
    // 3. Set Wallpaper from LocalStorage
    loadSavedWallpaper();
}

function loadTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }
}

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
}

// ===================================
// Authentication
// ===================================

let isLoginMode = true;

function showLoginModal() {
    isLoginMode = true;
    document.getElementById('auth-title').textContent = 'Sign In';
    document.getElementById('auth-submit-btn').textContent = 'Sign In';
    document.getElementById('auth-error').classList.add('hidden');
    document.getElementById('auth-modal').classList.remove('hidden');
}

function toggleAuthMode() {
    isLoginMode = !isLoginMode;
    const title = document.getElementById('auth-title');
    const btn = document.getElementById('auth-submit-btn');
    const link = document.querySelector('#auth-form .accent-link');
    
    if (isLoginMode) {
        title.textContent = 'Sign In';
        btn.textContent = 'Sign In';
        link.textContent = "Don't have an account? Register here";
    } else {
        title.textContent = 'Create Account';
        btn.textContent = 'Register';
        link.textContent = "Already have an account? Sign in here";
    }
}

async function handleAuthSubmit(e) {
    e.preventDefault();
    const btn = document.getElementById('auth-submit-btn');
    const errorEl = document.getElementById('auth-error');
    
    const username = document.getElementById('auth-username').value.trim();
    const password = document.getElementById('auth-password').value;
    
    btn.disabled = true;
    errorEl.classList.add('hidden');
    
    const endpoint = isLoginMode ? '/login' : '/register';
    
    try {
        const res = await fetch(`/api/rp${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await res.json();
        if (res.ok) {
            localStorage.setItem(RP_TOKEN_KEY, data.access_token);
            closeModal('auth-modal');
            await checkAuth();
            showToast(`Welcome, ${username}!`, 'success');
        } else {
            errorEl.textContent = data.detail || 'Authentication failed';
            errorEl.classList.remove('hidden');
        }
    } catch (err) {
        errorEl.textContent = err.message;
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
    }
}

async function checkAuth() {
    const token = localStorage.getItem(RP_TOKEN_KEY);
    if (!token) {
        handleLogoutState();
        return;
    }
    
    try {
        const res = await fetch('/api/rp/profile', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (res.ok) {
            currentUser = await res.json();
            handleLoginState();
            await loadUserContent();
        } else {
            // Token invalid or expired
            localStorage.removeItem(RP_TOKEN_KEY);
            handleLogoutState();
        }
    } catch (err) {
        console.error("Auth check failed:", err);
    }
}

function handleLoginState() {
    authNavBtn.classList.add('hidden');
    userProfileMenu.classList.remove('hidden');
    navUsername.textContent = currentUser.username;
}

function handleLogoutState() {
    currentUser = null;
    authNavBtn.classList.remove('hidden');
    userProfileMenu.classList.add('hidden');
    oldChatsList.innerHTML = '<div class="loading-text">Sign in to view chats</div>';
    if (menuOldChats) menuOldChats.innerHTML = '';
    ocSelect.innerHTML = '<option value="">No OC</option>';
}

function logoutRp() {
    localStorage.removeItem(RP_TOKEN_KEY);
    handleLogoutState();
    showDiscoveryHub();
    showToast('Logged out successfully', 'info');
}

function toggleSidebar() {
    const sidebar = document.getElementById('rp-sidebar');
    if (sidebar) sidebar.classList.toggle('open');
}

function toggleChatMenu() {
    if (chatMenuDropdown) chatMenuDropdown.classList.toggle('hidden');
}

function closeChatMenu() {
    if (chatMenuDropdown) chatMenuDropdown.classList.add('hidden');
}

// ===================================
// Data Loading
// ===================================

async function loadPublicModels() {
    try {
        const res = await fetch('/api/public-models');
        if (res.ok) {
            const data = await res.json();
            const models = data.models || [];
            modelSelect.innerHTML = '';
            
            if (models.length === 0) {
                modelSelect.innerHTML = '<option value="">No models available</option>';
            } else {
                models.forEach(m => {
                    const statusText = m.is_healthy ? 'HEALTHY' : 'DOWN';
                    const tag = m.is_healthy ? '🟢 ' : '🔴 ';
                    const opt = document.createElement('option');
                    // Strip API prefixes for display via alias or standard name if applicable
                    let displayName = m.alias || m.id;
                    opt.value = m.id;
                    opt.textContent = `${tag}${displayName} (${statusText})`;
                    if (!m.is_healthy) opt.disabled = true;
                    modelSelect.appendChild(opt);
                });
            }
        }
    } catch (e) {
        console.error("Failed to load models:", e);
    }
}

async function loadDiscoveryHub() {
    try {
        const res = await fetch('/api/rp/bots');
        if (res.ok) {
            const data = await res.json();
            const bots = data.bots;
            
            if (bots.length === 0) {
                botsGrid.innerHTML = '<div class="info-text">No bots have been created yet. Be the first!</div>';
                return;
            }
            
            botsGrid.innerHTML = bots.map(bot => `
                <div class="bot-card" onclick="openBotView('${bot.id}')">
                    <img src="${bot.avatar || '/static/default-bot.png'}" class="bot-card-image" alt="${escapeHtml(bot.name)}" onerror="this.src='/static/default-bot.png'">
                    <div class="bot-card-content">
                        <h3 class="bot-card-title">${escapeHtml(bot.name)}</h3>
                        <p class="bot-card-desc">${escapeHtml(bot.description || 'No description provided.')}</p>
                        ${bot.tags ? `
                        <div class="bot-card-tags">
                            ${bot.tags.split(',').map(t => `<span class="bot-tag">${escapeHtml(t.trim())}</span>`).join('')}
                        </div>
                        ` : ''}
                    </div>
                </div>
            `).join('');
        }
    } catch (e) {
        console.error("Hub load failed", e);
        botsGrid.innerHTML = '<div class="error-text">Failed to load bots.</div>';
    }
}

async function loadUserContent() {
    const token = localStorage.getItem(RP_TOKEN_KEY);
    if (!token) return;
    
    const headers = { 'Authorization': `Bearer ${token}` };
    
    // Load OCs
    try {
        const ocRes = await fetch('/api/rp/ocs', { headers });
        if (ocRes.ok) {
            const ocData = await ocRes.json();
            myOcs = ocData.ocs;
            
            ocSelect.innerHTML = '<option value="">No OC (Playing as yourself)</option>';
            myOcs.forEach(oc => {
                const opt = document.createElement('option');
                opt.value = oc.id;
                opt.textContent = oc.name;
                ocSelect.appendChild(opt);
            });
            // Update OC display in menu specifically if same
        }
    } catch (e) { console.error("OCs load failed", e); }
    
    // Load Chats
    try {
        const chatRes = await fetch('/api/rp/chats', { headers });
        if (chatRes.ok) {
            const chatData = await chatRes.json();
            
            const renderList = (container, isMenu = false) => {
                if (chatData.chats.length === 0) {
                    container.innerHTML = `<div class="loading-text">${isMenu ? 'No chats' : 'No previous chats.'}</div>`;
                    return;
                }
                chatData.chats.sort((a,b) => new Date(b.updated_at) - new Date(a.updated_at));
                container.innerHTML = chatData.chats.slice(0, isMenu ? 5 : 50).map(c => `
                    <div class="chat-item ${currentChatId === c.id ? 'active' : ''}" onclick="loadChatHistory('${c.id}')">
                        <img src="${c.bot_avatar || '/static/default-bot.png'}" class="chat-item-avatar" onerror="this.src='/static/default-bot.png'">
                        <div class="chat-item-details">
                            <span class="chat-item-name">${escapeHtml(c.bot_name)}</span>
                            <span class="chat-item-time">${formatShortDate(c.updated_at)}</span>
                        </div>
                        ${!isMenu ? `<button class="chat-item-delete" onclick="deleteChat(event, '${c.id}')">✕</button>` : ''}
                    </div>
                `).join('');
            };

            renderList(oldChatsList);
            if (menuOldChats) renderList(menuOldChats, true);
        }
    } catch (e) { console.error("Chats load failed", e); }
}

// ===================================
// Navigation & Views
// ===================================

function showDiscoveryHub() {
    chatInterface.classList.add('hidden');
    botProfileView.classList.add('hidden');
    discoveryHub.classList.remove('hidden');
    chatInterface.classList.remove('active-view');
    botProfileView.classList.remove('active-view');
    
    setTimeout(() => {
        discoveryHub.classList.add('active-view');
    }, 10);
    
    currentChatId = null;
    currentBotId = null;
    document.querySelectorAll('.chat-item').forEach(el => el.classList.remove('active'));
    loadDiscoveryHub();
}

async function openBotView(botId) {
    if (!currentUser) {
        showLoginModal();
        return;
    }
    
    try {
        const res = await fetch(`/api/rp/bots/${botId}`);
        if (res.ok) {
            const bot = await res.json();
            currentBotId = bot.id;
            
            // Populate Profile
            profileBotName.textContent = bot.name;
            profileBotCreator.textContent = `by ${bot.creator_name || 'Anon'}`;
            profileBotDesc.textContent = bot.description || 'No description provided.';
            profileBotAvatar.src = bot.avatar || '/static/default-bot.png';
            
            profileTags.innerHTML = bot.tags ? bot.tags.split(',').map(t => `<span class="bot-tag">${escapeHtml(t.trim())}</span>`).join('') : '';

            // Transition
            discoveryHub.classList.add('hidden');
            discoveryHub.classList.remove('active-view');
            botProfileView.classList.remove('hidden');
            setTimeout(() => {
                botProfileView.classList.add('active-view');
            }, 10);
        }
    } catch (e) {
        showToast('Error loading bot profile', 'error');
    }
}

async function startNewChat() {
    if (!currentBotId || !currentUser) return;
    const token = localStorage.getItem(RP_TOKEN_KEY);
    
    try {
        const payload = {
            bot_id: currentBotId,
            oc_id: ocSelect.value || null,
            model_id: modelSelect.value || null
        };
        
        const res = await fetch('/api/rp/chats', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            const chat = await res.json();
            await loadChatHistory(chat.id);
            await loadUserContent();
        } else {
            showToast('Failed to start chat', 'error');
        }
    } catch (e) {
        showToast('Network error starting chat', 'error');
    }
}

let currentChatMessages = [];

async function loadChatHistory(chatId) {
    const token = localStorage.getItem(RP_TOKEN_KEY);
    if (!token) return;
    
    try {
        const res = await fetch(`/api/rp/chats/${chatId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (res.ok) {
            const chat = await res.json();
            currentChatId = chat.id;
            currentBotId = chat.bot_id;
            currentChatMessages = chat.messages || [];
            
            // Re-sync dropdowns to match chat config
            if (chat.model_id) modelSelect.value = chat.model_id;
            if (chat.oc_id) ocSelect.value = chat.oc_id;
            else ocSelect.value = "";
            
            // Fetch bot info
            const botRes = await fetch(`/api/rp/bots/${currentBotId}`);
            if (botRes.ok) {
                const bot = await botRes.json();
                chatBotName.textContent = bot.name;
                chatBotAvatar.src = bot.avatar || '/static/default-bot.png';
                // Remove onerror from inline to prevent loops if missing, 
                // but we handled it.
            }
            
            renderChatMessages();
            
            // Switch view
            discoveryHub.classList.add('hidden');
            discoveryHub.classList.remove('active-view');
            botProfileView.classList.add('hidden');
            botProfileView.classList.remove('active-view');
            
            chatInterface.classList.remove('hidden');
            setTimeout(() => {
                chatInterface.classList.add('active-view');
                scrollToBottom();
            }, 10);
            
            // Update sidebar highlight
            document.querySelectorAll('.chat-item').forEach(el => el.classList.remove('active'));
            setTimeout(() => {
                const activeCard = document.querySelector(`.chat-item[onclick*="${chatId}"]`);
                if(activeCard) activeCard.classList.add('active');
            }, 100);
            
        }
    } catch (e) {
        console.error("Load chat error", e);
        showToast("Error loading chat", "error");
    }
}

async function deleteChat(event, chatId) {
    event.stopPropagation(); // prevent opening chat
    
    if (!confirm("Are you sure you want to delete this chat?")) return;
    
    const token = localStorage.getItem(RP_TOKEN_KEY);
    try {
        const res = await fetch(`/api/rp/chats/${chatId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (res.ok) {
            if (currentChatId === chatId) {
                showDiscoveryHub();
            }
            await loadUserContent();
        }
    } catch(e) {}
}

// ===================================
// Chat Rendering & Interaction
// ===================================

function renderChatMessages() {
    if (currentChatMessages.length === 0) {
        chatMessagesContainer.innerHTML = `
            <div style="text-align:center; color: var(--text-muted); margin-top: 2rem;">
                <p>Chat started. Send a message to begin the roleplay.</p>
            </div>
        `;
        return;
    }
    
    // Filter out system messages from display
    const displayMsgs = currentChatMessages.filter(m => m.role !== 'system');
    
    chatMessagesContainer.innerHTML = displayMsgs.map(msg => {
        const isUser = msg.role === 'user';
        const wrapperClass = isUser ? 'message-user' : 'message-bot';
        
        let avatarSrc = '/static/default-bot.png';
        if (isUser) {
            // Check if OC is active
            const activeOcId = ocSelect.value;
            if (activeOcId) {
                const oc = myOcs.find(o => o.id === activeOcId);
                if (oc && oc.avatar) avatarSrc = oc.avatar;
            } else if (currentUser && currentUser.avatar) {
                avatarSrc = currentUser.avatar;
            } else {
                avatarSrc = '/static/default-user.png';
            }
        } else {
            avatarSrc = chatBotAvatar.src;
        }
        
        // Handle Multimodal Image Inputs
        let contentHtml = '';
        if (Array.isArray(msg.content)) {
            // Parse Vision array formats
            msg.content.forEach(part => {
                if (part.type === 'text') {
                    contentHtml += `<p>${formatTextMarkup(escapeHtml(part.text))}</p>`;
                } else if (part.type === 'image_url') {
                    contentHtml += `<img src="${part.image_url.url}" class="attached-image">`;
                }
            });
        } else {
            contentHtml = `<p>${formatTextMarkup(escapeHtml(msg.content))}</p>`;
        }
        
        return `
            <div class="message-wrapper ${wrapperClass}">
                <img src="${avatarSrc}" onerror="this.src='/static/${isUser ? 'default-user.png' : 'default-bot.png'}'" class="message-avatar">
                <div class="message-bubble">
                    ${contentHtml}
                </div>
            </div>
        `;
    }).join('');
}

function formatTextMarkup(text) {
    // Basic markdown conversion: **bold**, *italic*
    if (!text) return '';
    let formatted = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    formatted = formatted.replace(/\*(.*?)\*/g, '<em>$1</em>');
    // Italics often indicate actions in RP
    return formatted.replace(/\\n/g, '<br>');
}

function scrollToBottom() {
    chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
}

function autoResizeTextarea(el) {
    el.style.height = 'auto';
    el.style.height = (el.scrollHeight) + 'px';
}

function handleChatKeydown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
}

// Image Attachment Handling
let pendingImageBase64 = null;
const ATTACHMENT_MAX_MB = 2;

function triggerChatAttachment() {
    document.getElementById('chat-attachment').click();
}

function handleChatAttachment(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    if (file.size > ATTACHMENT_MAX_MB * 1024 * 1024) {
        showToast(`Image too large. Max ${ATTACHMENT_MAX_MB}MB`, 'error');
        return;
    }
    
    fileToBase64(file).then(base64 => {
        pendingImageBase64 = base64;
        const preview = document.getElementById('image-preview');
        preview.src = base64;
        document.getElementById('image-preview-container').classList.remove('hidden');
    });
}

function removeImage() {
    pendingImageBase64 = null;
    document.getElementById('image-preview-container').classList.add('hidden');
    document.getElementById('chat-attachment').value = '';
}

// ---------------- SEND MESSAGE ENGINE ----------------

async function sendMessage() {
    if (isGenerating || !currentChatId) return;
    
    const text = chatInput.value.trim();
    if (!text && !pendingImageBase64) return;
    
    const token = localStorage.getItem(RP_TOKEN_KEY);
    if (!token) {
        showLoginModal();
        return;
    }
    
    // Construct User payload
    let userMsgPayload = { role: "user", content: text };
    
    if (pendingImageBase64) {
        userMsgPayload.content = [
            { type: "text", text: text || "Look at this image." },
            { type: "image_url", image_url: { url: pendingImageBase64 } }
        ];
    }
    
    // Optimistic UI Update for user message
    currentChatMessages.push(userMsgPayload);
    renderChatMessages();
    setTimeout(scrollToBottom, 50);
    
    // Add typing indicator shell
    const typingId = 'typing-' + Date.now();
    chatMessagesContainer.insertAdjacentHTML('beforeend', `
        <div class="message-wrapper message-bot" id="${typingId}-wrapper">
            <img src="${chatBotAvatar.src}" class="message-avatar">
            <div class="message-bubble" id="${typingId}-bubble">
                <span class="typing-indicator">● ● ●</span>
            </div>
        </div>
    `);
    setTimeout(scrollToBottom, 50);
    
    const typingBubble = document.getElementById(`${typingId}-bubble`);
    
    // Reset Input
    chatInput.value = '';
    chatInput.style.height = 'auto';
    removeImage();
    
    isGenerating = true;
    let fullResponse = "";
    
    try {
        const streamRes = await fetch('/api/rp/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                chat_id: currentChatId,
                message: text
            })
        });
        
        if (!streamRes.ok) {
            const errBody = await streamRes.json().catch(()=>({}));
            throw new Error(errBody.detail || 'Failed to start stream');
        }
        
        // Setup SSE Reader
        const reader = streamRes.body.getReader();
        const decoder = new TextDecoder("utf-8");
        
        // Remove typing indicator just before appending actual text
        let initializedText = false;
        
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            const chunkText = decoder.decode(value, {stream: true});
            const lines = chunkText.split('\\n');
            
            for (let line of lines) {
                if (line.startsWith('data: ')) {
                    const dataStr = line.replace('data: ', '').trim();
                    if (!dataStr || dataStr === '[DONE]') continue;
                    
                    try {
                        const parsed = JSON.parse(dataStr);
                        if (parsed.error) {
                            showToast(parsed.error, 'error');
                            fullResponse += `\\n[System: ${parsed.error}]`;
                        } else if (parsed.choices && parsed.choices[0].delta.content) {
                            if (!initializedText) {
                                typingBubble.innerHTML = '';
                                initializedText = true;
                            }
                            fullResponse += parsed.choices[0].delta.content;
                            typingBubble.innerHTML = `<p>${formatTextMarkup(escapeHtml(fullResponse))}</p>`;
                            scrollToBottom();
                        }
                    } catch (err) {
                        // Some endpoints just stream raw characters or incomplete json buffers
                        // The proxy sends chunks. We'll handle it if it isn't JSON.
                    }
                }
            }
        }
        
    } catch (err) {
        console.error(err);
        showToast("Inference error: " + err.message, "error");
        typingBubble.innerHTML = "<p><em>*Network interruption*</em></p>";
    } finally {
        isGenerating = false;
        
        // Save history state to DB
        // Add fullResponse to currentChatMessages
        if (fullResponse) {
            currentChatMessages.push({ role: "assistant", content: fullResponse });
        }
        
        // Sync context to backend
        await updateChatState();
    }
}

async function updateChatState() {
    if (!currentChatId) return;
    const token = localStorage.getItem(RP_TOKEN_KEY);
    
    try {
        await fetch(`/api/rp/chats/${currentChatId}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                messages: JSON.stringify(currentChatMessages),
                model_id: modelSelect.value || null,
                oc_id: ocSelect.value || null,
                wallpaper: currentWallpaperBase64 || null
            })
        });
        
        // Refresh sidebar silently
        loadUserContent();
    } catch (e) {
        console.error("Chat sync failed", e);
    }
}


// ===================================
// Background Wallpapers
// ===================================

let currentWallpaperBase64 = null;
const WALLPAPER_MAX_MB = 5;

function triggerWallpaperUpload() {
    document.getElementById('wallpaper-upload').click();
}

function handleWallpaperChange(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    if (file.size > WALLPAPER_MAX_MB * 1024 * 1024) {
        showToast(`Image too large. Max ${WALLPAPER_MAX_MB}MB`, 'error');
        return;
    }
    
    fileToBase64(file).then(base64 => {
        applyWallpaper(base64);
        
        // Sync to backend if in a chat
        if (currentChatId) {
            updateChatState();
        } else {
            // Save globally for discovery hub
            localStorage.setItem('rp_wallpaper', base64);
        }
    });
}

function applyWallpaper(url) {
    currentWallpaperBase64 = url;
    document.getElementById('rp-background').style.backgroundImage = `url('${url}')`;
}

function loadSavedWallpaper() {
    const saved = localStorage.getItem('rp_wallpaper');
    if (saved) applyWallpaper(saved);
}


// ===================================
// Modals & Creation Forms
// ===================================

function showCreateBotModal() {
    if (!currentUser) {
        showLoginModal();
        return;
    }
    document.getElementById('bot-form').reset();
    document.getElementById('bot-avatar-preview').src = '';
    document.getElementById('bot-avatar-preview').classList.add('hidden');
    document.getElementById('bot-avatar-placeholder').classList.remove('hidden');
    
    document.getElementById('bot-modal').classList.remove('hidden');
}

function showOcModal() {
    if (!currentUser) {
        showLoginModal();
        return;
    }
    document.getElementById('oc-form').reset();
    document.getElementById('oc-avatar-preview').src = '';
    document.getElementById('oc-avatar-preview').classList.add('hidden');
    document.getElementById('oc-avatar-placeholder').classList.remove('hidden');
    
    document.getElementById('oc-modal').classList.remove('hidden');
}

function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('hidden');
}

function showProfileModal() {
    if (!currentUser) return;
    profileUsernameInput.value = currentUser.username;
    if (currentUser.avatar) {
        profileAvatarPreview.src = currentUser.avatar;
        profileAvatarPreview.classList.remove('hidden');
        profileAvatarPlaceholder.classList.add('hidden');
    } else {
        profileAvatarPreview.classList.add('hidden');
        profileAvatarPlaceholder.classList.remove('hidden');
    }
    document.getElementById('profile-error').classList.add('hidden');
    profileModal.classList.remove('hidden');
}

async function handleProfileSubmit(e) {
    e.preventDefault();
    const token = localStorage.getItem(RP_TOKEN_KEY);
    const errorEl = document.getElementById('profile-error');
    const submitBtn = document.getElementById('profile-submit-btn');
    
    const payload = {
        username: profileUsernameInput.value.trim(),
        avatar: pendingModalBase64.user || currentUser.avatar
    };

    submitBtn.disabled = true;
    errorEl.classList.add('hidden');

    try {
        const res = await fetch('/api/rp/profile', {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            showToast('Profile updated!', 'success');
            closeModal('profile-modal');
            await checkAuth(); // Refresh state
        } else {
            const data = await res.json();
            throw new Error(data.detail || 'Failed to update profile');
        }
    } catch (err) {
        errorEl.textContent = err.message;
        errorEl.classList.remove('hidden');
    } finally {
        submitBtn.disabled = false;
    }
}


let pendingModalBase64 = { bot: null, oc: null, user: null };

function handleAvatarChange(event, type) {
    const file = event.target.files[0];
    if (!file) return;
    fileToBase64(file).then(base => {
        pendingModalBase64[type] = base;
        const preview = document.getElementById(`${type}-avatar-preview`);
        const placeholder = document.getElementById(`${type}-avatar-placeholder`);
        preview.src = base;
        preview.classList.remove('hidden');
        placeholder.classList.add('hidden');
    });
}

async function handleBotSubmit(e) {
    e.preventDefault();
    const token = localStorage.getItem(RP_TOKEN_KEY);
    const errorEl = document.getElementById('bot-error');
    errorEl.classList.add('hidden');
    
    const payload = {
        name: document.getElementById('bot-name').value,
        avatar: pendingModalBase64.bot,
        description: document.getElementById('bot-description').value,
        lore: document.getElementById('bot-lore').value,
        personality: document.getElementById('bot-personality').value,
        tags: document.getElementById('bot-tags').value
    };
    
    try {
        const res = await fetch('/api/rp/bots', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            closeModal('bot-modal');
            showToast('Character created!', 'success');
            loadDiscoveryHub();
        } else {
            const data = await res.json();
            throw new Error(data.detail || 'Failed to create bot');
        }
    } catch(err) {
        errorEl.textContent = err.message;
        errorEl.classList.remove('hidden');
    }
}

async function handleOcSubmit(e) {
    e.preventDefault();
    const token = localStorage.getItem(RP_TOKEN_KEY);
    const errorEl = document.getElementById('oc-error');
    errorEl.classList.add('hidden');
    
    const payload = {
        name: document.getElementById('oc-name').value,
        avatar: pendingModalBase64.oc,
        description: document.getElementById('oc-description').value,
        personality: document.getElementById('oc-personality').value,
    };
    
    try {
        const res = await fetch('/api/rp/ocs', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            closeModal('oc-modal');
            showToast('OC created!', 'success');
            loadUserContent(); // Refresh OC dropdown
        } else {
            const data = await res.json();
            throw new Error(data.detail || 'Failed to create OC');
        }
    } catch(err) {
        errorEl.textContent = err.message;
        errorEl.classList.remove('hidden');
    }
}

// ===================================
// Character Card Importing (V2/PNG/JSON)
// ===================================
// We use a basic JSON parsing strategy for Tawern format text chunks inside PNGs via ArrayBuffers
// The prompt asked for parsing PNG/JSON text chunk decoding in vanilla JS.

function triggerCardImport() {
    if (!currentUser) showLoginModal();
    else document.getElementById('card-upload').click();
}

async function handleCardImport(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    if (file.name.endsWith('.json')) {
        const reader = new FileReader();
        reader.onload = (event) => importFromParsedJson(JSON.parse(event.target.result));
        reader.readAsText(file);
    } else if (file.name.endsWith('.png')) {
        try {
            const parsedData = await extractTavernPNG(file);
            if (parsedData) {
                // If the PNG has an image, attach it for the avatar!
                fileToBase64(file).then(base64 => {
                    importFromParsedJson(parsedData, base64);
                });
            } else {
                showToast("No valid character data found in PNG.", "error");
            }
        } catch(err) {
            showToast("Failed to parse character card", "error");
            console.error(err);
        }
    }
    document.getElementById('card-upload').value = '';
}

// Decodes standard base64 and extract tEXt/iTXt chunks searching for 'chara'
async function extractTavernPNG(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = function(evt) {
            const buffer = new Uint8Array(evt.target.result);
            let offset = 8; // skip PNG signature
            
            while (offset < buffer.length) {
                const length = (buffer[offset] << 24) | (buffer[offset+1] << 16) | (buffer[offset+2] << 8) | buffer[offset+3];
                const type = String.fromCharCode(buffer[offset+4], buffer[offset+5], buffer[offset+6], buffer[offset+7]);
                
                if (type === 'tEXt' || type === 'iTXt' || type === 'zTXt') {
                    const chunkData = buffer.slice(offset + 8, offset + 8 + length);
                    const decoder = new TextDecoder('utf-8');
                    const text = decoder.decode(chunkData);
                    
                    if (text.includes('chara')) {
                        try {
                            // Extract Base64 that follows the separated key
                            let jsonStr = text.replace('chara\\0', '');
                            // Sometimes it's base64 encoded
                            try { jsonStr = atob(jsonStr); } catch(ex){}
                            
                            const parsed = JSON.parse(jsonStr);
                            resolve(parsed);
                            return;
                        } catch(e) {
                            console.error("Parsed char data error", e);
                        }
                    }
                }
                offset += 8 + length + 4; // chunk length + header + crc
            }
            resolve(null);
        };
        reader.onerror = reject;
        reader.readAsArrayBuffer(file);
    });
}

function importFromParsedJson(data, avatarBase64 = null) {
    // Fill the bot modal with the data and open it
    showCreateBotModal();
    
    // Support V1 and V2 Specs
    const name = data.name || data.data?.name || 'Unnamed Bot';
    const description = data.description || data.data?.description || '';
    const personality = data.personality || data.data?.personality || '';
    const lore = data.scenario || data.data?.scenario || data.mes_example || data.data?.mes_example || '';
    const tags = (data.tags || data.data?.tags || []).join(', ');
    
    document.getElementById('bot-name').value = name;
    document.getElementById('bot-description').value = description;
    document.getElementById('bot-personality').value = personality;
    document.getElementById('bot-lore').value = lore;
    document.getElementById('bot-tags').value = tags;
    
    if (avatarBase64) {
        pendingModalBase64.bot = avatarBase64;
        const preview = document.getElementById('bot-avatar-preview');
        preview.src = avatarBase64;
        preview.classList.remove('hidden');
        document.getElementById('bot-avatar-placeholder').classList.add('hidden');
    }
    
    showToast("Character card loaded! Save it to deploy.");
}

// ===================================
// Utilities
// ===================================

function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
        reader.readAsDataURL(file);
    });
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
function escapeAttr(text) {
    if (!text) return '';
    return escapeHtml(text).replace(/"/g, '&quot;');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span>${escapeHtml(message)}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
    `;
    container.appendChild(toast);
    setTimeout(() => { if(toast.parentElement) toast.remove(); }, 5000);
}

function formatShortDate(isoString) {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return '';
    const today = new Date();
    if (date.toDateString() === today.toDateString()) {
        return date.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
    }
    return date.toLocaleDateString([], { month:'short', day:'numeric' });
}

// Sidebar Mobile Toggle
document.getElementById('sidebar-toggle').addEventListener('click', () => {
    document.getElementById('rp-sidebar').classList.toggle('open');
});
