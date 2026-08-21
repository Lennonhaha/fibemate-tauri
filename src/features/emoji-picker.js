/**
 * Emoji Picker Component
 * 简单的Emoji选择器组件
 */

class EmojiPicker {
    constructor(options = {}) {
        this.onSelect = options.onSelect || (emoji => console.log('Emoji selected:', emoji));
        this.categories = [
            { name: 'Smileys', emojis: ['😀','😃','😄','😁','😅','😂','🤣','😊','😇','🙂','😉','😌','😍','🥰','😘','😗','😙','😚','😋','😛','😜','🤪','😝','🤑','🤗','🤭','🤫','🤔','🤐','🤨','😐','😑','😶','😏','😒','🙄','😬','🤥','😌','😔','😪','🤤','😴','😷','🤒','🤕'] },
            { name: 'Gestures', emojis: ['👋','🤚','🖐️','✋','🖖','👌','🤌','🤏','✌️','🤞','🤟','🤘','🤙','👈','👉','👆','🖕','👇','☝️','👍','👎','✊','👊','🤛','🤜','👏','🙌','👐','🤲','🤝','🙏'] },
            { name: 'Objects', emojis: ['💼','📁','📂','🗂️','📅','📆','🗒️','🗓️','📇','📈','📉','📊','📋','📌','📍','📎','🖇️','📏','📐','✂️','🗃️','🗄️','🗑️','🔒','🔓','🔏','🔐','🔑','🗝️','💡','🔦','🕯️','🪔','🧯'] },
            { name: 'Symbols', emojis: ['❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎','💔','❣️','💕','💞','💓','💗','💖','💘','💝','💟','☮️','✝️','☪️','🕉️','☸️','✡️','🔯','🕎','☯️','☦️','🛐','⛎','♈','♉','♊','♋','♌','♍','♎','♏','♐','♑','♒','♓'] },
            { name: 'Flags', emojis: ['🏳️','🏴','🏴‍☠️','🏁','🚩','🎌','🏳️‍🌈','🏳️‍⚧️','🏴‍☠️','🇺🇸','🇬🇧','🇨🇳','🇯🇵','🇰🇷','🇩🇪','🇫🇷','🇮🇹','🇷🇺','🇮🇳','🇧🇷','🇨🇦','🇦🇺','🇪🇸','🇲🇽','🇿🇦','🇳🇬','🇪🇬','🇸🇬','🇭🇰','🇹🇼'] }
        ];
    }

    render() {
        const container = document.createElement('div');
        container.className = 'emoji-picker';
        container.innerHTML = `
            <div class="emoji-header">
                <input type="text" class="emoji-search" placeholder="Search emoji..." />
                <button class="emoji-close">&times;</button>
            </div>
            <div class="emoji-categories">
                ${this.categories.map((c, i) => `<button class="emoji-cat-btn ${i === 0 ? 'active' : ''}" data-cat="${i}">${c.name}</button>`).join('')}
            </div>
            <div class="emoji-content">
                ${this.categories.map((c, i) => `<div class="emoji-grid ${i === 0 ? 'active' : ''}" data-cat="${i}">
                    ${c.emojis.map(e => `<button class="emoji-btn" data-emoji="${e}">${e}</button>`).join('')}
                </div>`).join('')}
            </div>
        `;
        
        this.bindEvents(container);
        return container;
    }

    bindEvents(container) {
        // Category switching
        container.querySelectorAll('.emoji-cat-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                container.querySelectorAll('.emoji-cat-btn').forEach(b => b.classList.remove('active'));
                container.querySelectorAll('.emoji-grid').forEach(g => g.classList.remove('active'));
                btn.classList.add('active');
                container.querySelector(`.emoji-grid[data-cat="${btn.dataset.cat}"]`).classList.add('active');
            });
        });

        // Emoji selection
        container.querySelectorAll('.emoji-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this.onSelect(btn.dataset.emoji);
                container.remove();
            });
        });

        // Close
        container.querySelector('.emoji-close').addEventListener('click', () => container.remove());
        
        // Search
        container.querySelector('.emoji-search').addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            container.querySelectorAll('.emoji-btn').forEach(btn => {
                const visible = btn.textContent.includes(query);
                btn.style.display = visible ? '' : 'none';
            });
        });

        // Click outside to close
        document.addEventListener('click', (e) => {
            if (!container.contains(e.target) && !e.target.closest('.emoji-picker-trigger')) {
                container.remove();
            }
        });
    }

    static injectStyles() {
        if (document.getElementById('emoji-picker-styles')) return;
        const style = document.createElement('style');
        style.id = 'emoji-picker-styles';
        style.textContent = `
            .emoji-picker {
                position: absolute;
                bottom: 60px;
                right: 10px;
                width: 320px;
                max-height: 400px;
                background: #1e1e1e;
                border: 1px solid #333;
                border-radius: 12px;
                box-shadow: 0 8px 32px rgba(0,0,0,0.4);
                z-index: 10000;
                overflow: hidden;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            }
            .emoji-header {
                display: flex;
                padding: 10px;
                border-bottom: 1px solid #333;
            }
            .emoji-search {
                flex: 1;
                background: #2a2a2a;
                border: none;
                color: #fff;
                padding: 8px 12px;
                border-radius: 6px;
                outline: none;
            }
            .emoji-close {
                background: none;
                border: none;
                color: #888;
                font-size: 20px;
                cursor: pointer;
                margin-left: 8px;
            }
            .emoji-categories {
                display: flex;
                padding: 8px;
                gap: 4px;
                border-bottom: 1px solid #333;
                overflow-x: auto;
            }
            .emoji-cat-btn {
                background: none;
                border: none;
                color: #888;
                font-size: 11px;
                padding: 6px 8px;
                cursor: pointer;
                border-radius: 4px;
                white-space: nowrap;
            }
            .emoji-cat-btn.active {
                background: #007acc;
                color: #fff;
            }
            .emoji-content {
                max-height: 280px;
                overflow-y: auto;
            }
            .emoji-grid {
                display: none;
                padding: 10px;
                grid-template-columns: repeat(8, 1fr);
                gap: 4px;
            }
            .emoji-grid.active {
                display: grid;
            }
            .emoji-btn {
                background: none;
                border: none;
                font-size: 22px;
                cursor: pointer;
                padding: 4px;
                border-radius: 4px;
            }
            .emoji-btn:hover {
                background: #333;
            }
        `;
        document.head.appendChild(style);
    }
}

/**
 * Message Actions - Forward, Recall, Copy, Delete
 */
class MessageActions {
    constructor() {
        this.contextMenu = null;
    }

    /**
     * Show message context menu
     */
    showMenu(messageElement, messageData) {
        this.hideMenu();
        
        const menu = document.createElement('div');
        menu.className = 'message-actions-menu';
        menu.innerHTML = `
            <button class="action-btn" data-action="copy">📋 Copy</button>
            <button class="action-btn" data-action="forward">↗️ Forward</button>
            <button class="action-btn" data-action="recall">↩️ Unsend</button>
            <button class="action-btn danger" data-action="delete">🗑️ Delete</button>
        `;
        
        menu.style.cssText = `
            position: absolute;
            top: ${messageElement.offsetTop}px;
            right: 10px;
            background: #2a2a2a;
            border: 1px solid #444;
            border-radius: 8px;
            padding: 4px;
            z-index: 9999;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        `;
        
        menu.querySelectorAll('.action-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this.handleAction(btn.dataset.action, messageData);
                this.hideMenu();
            });
        });
        
        messageElement.appendChild(menu);
        this.contextMenu = menu;
        
        // Close on click outside
        setTimeout(() => {
            document.addEventListener('click', this.hideMenu.bind(this));
        }, 100);
    }

    hideMenu() {
        if (this.contextMenu) {
            this.contextMenu.remove();
            this.contextMenu = null;
        }
    }

    async handleAction(action, messageData) {
        switch (action) {
            case 'copy':
                navigator.clipboard.writeText(messageData.text);
                showToast('Copied to clipboard', 'success');
                break;
                
            case 'forward':
                this.showForwardDialog(messageData);
                break;
                
            case 'recall':
                await this.recallMessage(messageData);
                break;
                
            case 'delete':
                await this.deleteMessage(messageData);
                break;
        }
    }

    showForwardDialog(messageData) {
        const dialog = document.createElement('div');
        dialog.className = 'forward-dialog';
        dialog.innerHTML = `
            <div class="forward-overlay"></div>
            <div class="forward-content">
                <h3>Forward Message</h3>
                <input type="text" class="forward-search" placeholder="Search contact..." />
                <div class="forward-contacts"></div>
                <button class="forward-cancel">Cancel</button>
            </div>
        `;
        
        // Load contacts for forwarding
        const contacts = JSON.parse(localStorage.getItem('fibemate_contacts') || '[]');
        const contactsDiv = dialog.querySelector('.forward-contacts');
        contactsDiv.innerHTML = contacts.map(c => `
            <div class="forward-contact" data-user-id="${c.userId}">
                <div class="contact-avatar">${c.name.charAt(0)}</div>
                <span>${c.name}</span>
            </div>
        `).join('');
        
        dialog.querySelectorAll('.forward-contact').forEach(contact => {
            contact.addEventListener('click', async () => {
                await this.forwardMessage(messageData, contact.dataset.userId);
                dialog.remove();
            });
        });
        
        dialog.querySelector('.forward-cancel').addEventListener('click', () => dialog.remove());
        dialog.querySelector('.forward-overlay').addEventListener('click', () => dialog.remove());
        
        // Search filter
        dialog.querySelector('.forward-search').addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            contactsDiv.querySelectorAll('.forward-contact').forEach(c => {
                c.style.display = c.textContent.toLowerCase().includes(query) ? 'flex' : 'none';
            });
        });
        
        document.body.appendChild(dialog);
    }

    async forwardMessage(messageData, toUserId) {
        try {
            const token = localStorage.getItem('fibemate_token');
            const res = await fetch(`${API_BASE}/messages`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                body: JSON.stringify({
                    conversationId: null,
                    to: toUserId,
                    text: messageData.text,
                    messageType: 'forwarded',
                    originalMessageId: messageData.id
                })
            });
            
            if (res.ok) {
                showToast('Message forwarded', 'success');
                loadConversations();
            } else {
                throw new Error('Forward failed');
            }
        } catch (err) {
            showToast('Forward failed: ' + err.message, 'error');
        }
    }

    async recallMessage(messageData) {
        if (!confirm('Unsend this message? It will be deleted for both parties.')) return;
        
        try {
            const token = localStorage.getItem('fibemate_token');
            const res = await fetch(`${API_BASE}/messages/${messageData.id}/recall`, {
                method: 'POST',
                headers: { Authorization: `Bearer ${token}` }
            });
            
            if (res.ok) {
                showToast('Message unsent', 'success');
                // Remove from UI
                const msgEl = document.querySelector(`.message[data-id="${messageData.id}"]`);
                if (msgEl) msgEl.remove();
            } else {
                throw new Error('Recall failed');
            }
        } catch (err) {
            showToast('Recall failed: ' + err.message, 'error');
        }
    }

    async deleteMessage(messageData) {
        try {
            const token = localStorage.getItem('fibemate_token');
            const res = await fetch(`${API_BASE}/messages/${messageData.id}`, {
                method: 'DELETE',
                headers: { Authorization: `Bearer ${token}` }
            });
            
            // Even if server fails, delete locally
            const msgEl = document.querySelector(`.message[data-id="${messageData.id}"]`);
            if (msgEl) msgEl.remove();
            showToast('Message deleted', 'success');
        } catch (err) {
            showToast('Delete failed', 'error');
        }
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { EmojiPicker, MessageActions };
}

if (typeof window !== 'undefined') {
    window.EmojiPicker = EmojiPicker;
    window.MessageActions = MessageActions;
}