/**
 * FIBEMATE Voice Message Module
 * 语音消息录制、播放、传输
 *
 * 功能：
 * - 按住录音 / 点击切换模式
 * - 实时波形预览
 * - E2EE 加密语音传输
 * - 流式播放 + 进度条
 * - 卫星模式自适应（压缩码率）
 *
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

const VoiceMessage = (() => {
  // ── 状态 ──
  let mediaRecorder = null;
  let audioChunks = [];
  let isRecording = false;
  let recordingStartTime = 0;
  let recordingTimer = null;
  let analyser = null;
  let audioContext = null;
  let animationFrame = null;
  let currentPlayback = null; // { audio, interval, startTime, duration }

  // ── 配置 ──
  const CONFIG = {
    maxDuration: 300,        // 最长5分钟
    minDuration: 0.5,        // 最短0.5秒（太短视为误触）
    mimeType: 'audio/webm;codecs=opus',
    fallbackMimeType: 'audio/webm',
    visualizerBars: 32,
    bitrates: {
      default: 32000,       // 32kbps（标准模式）
      satellite: 16000,     // 16kbps（卫星模式）
      '5g-a': 64000         // 64kbps（5G-A高保真）
    }
  };

  // ── 初始化 ──
  function init() {
    _injectStyles();
    _bindInputBarEvents();
    console.log('[VoiceMsg] Module initialized');
  }

  // ── 注入样式 ──
  function _injectStyles() {
    const style = document.createElement('style');
    style.id = 'voice-msg-styles';
    style.textContent = `
      /* 录音覆盖层 */
      .voice-recording-overlay {
        display: flex;
        align-items: center;
        gap: 12px;
        flex: 1;
        padding: 0 8px;
      }

      .voice-recording-indicator {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--danger);
        animation: voice-pulse 1s infinite;
      }

      @keyframes voice-pulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.5; transform: scale(0.8); }
      }

      .voice-recording-timer {
        font-size: 13px;
        color: var(--text-secondary);
        font-variant-numeric: tabular-nums;
        min-width: 42px;
      }

      .voice-recording-wave {
        display: flex;
        align-items: center;
        gap: 2px;
        height: 24px;
        flex: 1;
      }

      .voice-wave-bar {
        width: 3px;
        border-radius: 2px;
        background: var(--accent);
        transition: height 0.08s ease;
        min-height: 3px;
      }

      .voice-cancel-hint {
        font-size: 11px;
        color: var(--text-muted);
        white-space: nowrap;
      }

      /* 语音消息气泡 */
      .voice-message {
        display: flex;
        align-items: center;
        gap: 8px;
        min-width: 160px;
        max-width: 280px;
        cursor: pointer;
        user-select: none;
      }

      .voice-play-btn {
        width: 32px;
        height: 32px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(0,0,0,0.2);
        flex-shrink: 0;
        transition: all 0.15s;
      }

      .voice-play-btn:hover {
        background: rgba(0,0,0,0.35);
        transform: scale(1.05);
      }

      .voice-play-btn svg {
        width: 14px;
        height: 14px;
      }

      .message.sent .voice-play-btn {
        background: rgba(0,0,0,0.15);
      }

      .voice-waveform {
        display: flex;
        align-items: center;
        gap: 1.5px;
        height: 28px;
        flex: 1;
      }

      .voice-waveform-bar {
        width: 2.5px;
        border-radius: 1.5px;
        min-height: 2px;
        transition: background 0.2s;
      }

      .message.sent .voice-waveform-bar {
        background: rgba(10,10,15,0.35);
      }

      .message.sent .voice-waveform-bar.played {
        background: rgba(10,10,15,0.6);
      }

      .message.received .voice-waveform-bar {
        background: var(--text-muted);
      }

      .message.received .voice-waveform-bar.played {
        background: var(--accent);
      }

      .voice-duration {
        font-size: 11px;
        font-variant-numeric: tabular-nums;
        flex-shrink: 0;
      }

      .message.sent .voice-duration {
        color: rgba(10,10,15,0.6);
      }

      .message.received .voice-duration {
        color: var(--text-muted);
      }

      /* 语音发送按钮 */
      #btnVoiceRecord {
        transition: color 0.15s, background 0.15s;
      }

      #btnVoiceRecord.recording {
        color: var(--danger) !important;
        background: rgba(255,71,87,0.12);
      }

      /* 滑动取消录音 */
      .voice-slide-cancel {
        position: absolute;
        left: -60px;
        top: 50%;
        transform: translateY(-50%);
        padding: 6px 12px;
        background: var(--danger);
        color: white;
        border-radius: 8px;
        font-size: 11px;
        opacity: 0;
        transition: opacity 0.2s;
        pointer-events: none;
      }

      .voice-slide-cancel.visible {
        opacity: 1;
      }
    `;
    document.head.appendChild(style);
  }

  // ── 绑定输入栏事件 ──
  function _bindInputBarEvents() {
    const inputBar = document.querySelector('.chat-input-bar');
    if (!inputBar) return;

    // 在附件按钮前插入语音按钮
    const btnAttach = document.getElementById('btnAttach');
    if (btnAttach) {
      const btnVoice = document.createElement('button');
      btnVoice.className = 'icon-btn';
      btnVoice.id = 'btnVoiceRecord';
      btnVoice.title = 'Voice message';
      btnVoice.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
          <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
          <line x1="12" y1="19" x2="12" y2="23"/>
          <line x1="8" y1="23" x2="16" y2="23"/>
        </svg>
      `;
      btnAttach.parentNode.insertBefore(btnVoice, btnAttach);

      // 点击切换录音模式
      btnVoice.addEventListener('click', () => {
        if (isRecording) {
          stopRecording(true); // 发送
        } else if (!STATE.currentPeerId) {
          showToast('请先选择一个联系人', 'info');
        } else {
          startRecording();
        }
      });
    }
  }

  // ── 开始录音 ──
  async function startRecording() {
    try {
      // 检查浏览器支持
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        showToast('⚠️ 浏览器不支持录音功能', 'error');
        return;
      }

      // 获取网络模式（卫星模式降低码率）
      const networkMode = _getCurrentNetworkMode();
      const bitrate = CONFIG.bitrates[networkMode] || CONFIG.bitrates.default;

      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
          sampleRate: networkMode === 'satellite' ? 16000 : 48000
        }
      });

      // 选择编码格式
      const mimeType = MediaRecorder.isTypeSupported(CONFIG.mimeType)
        ? CONFIG.mimeType
        : CONFIG.fallbackMimeType;

      mediaRecorder = new MediaRecorder(stream, { mimeType, audioBitsPerSecond: bitrate });
      audioChunks = [];

      // 音频分析（波形可视化）
      audioContext = new (window.AudioContext || window.webkitAudioContext)();
      const source = audioContext.createMediaStreamSource(stream);
      analyser = audioContext.createAnalyser();
      analyser.fftSize = 128;
      source.connect(analyser);

      mediaRecorder.ondataavailable = (e) => {
        if (e.data.size > 0) audioChunks.push(e.data);
      };

      mediaRecorder.onstop = () => {
        stream.getTracks().forEach(t => t.stop());
        if (audioContext) {
          audioContext.close();
          audioContext = null;
        }
      };

      mediaRecorder.start(100); // 每100ms一个chunk
      isRecording = true;
      recordingStartTime = Date.now();

      // UI: 显示录音状态
      _showRecordingUI();
      _startWaveAnimation();
      _startTimer();

      console.log(`[VoiceMsg] Recording started (${networkMode}, ${bitrate}bps)`);

      // 自动停止（最大时长）
      recordingTimer = setTimeout(() => {
        if (isRecording) stopRecording(true);
      }, CONFIG.maxDuration * 1000);

    } catch (err) {
      console.error('[VoiceMsg] Start recording failed:', err);
      if (err.name === 'NotAllowedError') {
        showToast('🎤 请允许麦克风权限', 'warning');
      } else {
        showToast('录音失败: ' + err.message, 'error');
      }
    }
  }

  // ── 停止录音 ──
  function stopRecording(send = false) {
    if (!isRecording || !mediaRecorder) return;

    const duration = (Date.now() - recordingStartTime) / 1000;

    // 清理定时器
    if (recordingTimer) { clearTimeout(recordingTimer); recordingTimer = null; }
    _stopTimer();
    _stopWaveAnimation();

    isRecording = false;

    if (mediaRecorder.state === 'recording') {
      mediaRecorder.stop();
    }

    _hideRecordingUI();

    // 太短视为误触
    if (duration < CONFIG.minDuration) {
      showToast('录音时间过短', 'info');
      return;
    }

    if (send) {
      // 等待最后的数据
      setTimeout(() => {
        const audioBlob = new Blob(audioChunks, { type: mediaRecorder.mimeType });
        _sendVoiceMessage(audioBlob, duration);
      }, 200);
    }
  }

  // ── 取消录音 ──
  function cancelRecording() {
    isRecording = false;
    if (recordingTimer) { clearTimeout(recordingTimer); recordingTimer = null; }
    _stopTimer();
    _stopWaveAnimation();

    if (mediaRecorder && mediaRecorder.state === 'recording') {
      mediaRecorder.stop();
    }
    _hideRecordingUI();
    showToast('录音已取消', 'info');
  }

  // ── 发送语音消息 ──
  async function _sendVoiceMessage(audioBlob, duration) {
    if (!STATE.currentPeerId || !STATE.currentConversationId) {
      showToast('请先选择对话', 'error');
      return;
    }

    // 先在聊天中显示本地预览
    const localUrl = URL.createObjectURL(audioBlob);
    _appendVoiceMessage(true, localUrl, duration, [], false);

    try {
      // 转为 base64
      const base64Audio = await _blobToBase64(audioBlob);

      // Ensure E2EE session exists before encrypting, otherwise voice encryption fails
      const sessionReady = await _ensureSecureSession();
      if (!sessionReady) return;

      // E2EE 加密
      const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : (typeof MessageCrypto !== 'undefined' ? MessageCrypto : null);
      let payload;

      if (Crypto) {
        try {
          const envelope = await Crypto.encrypt(STATE.currentPeerId, base64Audio);
          // 若有 pending initMessage（首次 X3DH），附加到 envelope，让对方能 establish 会话（与文字消息一致）
          const wireEnvelope = STATE.pendingInitMessage
            ? { initMessage: STATE.pendingInitMessage, message: envelope }
            : envelope;
          STATE.pendingInitMessage = null;
          payload = {
            conversationId: STATE.currentConversationId,
            envelope: JSON.stringify(wireEnvelope),
            protocol: envelope.protocol || 'double-ratchet',
            version: envelope.version || 1,
            messageType: 'voice',
            voiceDuration: duration,
            voiceMimeType: audioBlob.type,
            burnAfterRead: false
          };
          console.log(`[VoiceMsg] E2EE voice sent (${duration.toFixed(1)}s)`);
        } catch (encryptErr) {
          console.error('[VoiceMsg] Encryption failed:', encryptErr.message);
          showToast('⚠️ 语音加密失败，消息未发送', 'error');
          return;
        }
      } else {
        showToast('⚠️ 安全模块未加载，语音未发送', 'error');
        return;
      }

      // WebSocket 发送（带流量混淆）
      if (STATE.ws && STATE.ws.readyState === WebSocket.OPEN) {
        _wsSend({
          type: 'message',
          to: STATE.currentPeerId,
          ...payload
        });
      } else {
        // REST 备选
        const token = localStorage.getItem('fk_token');
        await fetch(`${API_BASE}/messages`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(payload)
        });
      }
    } catch (err) {
      console.error('[VoiceMsg] Send failed:', err);
      showToast('语音发送失败', 'error');
    }
  }

  // ── 显示录音 UI ──
  function _showRecordingUI() {
    const inputBar = document.querySelector('.chat-input-bar');
    const messageInput = document.getElementById('messageInput');
    const btnSend = document.getElementById('btnSend');
    const btnVoice = document.getElementById('btnVoiceRecord');

    if (messageInput) messageInput.style.display = 'none';
    if (btnSend) btnSend.style.display = 'none';

    // 创建录音覆盖层
    const overlay = document.createElement('div');
    overlay.className = 'voice-recording-overlay';
    overlay.id = 'voiceRecordingOverlay';
    overlay.innerHTML = `
      <div class="voice-recording-indicator"></div>
      <span class="voice-recording-timer" id="voiceRecTimer">0:00</span>
      <div class="voice-recording-wave" id="voiceRecWave"></div>
      <span class="voice-cancel-hint">点击停止</span>
    `;

    // 填充波形条
    const waveContainer = overlay.querySelector('#voiceRecWave');
    for (let i = 0; i < CONFIG.visualizerBars; i++) {
      const bar = document.createElement('div');
      bar.className = 'voice-wave-bar';
      bar.style.height = '3px';
      waveContainer.appendChild(bar);
    }

    if (btnVoice) btnVoice.classList.add('recording');

    // 插入到输入栏
    const btnAttach = document.getElementById('btnAttach');
    if (btnAttach) {
      inputBar.insertBefore(overlay, btnAttach.nextSibling);
    }
  }

  // ── 隐藏录音 UI ──
  function _hideRecordingUI() {
    const messageInput = document.getElementById('messageInput');
    const btnSend = document.getElementById('btnSend');
    const btnVoice = document.getElementById('btnVoiceRecord');
    const overlay = document.getElementById('voiceRecordingOverlay');

    if (messageInput) messageInput.style.display = '';
    if (btnSend) btnSend.style.display = '';
    if (btnVoice) btnVoice.classList.remove('recording');
    if (overlay) overlay.remove();
  }

  // ── 波形动画 ──
  function _startWaveAnimation() {
    const waveContainer = document.getElementById('voiceRecWave');
    if (!waveContainer || !analyser) return;

    const dataArray = new Uint8Array(analyser.frequencyBinCount);

    function draw() {
      if (!isRecording) return;
      analyser.getByteFrequencyData(dataArray);

      const bars = waveContainer.querySelectorAll('.voice-wave-bar');
      const step = Math.floor(dataArray.length / bars.length);

      bars.forEach((bar, i) => {
        const value = dataArray[i * step] || 0;
        const height = Math.max(3, (value / 255) * 24);
        bar.style.height = height + 'px';
      });

      animationFrame = requestAnimationFrame(draw);
    }
    draw();
  }

  function _stopWaveAnimation() {
    if (animationFrame) {
      cancelAnimationFrame(animationFrame);
      animationFrame = null;
    }
  }

  // ── 录音计时器 ──
  function _startTimer() {
    const timerEl = document.getElementById('voiceRecTimer');
    if (!timerEl) return;

    function update() {
      if (!isRecording) return;
      const elapsed = (Date.now() - recordingStartTime) / 1000;
      const m = Math.floor(elapsed / 60);
      const s = Math.floor(elapsed % 60);
      timerEl.textContent = `${m}:${String(s).padStart(2, '0')}`;
    }
    recordingTimer = setInterval(update, 200);
  }

  function _stopTimer() {
    if (recordingTimer && typeof recordingTimer === 'number') {
      clearInterval(recordingTimer);
    }
  }

  // ── 添加语音消息到聊天列表 ──
  function _appendVoiceMessage(sent, audioUrl, duration, waveform = [], isEncrypted = true) {
    const list = document.getElementById('messagesList');
    if (!list) return;

    const time = formatTime(Date.now());
    const msg = document.createElement('div');
    msg.className = `message ${sent ? 'sent' : 'received'}`;

    const durationStr = _formatDuration(duration);
    const waveBars = _generateWaveformBars(waveform, 40);

    const e2eeBadge = isEncrypted ? '<span class="e2ee-badge" title="End-to-end encrypted"></span>' : '';

    msg.innerHTML = `
      <div class="msg-bubble">
        <div class="voice-message" data-audio-url="${audioUrl}" data-duration="${duration}">
          <div class="voice-play-btn">
            <svg viewBox="0 0 24 24" fill="currentColor" stroke="none">
              <polygon points="5,3 19,12 5,21"/>
            </svg>
          </div>
          <div class="voice-waveform">${waveBars}</div>
          <span class="voice-duration">${durationStr}</span>
        </div>
        ${e2eeBadge}
      </div>
      <div class="msg-time">${time}</div>
    `;

    // 绑定播放事件
    const voiceMsg = msg.querySelector('.voice-message');
    voiceMsg.addEventListener('click', () => _playVoiceMessage(voiceMsg));

    list.appendChild(msg);
    list.scrollTop = list.scrollHeight;
  }

  // ── 播放语音消息 ──
  function _playVoiceMessage(voiceMsgEl) {
    const audioUrl = voiceMsgEl.dataset.audioUrl;
    const duration = parseFloat(voiceMsgEl.dataset.duration);

    // 如果正在播放同一个，暂停
    if (currentPlayback && currentPlayback.audio.src === audioUrl) {
      if (currentPlayback.audio.paused) {
        currentPlayback.audio.play();
        _updatePlayButton(voiceMsgEl, true);
      } else {
        currentPlayback.audio.pause();
        _updatePlayButton(voiceMsgEl, false);
      }
      return;
    }

    // 停止上一个播放
    if (currentPlayback) {
      currentPlayback.audio.pause();
      currentPlayback.audio.currentTime = 0;
      clearInterval(currentPlayback.interval);
    }

    const audio = new Audio(audioUrl);
    currentPlayback = { audio, startTime: Date.now(), duration };

    _updatePlayButton(voiceMsgEl, true);

    // 进度动画
    const bars = voiceMsgEl.querySelectorAll('.voice-waveform-bar');
    const interval = setInterval(() => {
      if (audio.paused || audio.ended) {
        clearInterval(interval);
        if (audio.ended) {
          _updatePlayButton(voiceMsgEl, false);
          bars.forEach(b => b.classList.remove('played'));
        }
        return;
      }
      const progress = audio.currentTime / audio.duration;
      const playedCount = Math.floor(progress * bars.length);
      bars.forEach((b, i) => {
        b.classList.toggle('played', i < playedCount);
      });
    }, 100);

    currentPlayback.interval = interval;

    audio.onended = () => {
      _updatePlayButton(voiceMsgEl, false);
      bars.forEach(b => b.classList.remove('played'));
      clearInterval(interval);
      currentPlayback = null;
    };

    audio.play().catch(err => {
      console.error('[VoiceMsg] Playback failed:', err);
      showToast('播放失败', 'error');
      _updatePlayButton(voiceMsgEl, false);
    });
  }

  // ── 切换播放/暂停图标 ──
  function _updatePlayButton(voiceMsgEl, isPlaying) {
    const btn = voiceMsgEl.querySelector('.voice-play-btn');
    if (!btn) return;
    if (isPlaying) {
      btn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="currentColor" stroke="none">
          <rect x="6" y="4" width="4" height="16"/>
          <rect x="14" y="4" width="4" height="16"/>
        </svg>
      `;
    } else {
      btn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="currentColor" stroke="none">
          <polygon points="5,3 19,12 5,21"/>
        </svg>
      `;
    }
  }

  // ── 处理收到的语音消息 ──
  // ── 处理收到的语音消息 ──
  async function handleIncomingVoiceMessage(msg) {
    let audioData;
    const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : (typeof MessageCrypto !== 'undefined' ? MessageCrypto : null);

    if (msg.envelope && Crypto) {
      try {
        let envelope = JSON.parse(msg.envelope);

        // 首次 X3DH 握手：envelope 里带 initMessage（Alice 附加，与文字消息一致）
        if (envelope && envelope.initMessage && Crypto.receiveSession) {
          try {
            await Crypto.receiveSession(msg.from, envelope.initMessage);
            console.log('[VoiceMsg] X3DH session established from init message');
          } catch (initErr) {
            console.error('[VoiceMsg] receiveSession failed:', initErr.message);
          }
          envelope = envelope.message;
        }

        // 关键修复：decrypt 是 async，必须 await，否则 audioData 是 Promise 对象
        audioData = await Crypto.decrypt(msg.from, envelope);
      } catch (e) {
        console.error('[VoiceMsg] Decrypt failed:', e.message);
        appendMessage(false, '⚠️ 语音解密失败', msg.createdAt || Date.now());
        return;
      }
    } else {
      audioData = msg.voiceData || msg.content;
    }

    if (!audioData) return;

    // base64 → Blob → URL
    const blob = _base64ToBlob(audioData, msg.voiceMimeType || 'audio/webm');
    const url = URL.createObjectURL(blob);

    const duration = msg.voiceDuration || 0;
    const waveform = msg.voiceWaveform || [];
    _appendVoiceMessage(false, url, duration, waveform, true);
  }

  // ── 生成波形HTML ──
  function _generateWaveformBars(data, count) {
    let html = '';
    for (let i = 0; i < count; i++) {
      const value = data.length > 0 ? data[i % data.length] : Math.random();
      const height = Math.max(2, value * 24);
      html += `<div class="voice-waveform-bar" style="height:${height}px"></div>`;
    }
    return html;
  }

  // ── 工具函数 ──
  function _formatDuration(seconds) {
    const m = Math.floor(seconds / 60);
    const s = Math.floor(seconds % 60);
    return `${m}:${String(s).padStart(2, '0')}`;
  }

  // ================================================
  // Ensure an E2EE secure session (X3DH) exists with the current peer.
  // Mirrors the logic in chat.js sendMessage(). Without this, Crypto.encrypt()
  // throws "No secure session" and voice messages fail to send.
  // ================================================
  async function _ensureSecureSession() {
    const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : (typeof MessageCrypto !== 'undefined' ? MessageCrypto : null);
    if (!Crypto || typeof Crypto.hasSession !== 'function') return true;

    try {
      const hasSession = await Crypto.hasSession(STATE.currentPeerId);
      if (hasSession) return true;

      console.log(`[VoiceMsg] No session with ${STATE.currentPeerId}, attempting X3DH initiation...`);
      showToast('正在建立安全会话...', 'info');

      const token = localStorage.getItem('fk_token');
      const response = await fetch(`${API_BASE}/users/${STATE.currentPeerId}/keys`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!response.ok) {
        if (response.status === 404) {
          showToast('对方尚未注册加密密钥，无法发送加密消息', 'warning');
        } else {
          showToast('获取加密密钥失败', 'error');
        }
        return false;
      }

      const keysResp = await response.json();
      const bundle = {
        identityKey: keysResp.identityKey,
        signedPreKey: keysResp.signedPrekey || keysResp.identityKey,
        signedPreKeyId: 0,
        oneTimePreKeys: []
      };

      if (!bundle || !bundle.identityKey) {
        showToast('对方尚未上传密钥，无法建立加密会话', 'warning');
        return false;
      }

      let sessionResult;
      if (typeof PQIntegration !== 'undefined' && PQIntegration.isAvailable && PQIntegration.isAvailable() && bundle.kemPublicKey) {
        sessionResult = await Crypto.initiateHybridSession(STATE.currentPeerId, bundle);
      } else {
        sessionResult = await Crypto.initiateSession(STATE.currentPeerId, bundle);
      }

      if (sessionResult && (sessionResult.sessionEstablished || sessionResult.sessionReady)) {
        const isHybrid = sessionResult.hybrid || false;
        console.log(`[VoiceMsg] X3DH session established with ${STATE.currentPeerId} (${isHybrid ? 'hybrid' : 'classical'})`);
        showToast(`安全会话已建立${isHybrid ? ' (后量子)' : ''}`, 'success');
        if (sessionResult.initialMessage) {
          STATE.pendingInitMessage = sessionResult.initialMessage;
        }
        return true;
      }

      showToast('建立加密会话失败', 'error');
      return false;
    } catch (e) {
      console.warn('[VoiceMsg] Session ensure failed:', e.message);
      showToast('建立加密会话失败: ' + e.message, 'error');
      return false;
    }
  }

  function _blobToBase64(blob) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result.split(',')[1]);
      reader.onerror = reject;
      reader.readAsDataURL(blob);
    });
  }

  function _base64ToBlob(base64, mimeType) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new Blob([bytes], { type: mimeType });
  }

  function _getCurrentNetworkMode() {
    // 检测卫星/5G-A模式
    if (window.satelliteIntegration && window.satelliteIntegration.isActive?.()) return 'satellite';
    if (window.fiveGAIntegration && window.fiveGAIntegration.isActive?.()) return '5g-a';
    return 'default';
  }

  // ── 公共 API ──
  return {
    init,
    startRecording,
    stopRecording,
    cancelRecording,
    handleIncomingVoiceMessage,
    isRecording: () => isRecording
  };
})();
