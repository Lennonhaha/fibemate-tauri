/**
 * FIBEMATE WebRTC Module - 真实音视频通话实现
 * 支持: Voice Call, Video Call
 * 2026-05-03
 */

const WebRTCModule = (() => {
    let peerConnection = null;
    let localStream = null;
    let remoteStream = null;
    let isCalling = false;
    let isVideoEnabled = false;
    let ws = null;
    let currentCallType = 'voice'; // 'voice' | 'video'
    let currentPeerId = null;      // 当前通话对象

    // STUN/TURN 服务器配置
    const ICE_SERVERS = [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        // 添加 TURN 服务器（需要配置）
        // {
        //     urls: 'turn:your-turn-server.com:3478',
        //     username: 'user',
        //     credential: 'password'
        // }
    ];

    // 初始化 WebRTC
    function init(websocket) {
        ws = websocket;
        setupWebSocketHandlers();
    }

    // 设置 WebSocket 通话信令处理
    function setupWebSocketHandlers() {
        if (!ws) return;

        // 后端 WS 消息均经 WsPadding 混淆，需 unpad 后解析
        const originalHandler = ws.onmessage;
        ws.onmessage = (event) => {
            try {
                let raw;
                if (typeof WsPadding !== 'undefined' && !(typeof event.data === 'string')) {
                    const un = WsPadding.unpad(event.data);
                    if (un.isCover) return;
                    raw = new TextDecoder().decode(un.payload);
                } else {
                    raw = event.data;
                }
                const data = JSON.parse(raw);

                switch (data.type) {
                    case 'call_offer':
                        handleIncomingOffer(data);
                        return;
                    case 'call_answer':
                        handleIncomingAnswer(data);
                        return;
                    case 'call_end':
                        handleRemoteHangup(data);
                        return;
                    case 'call_ice':
                        handleRemoteIceCandidate(data);
                        return;
                    case 'incoming_call':
                        showIncomingCallUI(data);
                        return;
                }
            } catch (e) {
                // 不是 JSON，可能是普通消息
            }
            
            // 调用原始处理器
            if (originalHandler) {
                originalHandler.call(ws, event);
            }
        };
    }

    // 创建 PeerConnection
    function createPeerConnection() {
        peerConnection = new RTCPeerConnection({
            iceServers: ICE_SERVERS
        });

        peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                sendIceCandidate(event.candidate);
            }
        };

        peerConnection.ontrack = (event) => {
            remoteStream = event.streams[0];
            playRemoteStream(remoteStream);
        };

        peerConnection.oniceconnectionstatechange = () => {
            console.log('ICE Connection State:', peerConnection.iceConnectionState);
            
            if (peerConnection.iceConnectionState === 'connected') {
                updateCallStatus('connected');
            } else if (peerConnection.iceConnectionState === 'disconnected' ||
                       peerConnection.iceConnectionState === 'failed') {
                endCall();
            }
        };

        peerConnection.onremovetrack = () => {
            endCall();
        };

        return peerConnection;
    }

    // 开始通话
    async function startCall(peerId, callType = 'voice') {
        currentCallType = callType;
        currentPeerId = peerId;
        isCalling = true;
        
        try {
            // 获取本地媒体流
            localStream = await navigator.mediaDevices.getUserMedia({
                audio: true,
                video: callType === 'video'
            });

            // 创建 PeerConnection
            createPeerConnection();

            // 添加本地轨道
            localStream.getTracks().forEach(track => {
                peerConnection.addTrack(track, localStream);
            });

            // 播放本地预览
            playLocalStream(localStream);

            // 创建 Offer
            const offer = await peerConnection.createOffer();
            await peerConnection.setLocalDescription(offer);

            // 发送 Offer
            sendSignaling({
                type: 'call_offer',
                to: peerId,
                callType: callType,
                sdp: offer.sdp
            });

            updateCallUI('calling');
            startCallTimer();

        } catch (error) {
            console.error('Start call error:', error);
            showToast('无法访问麦克风/摄像头，请检查权限设置');
            endCall();
        }
    }

    // 接受来电
    async function acceptCall(peerId, callType = 'voice') {
        currentCallType = callType;
        currentPeerId = peerId || STATE.currentPeerId;
        isCalling = true;

        try {
            // 获取本地媒体流
            localStream = await navigator.mediaDevices.getUserMedia({
                audio: true,
                video: callType === 'video'
            });

            // 创建 PeerConnection
            createPeerConnection();

            // 添加本地轨道
            localStream.getTracks().forEach(track => {
                peerConnection.addTrack(track, localStream);
            });

            // 播放本地预览
            playLocalStream(localStream);

            // 创建 Answer
            const answer = await peerConnection.createAnswer();
            await peerConnection.setLocalDescription(answer);

            // 发送 Answer
            sendSignaling({
                type: 'call_answer',
                to: peerId || STATE.currentPeerId,
                sdp: answer.sdp
            });

            hideIncomingCallUI();
            updateCallUI('connected');
            startCallTimer();

        } catch (error) {
            console.error('Accept call error:', error);
            showToast('无法访问麦克风/摄像头');
            rejectCall(peerId);
        }
    }

    // 拒绝来电
    function rejectCall(peerId) {
        sendSignaling({
            type: 'call_end',
            to: peerId || currentPeerId || STATE.currentPeerId,
            reason: 'rejected'
        });
        hideIncomingCallUI();
        cleanup();
    }

    // 结束通话
    function endCall() {
        sendSignaling({
            type: 'call_end',
            to: currentPeerId || STATE.currentPeerId,
            reason: 'local_hangup'
        });
        cleanup();
        updateCallUI('idle');
    }

    // 清理资源
    function cleanup() {
        if (localStream) {
            localStream.getTracks().forEach(track => track.stop());
            localStream = null;
        }

        if (peerConnection) {
            peerConnection.close();
            peerConnection = null;
        }

        remoteStream = null;
        isCalling = false;
        isVideoEnabled = false;
        stopCallTimer();
    }

    // 切换视频
    function toggleVideo() {
        if (!localStream) return;
        
        const videoTrack = localStream.getVideoTracks()[0];
        if (videoTrack) {
            videoTrack.enabled = !videoTrack.enabled;
            isVideoEnabled = videoTrack.enabled;
            updateVideoButton();
            return isVideoEnabled;
        }
        return false;
    }

    // 切换静音
    function toggleMute() {
        if (!localStream) return;
        
        const audioTrack = localStream.getAudioTracks()[0];
        if (audioTrack) {
            audioTrack.enabled = !audioTrack.enabled;
            updateMuteButton();
            return !audioTrack.enabled;
        }
        return false;
    }

    // 切换扬声器
    function toggleSpeaker() {
        // 在移动设备上切换音频输出
        const audio = document.querySelector('#remoteAudio') || document.querySelector('audio');
        if (audio) {
            audio.setSinkId ? audio.setSinkId('default') : Promise.resolve();
        }
    }

    // ========== 信令处理 ==========

    function handleIncomingOffer(data) {
        // 处理收到的 Offer
        if (!peerConnection) {
            createPeerConnection();
        }

        // 记录来电者（acceptCall/rejectCall 时用）
        if (data.from) {
            STATE.currentPeerId = data.from;
        }

        peerConnection.setRemoteDescription(new RTCSessionDescription({
            type: 'offer',
            sdp: data.sdp
        })).then(() => {
            // 自动发送 Answer（自动接听模式）
            // 或者显示来电界面
            currentCallType = data.callType || 'voice';
            showIncomingCallUI(data);
        });
    }

    function handleIncomingAnswer(data) {
        peerConnection.setRemoteDescription(new RTCSessionDescription({
            type: 'answer',
            sdp: data.sdp
        }));
        updateCallUI('connected');
    }

    function handleRemoteIceCandidate(data) {
        if (peerConnection && data.candidate) {
            peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
        }
    }

    function handleRemoteHangup(data) {
        showToast('对方已结束通话');
        cleanup();
        updateCallUI('idle');
    }

    // ========== 媒体播放 ==========

    function playLocalStream(stream) {
        const localVideo = document.getElementById('localVideo');
        if (localVideo) {
            localVideo.srcObject = stream;
            localVideo.style.display = currentCallType === 'video' ? 'block' : 'none';
        }
    }

    function playRemoteStream(stream) {
        const remoteVideo = document.getElementById('remoteVideo');
        const remoteAudio = document.getElementById('remoteAudio') || document.createElement('audio');
        
        if (currentCallType === 'video' && remoteVideo) {
            remoteVideo.srcObject = stream;
            remoteVideo.style.display = 'block';
        } else {
            remoteAudio.srcObject = stream;
            remoteAudio.id = 'remoteAudio';
            remoteAudio.autoplay = true;
            document.body.appendChild(remoteAudio);
        }
    }

    // ========== 信令发送 ==========

    function sendSignaling(data) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            const payload = JSON.stringify(data);
            if (typeof WsPadding !== 'undefined') {
                ws.send(WsPadding.pad(payload));
            } else {
                ws.send(payload);
            }
        }
    }

    function sendIceCandidate(candidate) {
        sendSignaling({
            type: 'call_ice',
            to: currentPeerId || STATE.currentPeerId,
            candidate: candidate
        });
    }

    // ========== UI 更新 ==========

    function updateCallUI(status) {
        const callOverlay = document.getElementById('callOverlay');
        const callStatus = document.getElementById('callStatus');
        const callTimer = document.getElementById('callTimer');
        
        if (callOverlay) {
            if (status === 'idle') {
                callOverlay.style.display = 'none';
            } else {
                callOverlay.style.display = 'flex';
            }
        }

        if (callStatus) {
            const statusMap = {
                'idle': '',
                'calling': '正在呼叫...',
                'connected': '通话中',
                'ringing': '等待接听...'
            };
            callStatus.textContent = statusMap[status] || status;
        }
    }

    function showIncomingCallUI(data) {
        const incomingOverlay = document.getElementById('incomingCallOverlay');
        const callerName = document.getElementById('callerName');
        
        if (incomingOverlay) {
            incomingOverlay.style.display = 'flex';
            if (callerName) {
                callerName.textContent = data.fromName || data.from || '未知用户';
            }
        }
    }

    function hideIncomingCallUI() {
        const incomingOverlay = document.getElementById('incomingCallOverlay');
        if (incomingOverlay) {
            incomingOverlay.style.display = 'none';
        }
    }

    function updateVideoButton() {
        const btn = document.getElementById('btnVideoToggle');
        if (btn) {
            btn.classList.toggle('off', !isVideoEnabled);
        }
    }

    function updateMuteButton() {
        const btn = document.getElementById('btnMute');
        if (btn) {
            btn.classList.toggle('off', false); // 简化
        }
    }

    function updateCallStatus(status) {
        const statusEl = document.getElementById('callStatus');
        if (statusEl) {
            statusEl.textContent = status === 'connected' ? '通话中' : status;
        }
    }

    // ========== 通话计时器 ==========

    let timerInterval = null;

    function startCallTimer() {
        let seconds = 0;
        timerInterval = setInterval(() => {
            seconds++;
            const mins = Math.floor(seconds / 60).toString().padStart(2, '0');
            const secs = (seconds % 60).toString().padStart(2, '0');
            const timerEl = document.getElementById('callTimer');
            if (timerEl) {
                timerEl.textContent = `${mins}:${secs}`;
            }
        }, 1000);
    }

    function stopCallTimer() {
        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }
        const timerEl = document.getElementById('callTimer');
        if (timerEl) {
            timerEl.textContent = '00:00';
        }
    }

    // ========== Toast ==========

    function showToast(message) {
        if (window.showToast) {
            window.showToast(message);
        } else {
            alert(message);
        }
    }

    // ========== 公开 API ==========

    return {
        init,
        startCall,
        acceptCall,
        rejectCall,
        endCall,
        toggleVideo,
        toggleMute,
        toggleSpeaker,
        isCalling: () => isCalling,
        getCurrentCallType: () => currentCallType
    };
})();

// 自动初始化
if (typeof window !== 'undefined') {
    window.WebRTCModule = WebRTCModule;
}
