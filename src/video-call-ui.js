/**
 * FIBEMATE Video Call UI - 视频通话界面
 * 3D 高光粒子质感设计
 * 2026-08-20
 */

const VideoCallUI = (() => {
    
    // 生成通话 UI HTML
    function getCallOverlayHTML() {
        return `
        <!-- 通话覆盖层 -->
        <div id="callOverlay" class="call-overlay" style="display: none;">
            <!-- 主通话界面 -->
            <div class="call-container">
                <!-- 远端视频/头像 -->
                <div class="call-remote" id="callRemote">
                    <video id="remoteVideo" class="remote-video" autoplay playsinline style="display: none;"></video>
                    <div id="remoteAvatar" class="remote-avatar">
                        <div class="avatar-particles"></div>
                        <div class="avatar-ring"></div>
                        <span class="avatar-initial" id="remoteInitial">?</span>
                    </div>
                    <div class="call-peer-name" id="callPeerName">正在连接...</div>
                    <div class="call-status" id="callStatus">通话中</div>
                </div>
                
                <!-- 本地视频预览 -->
                <div class="call-local" id="callLocal">
                    <video id="localVideo" class="local-video" autoplay playsinline muted></video>
                    <div id="localPlaceholder" class="local-placeholder">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/>
                            <circle cx="12" cy="13" r="4"/>
                        </svg>
                    </div>
                </div>
                
                <!-- 通话计时 -->
                <div class="call-timer" id="callTimer">00:00</div>
                
                <!-- 控制按钮 - 3D 高光粒子质感 -->
                <div class="call-controls">
                    <button class="call-btn" id="btnMute" title="静音">
                        <span class="call-btn-glow"></span>
                        <span class="call-btn-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
                                <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
                                <line x1="12" y1="19" x2="12" y2="23"/>
                                <line x1="8" y1="23" x2="16" y2="23"/>
                            </svg>
                        </span>
                        <span class="call-btn-label">静音</span>
                    </button>
                    
                    <button class="call-btn" id="btnVideoToggle" title="切换视频">
                        <span class="call-btn-glow"></span>
                        <span class="call-btn-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polygon points="23 7 16 12 23 17 23 7"/>
                                <rect x="1" y="5" width="15" height="14" rx="2" ry="2"/>
                            </svg>
                        </span>
                        <span class="call-btn-label">视频</span>
                    </button>
                    
                    <button class="call-btn" id="btnSpeaker" title="扬声器">
                        <span class="call-btn-glow"></span>
                        <span class="call-btn-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/>
                                <path d="M19.07 4.93a10 10 0 0 1 0 14.14"/>
                                <path d="M15.54 8.46a5 5 0 0 1 0 7.07"/>
                            </svg>
                        </span>
                        <span class="call-btn-label">扬声器</span>
                    </button>
                    
                    <button class="call-btn" id="btnFlipCamera" title="切换摄像头">
                        <span class="call-btn-glow"></span>
                        <span class="call-btn-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/>
                                <path d="M9 13a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"/>
                            </svg>
                        </span>
                        <span class="call-btn-label">翻转</span>
                    </button>
                    
                    <button class="call-btn end-call" id="btnEndCall" title="结束通话">
                        <span class="call-btn-glow"></span>
                        <span class="call-btn-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/>
                                <line x1="1" y1="1" x2="23" y2="23"/>
                            </svg>
                        </span>
                        <span class="call-btn-label">结束</span>
                    </button>
                </div>
            </div>
        </div>
        
        <!-- 来电界面 -->
        <div id="incomingCallOverlay" class="incoming-call-overlay" style="display: none;">
            <div class="incoming-call-container">
                <div class="incoming-avatar">
                    <div class="avatar-particles"></div>
                    <div class="avatar-ring pulse"></div>
                    <span class="avatar-initial" id="incomingAvatarInitial">?</span>
                </div>
                <div class="incoming-info">
                    <div class="incoming-title">来电</div>
                    <div class="incoming-name" id="callerName">未知用户</div>
                    <div class="incoming-type" id="incomingCallType">语音通话</div>
                </div>
                <div class="incoming-controls">
                    <button class="call-btn reject" id="btnReject" title="拒绝">
                        <span class="call-btn-glow"></span>
                        <span class="call-btn-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72"/>
                                <line x1="1" y1="1" x2="23" y2="23"/>
                            </svg>
                        </span>
                        <span class="call-btn-label">拒绝</span>
                    </button>
                    <button class="call-btn accept" id="btnAccept" title="接听">
                        <span class="call-btn-glow"></span>
                        <span class="call-btn-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72"/>
                            </svg>
                        </span>
                        <span class="call-btn-label">接听</span>
                    </button>
                </div>
            </div>
        </div>
        
        <!-- 视频选择器 -->
        <div id="videoSelectModal" class="modal" style="display: none;">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>选择通话方式</h3>
                    <button class="modal-close" id="closeVideoSelect">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="call-type-options">
                        <button class="call-type-btn" id="btnVoiceCall">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72"/>
                            </svg>
                            <span>语音通话</span>
                        </button>
                        <button class="call-type-btn" id="btnVideoCall">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polygon points="23 7 16 12 23 17 23 7"/>
                                <rect x="1" y="5" width="15" height="14" rx="2" ry="2"/>
                            </svg>
                            <span>视频通话</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <style>
        /* ========== 通话覆盖层样式 - 3D 高光粒子质感 ========== */
        
        .call-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%);
            z-index: 9999;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .call-container {
            width: 100%;
            height: 100%;
            position: relative;
        }
        
        /* ========== 远端视频/头像区域 ========== */
        .call-remote {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 140px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        
        .remote-video {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        /* 3D 粒子光环头像 */
        .remote-avatar {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: linear-gradient(145deg, rgba(0,229,195,0.2), rgba(0,184,212,0.1));
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            box-shadow: 
                0 0 60px rgba(0,229,195,0.3),
                inset 0 0 30px rgba(0,229,195,0.1);
        }
        
        .avatar-particles {
            position: absolute;
            width: 180px;
            height: 180px;
            border-radius: 50%;
            background: 
                radial-gradient(circle at 30% 30%, rgba(0,229,195,0.4) 0%, transparent 50%),
                radial-gradient(circle at 70% 70%, rgba(0,184,212,0.3) 0%, transparent 50%),
                radial-gradient(circle at 50% 50%, rgba(0,229,195,0.1) 0%, transparent 70%);
            animation: particle-rotate 8s linear infinite;
        }
        
        @keyframes particle-rotate {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .avatar-ring {
            position: absolute;
            width: 140px;
            height: 140px;
            border-radius: 50%;
            border: 2px solid transparent;
            background: linear-gradient(135deg, #00e5c3, #00b8d4) border-box;
            -webkit-mask: 
                linear-gradient(#fff 0 0) padding-box, 
                linear-gradient(#fff 0 0);
            mask: 
                linear-gradient(#fff 0 0) padding-box, 
                linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            animation: ring-pulse 2s ease-in-out infinite;
        }
        
        @keyframes ring-pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.05); opacity: 0.8; }
        }
        
        .avatar-initial {
            font-size: 48px;
            font-weight: 700;
            color: white;
            text-shadow: 0 0 20px rgba(0,229,195,0.8);
            z-index: 10;
        }
        
        .call-peer-name {
            margin-top: 24px;
            font-size: 22px;
            font-weight: 600;
            color: white;
            text-shadow: 0 2px 10px rgba(0,0,0,0.5);
        }
        
        .call-status {
            font-size: 14px;
            color: rgba(255,255,255,0.6);
            margin-top: 8px;
        }
        
        /* ========== 本地视频预览 ========== */
        .call-local {
            position: absolute;
            top: 20px;
            right: 20px;
            width: 140px;
            height: 180px;
            border-radius: 12px;
            overflow: hidden;
            background: #0a0a15;
            border: 1px solid rgba(0,229,195,0.2);
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }
        
        .local-video {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        .local-placeholder {
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: rgba(255,255,255,0.3);
        }
        
        .local-placeholder svg {
            width: 48px;
            height: 48px;
        }
        
        /* ========== 通话计时 ========== */
        .call-timer {
            position: absolute;
            top: 30px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 16px;
            font-weight: 500;
            color: rgba(255,255,255,0.9);
            background: rgba(0,0,0,0.4);
            padding: 8px 20px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }
        
        /* ========== 控制按钮 - 3D 高光粒子质感 ========== */
        .call-controls {
            position: absolute;
            bottom: 40px;
            left: 50%;
            transform: translateX(-50%);
            display: flex;
            align-items: center;
            gap: 20px;
            padding: 0;
            background: transparent;
            border: none;
            box-shadow: none;
        }
        
        .call-btn {
            position: relative;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
            width: 72px;
            height: auto;
            padding: 0;
            border: none;
            background: transparent !important;
            color: white;
            cursor: pointer;
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        /* 覆盖 main.css 的干扰规则：结束键不再整体旋转、不再实心背景遮住水晶 */
        .call-btn.end-call {
            transform: none !important;
            background: transparent !important;
        }
        .call-btn.off {
            background: transparent !important;
        }
        .call-btn.accept,
        .call-btn.reject,
        .call-btn.hangup {
            background: transparent !important;
        }
        
        .call-btn:hover {
            transform: translateY(-4px);
        }
        
        .call-btn:active {
            transform: translateY(-2px) scale(0.96);
        }
        
        /* 能量水晶按钮外圈 - 棱镜折射光晕 */
        .call-btn-glow {
            position: absolute;
            top: 50%;
            left: 50%;
            width: 68px;
            height: 68px;
            transform: translate(-50%, -50%);
            border-radius: 50%;
            background: conic-gradient(from 0deg, rgba(0,229,195,0) 0%, rgba(0,229,195,0.55) 20%, rgba(120,240,255,0.5) 40%, rgba(0,184,212,0.45) 60%, rgba(0,229,195,0) 100%);
            opacity: 0;
            filter: blur(5px);
            transition: opacity 0.3s ease;
            pointer-events: none;
        }
        
        .call-btn:hover .call-btn-glow {
            opacity: 1;
            animation: crystal-glow 2s linear infinite;
        }
        
        @keyframes crystal-glow {
            0% { transform: translate(-50%, -50%) rotate(0deg) scale(1); opacity: 0.7; }
            50% { transform: translate(-50%, -50%) rotate(180deg) scale(1.15); opacity: 1; }
            100% { transform: translate(-50%, -50%) rotate(360deg) scale(1); opacity: 0.7; }
        }
        
        /* 能量水晶按钮本体 - 透明水晶质感 + 内发光 + 强制正圆 */
        .call-btn-icon {
            position: relative;
            width: 56px !important;
            height: 56px !important;
            min-width: 56px !important;
            min-height: 56px !important;
            max-width: 56px !important;
            max-height: 56px !important;
            border-radius: 50% !important;
            display: flex;
            align-items: center;
            justify-content: center;
            background:
                linear-gradient(155deg, rgba(255,255,255,0.45) 0%, rgba(255,255,255,0.08) 28%, transparent 45%),
                linear-gradient(205deg, transparent 52%, rgba(0,229,195,0.22) 78%, rgba(0,184,212,0.38) 100%),
                linear-gradient(145deg, rgba(140,245,255,0.30) 0%, rgba(0,229,195,0.22) 45%, rgba(0,110,150,0.34) 100%);
            border: 1px solid rgba(150,255,240,0.55);
            box-shadow:
                0 8px 22px rgba(0,0,0,0.45),
                0 0 22px rgba(0,229,195,0.35),
                inset 0 0 24px rgba(0,229,195,0.35),
                inset 0 1px 0 rgba(255,255,255,0.55),
                inset 0 -3px 8px rgba(0,90,130,0.45);
            backdrop-filter: blur(3px);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            overflow: hidden;
        }
        
        /* 水晶棱镜折射切面 */
        .call-btn-icon::before {
            content: '';
            position: absolute;
            top: -25%;
            left: 22%;
            width: 28%;
            height: 150%;
            background: linear-gradient(180deg, transparent 0%, rgba(255,255,255,0.28) 50%, transparent 100%);
            transform: rotate(25deg);
            pointer-events: none;
        }
        
        .call-btn:hover .call-btn-icon {
            background:
                linear-gradient(155deg, rgba(255,255,255,0.55) 0%, rgba(255,255,255,0.12) 28%, transparent 45%),
                linear-gradient(205deg, transparent 52%, rgba(0,229,195,0.30) 78%, rgba(0,184,212,0.48) 100%),
                linear-gradient(145deg, rgba(160,250,255,0.38) 0%, rgba(0,229,195,0.30) 45%, rgba(0,130,170,0.40) 100%);
            box-shadow:
                0 10px 28px rgba(0,0,0,0.5),
                0 0 34px rgba(0,229,195,0.55),
                inset 0 0 30px rgba(0,229,195,0.5),
                inset 0 1px 0 rgba(255,255,255,0.7),
                inset 0 -3px 8px rgba(0,90,130,0.5);
            transform: scale(1.06);
        }
        
        .call-btn:active .call-btn-icon {
            transform: scale(0.95);
            box-shadow:
                0 3px 12px rgba(0,0,0,0.4),
                0 0 16px rgba(0,229,195,0.4),
                inset 0 0 18px rgba(0,229,195,0.4),
                inset 0 2px 6px rgba(0,60,90,0.5);
        }
        
        .call-btn-icon svg {
            width: 22px;
            height: 22px;
            stroke-width: 2;
            filter: drop-shadow(0 1px 3px rgba(0,0,0,0.4)) drop-shadow(0 0 6px rgba(0,229,195,0.5));
        }
        
        .call-btn-label {
            font-size: 11px;
            font-weight: 500;
            color: rgba(190,255,245,0.85);
            text-shadow: 0 0 8px rgba(0,229,195,0.5), 0 1px 2px rgba(0,0,0,0.5);
            transition: color 0.3s ease;
        }
        
        .call-btn:hover .call-btn-label {
            color: rgba(220,255,250,1);
            text-shadow: 0 0 12px rgba(0,229,195,0.8);
        }
        
        /* ========== 结束通话键 - 红色能量水晶 ========== */
        .call-btn.end-call .call-btn-icon {
            background:
                linear-gradient(155deg, rgba(255,255,255,0.45) 0%, rgba(255,255,255,0.08) 28%, transparent 45%),
                linear-gradient(205deg, transparent 52%, rgba(255,71,87,0.25) 78%, rgba(200,30,50,0.45) 100%),
                linear-gradient(145deg, rgba(255,150,160,0.35) 0%, rgba(220,38,38,0.32) 45%, rgba(120,10,25,0.45) 100%);
            border: 1px solid rgba(255,160,170,0.55);
            box-shadow:
                0 8px 22px rgba(0,0,0,0.45),
                0 0 22px rgba(220,38,38,0.45),
                inset 0 0 24px rgba(255,71,87,0.45),
                inset 0 1px 0 rgba(255,255,255,0.5),
                inset 0 -3px 8px rgba(120,10,25,0.5);
        }
        
        .call-btn.end-call .call-btn-glow {
            background: conic-gradient(from 0deg, rgba(255,71,87,0) 0%, rgba(255,71,87,0.55) 20%, rgba(255,140,150,0.5) 40%, rgba(220,38,38,0.45) 60%, rgba(255,71,87,0) 100%);
            filter: blur(5px);
        }
        
        .call-btn.end-call:hover .call-btn-icon {
            background:
                linear-gradient(155deg, rgba(255,255,255,0.55) 0%, rgba(255,255,255,0.12) 28%, transparent 45%),
                linear-gradient(205deg, transparent 52%, rgba(255,71,87,0.32) 78%, rgba(220,38,38,0.52) 100%),
                linear-gradient(145deg, rgba(255,170,180,0.42) 0%, rgba(239,68,68,0.40) 45%, rgba(150,15,30,0.50) 100%);
            box-shadow:
                0 10px 28px rgba(0,0,0,0.5),
                0 0 34px rgba(220,38,38,0.6),
                inset 0 0 30px rgba(255,71,87,0.55),
                inset 0 1px 0 rgba(255,255,255,0.65),
                inset 0 -3px 8px rgba(120,10,25,0.55);
        }
        
        .call-btn.end-call .call-btn-icon svg {
            transform: rotate(135deg);
            filter: drop-shadow(0 1px 3px rgba(0,0,0,0.4)) drop-shadow(0 0 6px rgba(255,71,87,0.6));
        }
        
        .call-btn.end-call .call-btn-label {
            color: rgba(255,180,190,0.9);
            font-weight: 600;
            text-shadow: 0 0 8px rgba(255,71,87,0.6);
        }
        
        /* ========== 关闭态（静音/关视频）========== */
        .call-btn.off .call-btn-icon {
            background:
                linear-gradient(155deg, rgba(255,255,255,0.3) 0%, rgba(255,255,255,0.05) 28%, transparent 45%),
                linear-gradient(205deg, transparent 52%, rgba(255,71,87,0.20) 78%, rgba(150,20,35,0.4) 100%),
                linear-gradient(145deg, rgba(255,120,140,0.25) 0%, rgba(180,30,45,0.3) 45%, rgba(90,5,15,0.4) 100%);
            border: 1px solid rgba(255,140,150,0.5);
            box-shadow:
                0 6px 18px rgba(0,0,0,0.4),
                0 0 18px rgba(255,71,87,0.35),
                inset 0 0 20px rgba(255,71,87,0.35);
        }
        
        .call-btn.off .call-btn-icon svg {
            color: #ff8a96;
            filter: drop-shadow(0 0 6px rgba(255,71,87,0.5));
        }
        
        .call-btn.off .call-btn-label {
            color: #ff9aa5;
            text-shadow: 0 0 8px rgba(255,71,87,0.5);
        }
        
        /* ========== 来电界面 ========== */
        .incoming-call-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(ellipse at 50% 0%, rgba(0,229,195,0.08) 0%, transparent 50%),
                linear-gradient(180deg, #0d1117 0%, #161b22 100%);
            z-index: 9999;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .incoming-call-container {
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        
        .incoming-avatar {
            position: relative;
            width: 140px;
            height: 140px;
            border-radius: 50%;
            background: linear-gradient(145deg, rgba(0,229,195,0.15), rgba(0,184,212,0.08));
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 
                0 0 80px rgba(0,229,195,0.25),
                inset 0 0 40px rgba(0,229,195,0.08);
        }
        
        .incoming-avatar .avatar-particles {
            position: absolute;
            width: 200px;
            height: 200px;
        }
        
        .incoming-avatar .avatar-ring {
            width: 160px;
            height: 160px;
        }
        
        .incoming-avatar .avatar-initial {
            font-size: 56px;
        }
        
        .incoming-info {
            margin-top: 32px;
        }
        
        .incoming-title {
            font-size: 14px;
            font-weight: 500;
            letter-spacing: 3px;
            color: rgba(0,229,195,0.8);
            text-transform: uppercase;
            margin-bottom: 12px;
        }
        
        .incoming-name {
            font-size: 32px;
            font-weight: 700;
            color: white;
            margin-bottom: 8px;
            text-shadow: 0 2px 20px rgba(0,0,0,0.5);
        }
        
        .incoming-type {
            font-size: 15px;
            color: rgba(255,255,255,0.5);
        }
        
        .incoming-controls {
            display: flex;
            gap: 48px;
            margin-top: 48px;
        }
        
        .incoming-controls .call-btn {
            width: 88px;
        }
        
        .incoming-controls .call-btn-icon {
            width: 72px !important;
            height: 72px !important;
            min-width: 72px !important;
            min-height: 72px !important;
            max-width: 72px !important;
            max-height: 72px !important;
        }
        
        .incoming-controls .call-btn-icon svg {
            width: 28px;
            height: 28px;
        }
        
        .incoming-controls .call-btn-label {
            font-size: 13px;
            margin-top: 4px;
        }
        
        /* 接听键 - 青绿色能量水晶 */
        .incoming-controls .call-btn.accept .call-btn-icon {
            background:
                linear-gradient(155deg, rgba(255,255,255,0.5) 0%, rgba(255,255,255,0.1) 28%, transparent 45%),
                linear-gradient(205deg, transparent 52%, rgba(0,229,195,0.28) 78%, rgba(0,150,140,0.48) 100%),
                linear-gradient(145deg, rgba(120,255,225,0.42) 0%, rgba(0,229,195,0.35) 45%, rgba(0,110,130,0.45) 100%);
            border: 1px solid rgba(150,255,240,0.6);
            box-shadow:
                0 8px 22px rgba(0,0,0,0.45),
                0 0 26px rgba(0,229,195,0.5),
                inset 0 0 26px rgba(0,229,195,0.5),
                inset 0 1px 0 rgba(255,255,255,0.6),
                inset 0 -3px 8px rgba(0,100,110,0.5);
        }
        
        .incoming-controls .call-btn.accept .call-btn-glow {
            background: conic-gradient(from 0deg, rgba(0,229,195,0) 0%, rgba(0,229,195,0.55) 20%, rgba(120,240,255,0.5) 40%, rgba(0,184,212,0.45) 60%, rgba(0,229,195,0) 100%);
            filter: blur(5px);
        }
        
        .incoming-controls .call-btn.accept:hover .call-btn-icon {
            box-shadow:
                0 10px 28px rgba(0,0,0,0.5),
                0 0 38px rgba(0,229,195,0.65),
                inset 0 0 32px rgba(0,229,195,0.6),
                inset 0 1px 0 rgba(255,255,255,0.7);
        }
        
        /* 拒绝键 - 红色能量水晶 */
        .incoming-controls .call-btn.reject .call-btn-icon {
            background:
                linear-gradient(155deg, rgba(255,255,255,0.45) 0%, rgba(255,255,255,0.08) 28%, transparent 45%),
                linear-gradient(205deg, transparent 52%, rgba(255,71,87,0.25) 78%, rgba(200,30,50,0.45) 100%),
                linear-gradient(145deg, rgba(255,150,160,0.38) 0%, rgba(220,38,38,0.32) 45%, rgba(120,10,25,0.45) 100%);
            border: 1px solid rgba(255,160,170,0.55);
            box-shadow:
                0 8px 22px rgba(0,0,0,0.45),
                0 0 26px rgba(220,38,38,0.45),
                inset 0 0 26px rgba(255,71,87,0.45),
                inset 0 1px 0 rgba(255,255,255,0.5),
                inset 0 -3px 8px rgba(120,10,25,0.5);
        }
        
        .incoming-controls .call-btn.reject .call-btn-glow {
            background: conic-gradient(from 0deg, rgba(255,71,87,0) 0%, rgba(255,71,87,0.55) 20%, rgba(255,140,150,0.5) 40%, rgba(220,38,38,0.45) 60%, rgba(255,71,87,0) 100%);
            filter: blur(5px);
        }
        
        /* ========== 通话类型选择 ========== */
        .call-type-options {
            display: flex;
            gap: 24px;
            justify-content: center;
        }
        
        .call-type-btn {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 12px;
            padding: 32px 40px;
            background: 
                linear-gradient(145deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 16px;
            color: white;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .call-type-btn:hover {
            background: 
                linear-gradient(145deg, rgba(0,229,195,0.1) 0%, rgba(0,229,195,0.05) 100%);
            border-color: rgba(0,229,195,0.3);
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0,229,195,0.15);
        }
        
        .call-type-btn svg {
            width: 40px;
            height: 40px;
        }
        
        .call-type-btn span {
            font-size: 15px;
            font-weight: 500;
        }
        </style>
        `;
    }

    // 初始化 UI
    function init(options = {}) {
        // 插入 HTML
        document.body.insertAdjacentHTML('beforeend', getCallOverlayHTML());

        // 绑定事件
        bindEvents(options);
    }

    // 绑定事件
    function bindEvents(options) {
        // 结束通话
        const btnEndCall = document.getElementById('btnEndCall');
        if (btnEndCall) {
            btnEndCall.addEventListener('click', () => {
                if (options.onEndCall) options.onEndCall();
                hideCallOverlay();
            });
        }

        // 静音
        const btnMute = document.getElementById('btnMute');
        if (btnMute) {
            btnMute.addEventListener('click', () => {
                const isMuted = btnMute.classList.toggle('off');
                if (options.onToggleMute) options.onToggleMute(isMuted);
            });
        }

        // 视频切换
        const btnVideoToggle = document.getElementById('btnVideoToggle');
        if (btnVideoToggle) {
            btnVideoToggle.addEventListener('click', () => {
                const isOff = btnVideoToggle.classList.toggle('off');
                if (options.onToggleVideo) options.onToggleVideo(isOff);
            });
        }

        // 接听
        const btnAccept = document.getElementById('btnAccept');
        if (btnAccept) {
            btnAccept.addEventListener('click', () => {
                if (options.onAcceptCall) options.onAcceptCall();
                hideIncomingOverlay();
                showCallOverlay();
            });
        }

        // 拒绝
        const btnReject = document.getElementById('btnReject');
        if (btnReject) {
            btnReject.addEventListener('click', () => {
                if (options.onRejectCall) options.onRejectCall();
                hideIncomingOverlay();
            });
        }

        // 通话类型选择
        const btnVoiceCall = document.getElementById('btnVoiceCall');
        if (btnVoiceCall) {
            btnVoiceCall.addEventListener('click', () => {
                hideVideoSelectModal();
                if (options.onStartCall) options.onStartCall('voice');
            });
        }

        const btnVideoCall = document.getElementById('btnVideoCall');
        if (btnVideoCall) {
            btnVideoCall.addEventListener('click', () => {
                hideVideoSelectModal();
                if (options.onStartCall) options.onStartCall('video');
            });
        }

        const closeVideoSelect = document.getElementById('closeVideoSelect');
        if (closeVideoSelect) {
            closeVideoSelect.addEventListener('click', hideVideoSelectModal);
        }
    }

    // 显示通话界面
    function showCallOverlay() {
        const overlay = document.getElementById('callOverlay');
        if (overlay) overlay.style.display = 'flex';
    }

    // 隐藏通话界面
    function hideCallOverlay() {
        const overlay = document.getElementById('callOverlay');
        if (overlay) overlay.style.display = 'none';
    }

    // 显示来电界面
    function showIncomingOverlay(callerName, callType = 'voice') {
        const overlay = document.getElementById('incomingCallOverlay');
        const nameEl = document.getElementById('callerName');
        const typeEl = document.getElementById('incomingCallType');
        const initialEl = document.getElementById('incomingAvatarInitial');

        if (overlay) {
            overlay.style.display = 'flex';
            if (nameEl) nameEl.textContent = callerName || '未知用户';
            if (typeEl) typeEl.textContent = callType === 'video' ? '视频通话' : '语音通话';
            if (initialEl && callerName) {
                initialEl.textContent = callerName.charAt(0).toUpperCase();
            }
        }
    }

    // 隐藏来电界面
    function hideIncomingOverlay() {
        const overlay = document.getElementById('incomingCallOverlay');
        if (overlay) overlay.style.display = 'none';
    }

    // 显示通话类型选择
    function showVideoSelectModal() {
        const modal = document.getElementById('videoSelectModal');
        if (modal) modal.style.display = 'flex';
    }

    // 隐藏通话类型选择
    function hideVideoSelectModal() {
        const modal = document.getElementById('videoSelectModal');
        if (modal) modal.style.display = 'none';
    }

    // 更新通话状态
    function updateCallStatus(status) {
        const statusEl = document.getElementById('callStatus');
        if (statusEl) {
            const statusMap = {
                'calling': '正在呼叫...',
                'connected': '通话中',
                'ringing': '等待接听...',
                'ended': '通话已结束'
            };
            statusEl.textContent = statusMap[status] || status;
        }
    }

    // 更新对方名称
    function updatePeerName(name) {
        const nameEl = document.getElementById('callPeerName');
        const initialEl = document.getElementById('remoteInitial');
        
        if (nameEl) nameEl.textContent = name || '未知用户';
        if (initialEl && name) {
            initialEl.textContent = name.charAt(0).toUpperCase();
        }
    }

    // 更新计时器
    function updateTimer(seconds) {
        const timerEl = document.getElementById('callTimer');
        if (timerEl) {
            const mins = Math.floor(seconds / 60).toString().padStart(2, '0');
            const secs = (seconds % 60).toString().padStart(2, '0');
            timerEl.textContent = `${mins}:${secs}`;
        }
    }

    // 显示/隐藏本地预览
    function showLocalVideo(show) {
        const localVideo = document.getElementById('localVideo');
        const localPlaceholder = document.getElementById('localPlaceholder');
        
        if (localVideo) localVideo.style.display = show ? 'block' : 'none';
        if (localPlaceholder) localPlaceholder.style.display = show ? 'none' : 'flex';
    }

    // 显示/隐藏远端视频
    function showRemoteVideo(show) {
        const remoteVideo = document.getElementById('remoteVideo');
        const remoteAvatar = document.getElementById('remoteAvatar');
        
        if (remoteVideo) remoteVideo.style.display = show ? 'block' : 'none';
        if (remoteAvatar) remoteAvatar.style.display = show ? 'none' : 'flex';
    }

    // 设置本地视频流
    function setLocalStream(stream) {
        const localVideo = document.getElementById('localVideo');
        if (localVideo && stream) {
            localVideo.srcObject = stream;
            showLocalVideo(true);
        }
    }

    // 设置远端视频流
    function setRemoteStream(stream) {
        const remoteVideo = document.getElementById('remoteVideo');
        if (remoteVideo && stream) {
            remoteVideo.srcObject = stream;
            showRemoteVideo(true);
        }
    }

    // 导出 API
    return {
        init,
        showCallOverlay,
        hideCallOverlay,
        showIncomingOverlay,
        hideIncomingOverlay,
        showVideoSelectModal,
        hideVideoSelectModal,
        updateCallStatus,
        updatePeerName,
        updateTimer,
        showLocalVideo,
        showRemoteVideo,
        setLocalStream,
        setRemoteStream
    };
})();

// 自动初始化（可选）
if (typeof window !== 'undefined') {
    window.VideoCallUI = VideoCallUI;
}
