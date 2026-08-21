/**
 * FIBEMATE Phone Verification UI Module
 * 手机号验证码绑定 UI — 独立模块，零依赖
 * 
 * 用法：
 *   1. <script src="phone-verify.js"></script>
 *   2. 调用 PhoneVerify.init() 初始化
 *   3. 设置面板自动出现"绑定手机"项
 */

const PhoneVerify = (() => {
  const API_BASE = '';  // 同源，留空
  let countdown = 0;
  let countdownTimer = null;

  // ─── 工具函数 ───
  function $(sel) { return document.querySelector(sel); }
  function getToken() { return localStorage.getItem('fk_token'); }

  // ─── 创建模态框 HTML ───
  function createModal() {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'modalPhoneVerify';
    overlay.style.display = 'none';
    overlay.innerHTML = `
      <div class="modal" style="max-width:400px">
        <div class="modal-header">
          <h4>📱 绑定手机号</h4>
          <button class="modal-close" data-modal="modalPhoneVerify">×</button>
        </div>
        <div class="modal-body">
          <!-- 步骤1: 输入手机号 -->
          <div id="phoneStep1">
            <div class="input-group">
              <label>手机号码</label>
              <input type="tel" id="pvPhoneInput" placeholder="请输入手机号" maxlength="11" autocomplete="off"
                style="font-size:16px;letter-spacing:2px">
            </div>
            <button class="btn-primary" id="pvSendBtn" style="width:100%;margin-top:12px">
              发送验证码
            </button>
          </div>
          <!-- 步骤2: 输入验证码 -->
          <div id="phoneStep2" style="display:none">
            <div style="text-align:center;margin-bottom:16px">
              <div style="font-size:14px;color:var(--text-secondary,#888)">验证码已发送至</div>
              <div id="pvPhoneDisplay" style="font-size:18px;font-weight:600;margin-top:4px"></div>
            </div>
            <div class="input-group">
              <label>验证码</label>
              <input type="text" id="pvCodeInput" placeholder="6位验证码" maxlength="6" autocomplete="one-time-code"
                inputmode="numeric" pattern="[0-9]*"
                style="font-size:24px;letter-spacing:8px;text-align:center">
            </div>
            <button class="btn-primary" id="pvVerifyBtn" style="width:100%;margin-top:12px">
              验证并绑定
            </button>
            <div style="text-align:center;margin-top:12px">
              <button class="btn-text" id="pvResendBtn" style="font-size:13px" disabled>
                重新发送 <span id="pvCountdown"></span>
              </button>
            </div>
            <button class="btn-text" id="pvBackBtn" style="margin-top:8px">← 修改手机号</button>
          </div>
          <!-- 步骤3: 成功 -->
          <div id="phoneStep3" style="display:none;text-align:center;padding:20px 0">
            <div style="font-size:48px">✅</div>
            <h4 style="margin:12px 0 4px">绑定成功</h4>
            <p style="color:var(--text-secondary,#888);font-size:14px" id="pvBoundPhone"></p>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    return overlay;
  }

  // ─── 事件绑定 ───
  function bindEvents() {
    const modal = $('#modalPhoneVerify');

    // 关闭按钮
    modal.querySelectorAll('.modal-close').forEach(btn => {
      btn.addEventListener('click', () => closeModal());
    });
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });

    // 手机号输入 — 只允许数字
    $('#pvPhoneInput').addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/\D/g, '');
    });

    // 验证码输入 — 只允许数字
    $('#pvCodeInput').addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/\D/g, '');
    });

    // 发送验证码
    $('#pvSendBtn').addEventListener('click', handleSend);

    // 验证并绑定
    $('#pvVerifyBtn').addEventListener('click', handleVerify);

    // 重新发送
    $('#pvResendBtn').addEventListener('click', handleSend);

    // 返回修改手机号
    $('#pvBackBtn').addEventListener('click', () => {
      showStep(1);
      stopCountdown();
    });
  }

  // ─── 步骤切换 ───
  function showStep(n) {
    $('#phoneStep1').style.display = n === 1 ? '' : 'none';
    $('#phoneStep2').style.display = n === 2 ? '' : 'none';
    $('#phoneStep3').style.display = n === 3 ? '' : 'none';
  }

  // ─── 倒计时 ───
  function startCountdown(seconds) {
    countdown = seconds;
    const btn = $('#pvResendBtn');
    const span = $('#pvCountdown');
    btn.disabled = true;
    span.textContent = `(${countdown}s)`;

    countdownTimer = setInterval(() => {
      countdown--;
      if (countdown <= 0) {
        stopCountdown();
        btn.disabled = false;
        span.textContent = '';
      } else {
        span.textContent = `(${countdown}s)`;
      }
    }, 1000);
  }

  function stopCountdown() {
    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
    const btn = $('#pvResendBtn');
    const span = $('#pvCountdown');
    if (btn) { btn.disabled = false; span.textContent = ''; }
  }

  // ─── 发送验证码 ───
  async function handleSend() {
    const phone = $('#pvPhoneInput').value.trim();
    if (!/^1[3-9]\d{9}$/.test(phone)) {
      showToast('请输入正确的手机号', 'error');
      return;
    }

    const btn = $('#pvSendBtn');
    const origText = btn.textContent;
    btn.disabled = true;
    btn.textContent = '发送中...';

    try {
      const res = await fetch(`${API_BASE}/api/sms/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone })
      });
      const data = await res.json();

      if (!res.ok) {
        showToast(data.error || '发送失败', 'error');
        return;
      }

      // 切换到验证码输入
      $('#pvPhoneDisplay').textContent = phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2');
      showStep(2);
      startCountdown(60);
      $('#pvCodeInput').focus();
      showToast('验证码已发送', 'success');
    } catch (err) {
      showToast('网络错误，请重试', 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = origText;
    }
  }

  // ─── 验证并绑定 ───
  async function handleVerify() {
    const phone = $('#pvPhoneInput').value.trim();
    const code = $('#pvCodeInput').value.trim();

    if (code.length !== 6) {
      showToast('请输入6位验证码', 'error');
      return;
    }

    const btn = $('#pvVerifyBtn');
    const origText = btn.textContent;
    btn.disabled = true;
    btn.textContent = '验证中...';

    try {
      // 第1步：校验验证码，获取临时 token
      const verifyRes = await fetch(`${API_BASE}/api/sms/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone, code })
      });
      const verifyData = await verifyRes.json();

      if (!verifyRes.ok) {
        showToast(verifyData.error || '验证码错误', 'error');
        return;
      }

      const tempToken = verifyData.tempToken;
      const authToken = getToken();

      if (!authToken) {
        showToast('请先登录', 'error');
        closeModal();
        return;
      }

      // 第2步：绑定手机号
      const bindRes = await fetch(`${API_BASE}/api/sms/bind-phone`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
          'X-Phone-Token': tempToken
        },
        body: JSON.stringify({ phone })
      });
      const bindData = await bindRes.json();

      if (!bindRes.ok) {
        showToast(bindData.error || '绑定失败', 'error');
        return;
      }

      // 成功！
      stopCountdown();
      $('#pvBoundPhone').textContent = phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2');
      showStep(3);

      // 更新设置面板显示
      updateSettingDisplay(phone);

      // 2秒后自动关闭
      setTimeout(() => closeModal(), 2000);
      showToast('手机号绑定成功', 'success');
    } catch (err) {
      showToast('网络错误，请重试', 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = origText;
    }
  }

  // ─── 更新设置面板中的手机号显示 ───
  function updateSettingDisplay(phone) {
    const desc = $('#settingPhoneDesc');
    if (desc) {
      desc.textContent = phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2');
    }
    const item = $('#settingPhone');
    if (item) {
      item.classList.remove('danger');
    }
  }

  // ─── 打开/关闭模态框 ───
  function openModal() {
    const modal = $('#modalPhoneVerify');
    if (!modal) return;
    // 重置状态
    showStep(1);
    $('#pvPhoneInput').value = '';
    $('#pvCodeInput').value = '';
    stopCountdown();
    modal.style.display = 'flex';
  }

  function closeModal() {
    const modal = $('#modalPhoneVerify');
    if (!modal) return;
    modal.style.display = 'none';
    stopCountdown();
  }

  // ─── showToast 兼容（使用项目已有的或降级版） ───
  function showToast(msg, type) {
    if (typeof window.showToast === 'function') {
      window.showToast(msg, type);
      return;
    }
    // 降级：用 alert
    alert(msg);
  }

  // ─── 公开 API ───
  return {
    init() {
      createModal();
      bindEvents();
      // 绑定设置面板的点击事件
      const phoneSetting = document.getElementById('settingPhone');
      if (phoneSetting) {
        phoneSetting.addEventListener('click', openModal);
      }
    },
    open: openModal,
    close: closeModal
  };
})();
