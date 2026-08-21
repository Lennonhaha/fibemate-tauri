/**
 * FIBEMATE 用户分级与权限系统
 * 
 * 用户等级：
 * 0 - 游客（未登录）
 * 1 - 手机验证用户
 * 2 - 实名认证用户
 * 3 - ZK验证用户（完整功能）
 */

// 权限定义
const PERMISSIONS = {
  // 基础功能
  VIEW_MESSAGES: { level: 0, name: '查看消息' },
  SEND_TEXT: { level: 1, name: '发送文字' },
  
  // 进阶功能
  SEND_IMAGE: { level: 2, name: '发送图片' },
  SEND_FILE: { level: 2, name: '发送文件' },
  CREATE_GROUP: { level: 2, name: '创建群聊' },
  VOICE_CALL: { level: 2, name: '语音通话' },
  
  // 高级功能
  ZK_ANONYMOUS: { level: 3, name: 'ZK匿名模式' },
  ADVANCED_CRYPTO: { level: 3, name: '高级加密设置' }
};

// 功能限制提示信息
const UPGRADE_MESSAGES = {
  1: '请验证手机号以使用此功能',
  2: '请完成实名认证以使用此功能',
  3: '请完成ZK验证以使用此功能'
};

/**
 * 检查用户权限
 * @param {string} action - 操作标识
 * @param {number} userLevel - 用户当前等级
 * @returns {object} { allowed: boolean, message?: string }
 */
function checkPermission(action, userLevel = 0) {
  const permission = PERMISSIONS[action];
  
  if (!permission) {
    return { allowed: false, message: '未知操作' };
  }
  
  if (userLevel >= permission.level) {
    return { allowed: true };
  }
  
  return {
    allowed: false,
    message: UPGRADE_MESSAGES[permission.level] || '权限不足',
    requiredLevel: permission.level,
    currentLevel: userLevel
  };
}

/**
 * 前端权限检查（用于 UI 控制）
 * @param {string} action 
 * @returns {boolean}
 */
function canPerform(action) {
  const userLevel = parseInt(localStorage.getItem('fk_user_level') || '0');
  return checkPermission(action, userLevel).allowed;
}

/**
 * 显示升级提示
 * @param {string} action 
 */
function showUpgradePrompt(action) {
  const result = checkPermission(action);
  if (!result.allowed) {
    // 显示提示弹窗
    const modal = document.createElement('div');
    modal.className = 'upgrade-modal';
    modal.innerHTML = `
      <div class="upgrade-content">
        <h3>功能受限</h3>
        <p>${result.message}</p>
        <div class="upgrade-actions">
          <button onclick="goToVerification()">去验证</button>
          <button onclick="closeModal()">稍后再说</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }
}

/**
 * 获取用户等级名称
 * @param {number} level 
 * @returns {string}
 */
function getLevelName(level) {
  const names = {
    0: '游客',
    1: '已验证用户',
    2: '实名用户',
    3: '高级用户'
  };
  return names[level] || '未知';
}

/**
 * 获取用户等级图标
 * @param {number} level 
 * @returns {string}
 */
function getLevelIcon(level) {
  const icons = {
    0: '👤',
    1: '✓',
    2: '✓✓',
    3: '🔒'
  };
  return icons[level] || '?';
}

// 导出模块
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    PERMISSIONS,
    checkPermission,
    canPerform,
    showUpgradePrompt,
    getLevelName,
    getLevelIcon
  };
}
