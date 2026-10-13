// ============ 图标基础库（统一线条风格）============
const ICON_DEFS = {
  // 状态指示
  grid: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
  checkCircle: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="10"/><path d="M9 12l2 2 4-4"/></svg>',
  xCircle: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
  helpCircle: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/><circle cx="12" cy="17" r="0.5" fill="currentColor"/></svg>',
  alertTriangle: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="17" r="0.5" fill="currentColor"/></svg>',
  pause: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>',

  // 导航和箭头
  arrowUp: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 19V5M5 12l7-7 7 7"/></svg>',
  arrowDown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 5v14M19 12l-7 7-7-7"/></svg>',
  chevronUp: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M18 15l-6-6-6 6"/></svg>',
  chevronDown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M6 9l6 6 6-6"/></svg>',

  // 监控和时间
  activity: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
  clock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>',
  zap: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M13 2L3 14h8l-1 8 10-12h-8l1-8z"/></svg>',
  refreshCw: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>',

  // 数据和图表
  barChart: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
  trendingUp: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M23 6l-9.5 9.5-5-5L1 18"/><path d="M17 6h6v6"/></svg>',
  trendingDown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M23 18l-9.5-9.5-5 5L1 6"/><path d="M17 18h6v-6"/></svg>',

  // 文件和文档
  file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>',
  fileText: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>',
  folder: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>',

  // 通信
  messageSquare: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>',

  // 操作
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
  edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>',
  move: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M5 9l-3 3 3 3M9 5l3-3 3 3M15 19l-3 3-3-3M19 9l3 3-3 3M2 12h20M12 2v20"/></svg>',

  // 其他
  layers: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5M2 12l10 5 10-5"/></svg>',
  target: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
  settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="3"/><path d="M12 1v6m0 6v6M5.64 5.64l4.24 4.24m4.24 4.24l4.24 4.24M1 12h6m6 0h6M5.64 18.36l4.24-4.24m4.24-4.24l4.24-4.24"/></svg>',
  box: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/><path d="M3.27 6.96L12 12.01l8.73-5.05M12 22.08V12"/></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>'
};

// ============ 图标映射（使用引用避免重复）============
const icons = {
  // 状态相关
  total: ICON_DEFS.grid,
  up: ICON_DEFS.checkCircle,
  down: ICON_DEFS.xCircle,
  unknown: ICON_DEFS.helpCircle,
  warning: ICON_DEFS.alertTriangle,
  paused: ICON_DEFS.pause,

  // 监控属性
  type: ICON_DEFS.box,
  responseTime: ICON_DEFS.activity,
  interval: ICON_DEFS.clock,
  timeout: ICON_DEFS.clock,
  retries: ICON_DEFS.refreshCw,
  lastCheck: ICON_DEFS.clock,
  ssl: ICON_DEFS.lock,

  // 图表和记录
  chart: ICON_DEFS.barChart,
  records: ICON_DEFS.fileText,
  time: ICON_DEFS.clock,
  status: ICON_DEFS.layers,
  message: ICON_DEFS.messageSquare,

  // 统计信息
  avg: ICON_DEFS.barChart,
  fastest: ICON_DEFS.trendingUp,
  slowest: ICON_DEFS.trendingDown,
  uptime: ICON_DEFS.zap,

  // 操作相关
  add: ICON_DEFS.plus,
  edit: ICON_DEFS.edit,
  delete: ICON_DEFS.trash,
  sortUp: ICON_DEFS.chevronUp,
  sortDown: ICON_DEFS.chevronDown,
  drag: ICON_DEFS.move,
  folder: ICON_DEFS.folder,
  target: ICON_DEFS.target,
  empty: ICON_DEFS.messageSquare,
  settings: ICON_DEFS.settings
};

/**
 * @param {string} id
 * @returns {HTMLElement}
 */
function byId(id) {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Missing DOM element: ${id}`);
  }
  return element;
}

/**
 * @param {string} id
 * @returns {HTMLInputElement}
 */
function input(id) {
  return /** @type {HTMLInputElement} */ (byId(id));
}

/**
 * @param {string} id
 * @returns {HTMLFormElement}
 */
function form(id) {
  return /** @type {HTMLFormElement} */ (byId(id));
}

/**
 * @param {string} id
 * @returns {HTMLCanvasElement}
 */
function canvas(id) {
  return /** @type {HTMLCanvasElement} */ (byId(id));
}

/**
 * @param {Event} event
 * @returns {Element | null}
 */
function eventElement(event) {
  return event.target instanceof Element ? event.target : null;
}

/**
 * @param {Element} element
 * @param {string} className
 * @returns {boolean}
 */
function hasClass(element, className) {
  return Array.prototype.indexOf.call(element.classList, className) !== -1;
}

/**
 * @param {Element | null} element
 * @returns {HTMLInputElement | null}
 */
function asInput(element) {
  return element instanceof HTMLInputElement ? element : null;
}

/**
 * @param {CanvasRenderingContext2D} context
 * @param {object} config
 * @returns {any}
 */
function createChart(context, config) {
  const chartConstructor = window['Chart'];
  if (typeof chartConstructor !== 'function') {
    throw new Error('Chart.js is not loaded');
  }
  return new chartConstructor(context, config);
}

// ============ 主题切换 ============
const theme = ui.theme;

// ============ 安装向导 ============
const setup = {
  currentStep: 1,
  dbConfig: null,
  dbHasAdmin: false,

  async init() {
    const status = await ui.runtime.load();
    if (!status) { auth.showLogin(); return; }
    const {installed} = status;

    if (!installed) {
      this.show();
      this.bindEvents();
    } else {
      await auth.init();
    }
  },

  show() {
    const setupWizard = document.getElementById('setup-wizard');
    const loginPage = document.getElementById('login-page');
    const mainApp = document.getElementById('main-app');

    if (setupWizard) {
      setupWizard.style.display = 'flex';
    }
    if (loginPage) {
      loginPage.style.display = 'none';
    }
    if (mainApp) {
      mainApp.style.display = 'none';
    }
  },

  bindEvents() {
    document.getElementById('db-form').addEventListener('submit', (e) => {
      e.preventDefault();
      // 如果数据库已有管理员，直接完成安装
      if (this.dbHasAdmin) {
        this.completeSetupWithExistingAdmin().then(_r => {
        });
      } else {
        this.nextStep();
      }
    });

    document.getElementById('admin-form').addEventListener('submit', (e) => {
      e.preventDefault();
      this.completeSetup().then(_r => {
      });
    });
  },

  async testDatabase() {
    if (!ui.runtime.guardWrite()) return;
    const config = {
      host: input('db-host').value,
      port: parseInt(input('db-port').value),
      user: input('db-user').value,
      password: input('db-password').value,
      name: input('db-name').value
    };

    const resultEl = document.getElementById('db-test-result');
    const nextBtn = document.getElementById('btn-step1-next');

    resultEl.className = 'test-result testing';
    resultEl.textContent = '正在测试连接...';

    try {
      const response = await fetch('/api/install/test-db', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(config)
      });

      const result = await response.json();

      if (result.success) {
        this.dbConfig = config;
        this.dbHasAdmin = result.hasAdmin;

        if (result.hasAdmin) {
          // 数据库已有管理员，可以直接使用
          resultEl.className = 'test-result success';
          resultEl.innerHTML = `✓ ${result.message}<br><small style="opacity:0.8">点击"完成"直接使用现有数据</small>`;
          nextBtn.textContent = '完成';
          nextBtn.disabled = false;
        } else if (result.initialized) {
          // 数据库已初始化但没有管理员
          resultEl.className = 'test-result success';
          resultEl.innerHTML = `✓ 数据库已初始化，但没有管理员账户<br><small style="opacity:0.8">请创建管理员账户</small>`;
          nextBtn.textContent = '下一步';
          nextBtn.disabled = false;
        } else {
          // 全新数据库
          resultEl.className = 'test-result success';
          resultEl.textContent = '✓ ' + result.message;
          nextBtn.textContent = '下一步';
          nextBtn.disabled = false;
        }
      } else {
        resultEl.className = 'test-result error';
        resultEl.textContent = '✗ ' + result.message;
        nextBtn.disabled = true;
        this.dbHasAdmin = false;
      }
    } catch (e) {
      resultEl.className = 'test-result error';
      resultEl.textContent = '✗ 连接失败: ' + e.message;
      document.getElementById('btn-step1-next').disabled = true;
      this.dbHasAdmin = false;
    }
  },

  nextStep() {
    if (this.currentStep >= 3) return;

    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.remove('active');
    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.add('completed');
    this.currentStep++;
    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.add('active');

    document.querySelectorAll('.setup-step-content').forEach(el => el.classList.remove('active'));
    document.getElementById(`step-${this.currentStep}`).classList.add('active');
  },

  goToStep(step) {
    // 更新步骤指示器
    for (let i = 1; i <= 3; i++) {
      const stepEl = document.querySelector(`.step[data-step="${i}"]`);
      stepEl.classList.remove('active', 'completed');
      if (i < step) stepEl.classList.add('completed');
      if (i === step) stepEl.classList.add('active');
    }
    this.currentStep = step;

    document.querySelectorAll('.setup-step-content').forEach(el => el.classList.remove('active'));
    document.getElementById(`step-${step}`).classList.add('active');
  },

  prevStep() {
    if (this.currentStep <= 1) return;

    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.remove('active');
    this.currentStep--;
    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.remove('completed');
    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.add('active');

    document.querySelectorAll('.setup-step-content').forEach(el => el.classList.remove('active'));
    document.getElementById(`step-${this.currentStep}`).classList.add('active');
  },

  // 使用已有管理员完成安装
  async completeSetupWithExistingAdmin() {
    if (!ui.runtime.guardWrite()) return;
    try {
      const response = await fetch('/api/install/complete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          database: this.dbConfig,
          skipAdmin: true
        })
      });

      const result = await response.json();

      if (result.success) {
        document.getElementById('setup-complete-msg').textContent = '已连接到现有数据库，可以使用原有账户登录';
        this.goToStep(3);
      } else {
        app.showToast(result.error || '安装失败', 'error');
      }
    } catch (e) {
      app.showToast('安装失败: ' + e.message, 'error');
    }
  },

  async completeSetup() {
    if (!ui.runtime.guardWrite()) return;
    const password = input('admin-password').value;
    const passwordConfirm = input('admin-password-confirm').value;

    if (password !== passwordConfirm) {
      app.showToast('两次输入的密码不一致', 'error');
      return;
    }

    const adminConfig = {
      username: input('admin-username').value,
      email: input('admin-email').value,
      password: password
    };

    try {
      const response = await fetch('/api/install/complete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          database: this.dbConfig,
          admin: adminConfig,
          skipAdmin: false
        })
      });

      const result = await response.json();

      if (result.success) {
        document.getElementById('setup-complete-msg').textContent = 'Xilore UptimeBot 已成功安装';
        this.nextStep();
      } else {
        app.showToast(result.error || '安装失败', 'error');
      }
    } catch (e) {
      app.showToast('安装失败: ' + e.message, 'error');
    }
  }
};

// ============ 认证模块 ============
const auth = {
  user: null,

  async init() {
    try {
      const response = await fetch('/api/auth/me');
      if (response.ok) {
        const data = await response.json();
        this.user = data.user;
        this.showApp();
      } else {
        this.showLogin();
      }
    } catch (e) {
      this.showLogin();
    }
  },

  showLogin() {
    clearInterval(app.refreshInterval);
    app.closeDetailModal();
    app.resetSettings();
    if (typeof communications !== 'undefined') communications.reset();
    versions.reset();
    const sidebarVersion = document.getElementById('sidebar-version');
    if (sidebarVersion) sidebarVersion.hidden = true;
    ui.toggleSidebar(false);
    document.querySelectorAll('.modal-overlay.active').forEach(overlay => overlay.classList.remove('active'));
    const setupWizard = document.getElementById('setup-wizard');
    const loginPage = document.getElementById('login-page');
    const mainApp = document.getElementById('main-app');

    if (setupWizard) {
      setupWizard.style.display = 'none';
    }
    if (loginPage) {
      loginPage.style.display = 'flex';
    }
    if (mainApp) {
      mainApp.style.display = 'none';
    }
  },

  showApp() {
    const setupWizard = document.getElementById('setup-wizard');
    const loginPage = document.getElementById('login-page');
    const mainApp = document.getElementById('main-app');
    const currentUser = document.getElementById('current-user');

    if (setupWizard) {
      setupWizard.style.display = 'none';
    }
    if (loginPage) {
      loginPage.style.display = 'none';
    }
    if (mainApp) {
      mainApp.style.display = 'flex';
    }
    if (currentUser && this.user) {
      currentUser.textContent = this.user.username;
    }
    app.init().then(_r => {
    });
  },

  async login(e) {
    e.preventDefault();

    const username = input('login-username').value;
    const password = input('login-password').value;
    const errorEl = document.getElementById('login-error');

    errorEl.classList.remove('show');

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password})
      });

      const result = await response.json();

      if (result.success) {
        this.user = result.user;
        this.showApp();
      } else {
        errorEl.textContent = result.error || '登录失败';
        errorEl.classList.add('show');
      }
    } catch (e) {
      errorEl.textContent = '登录失败: ' + e.message;
      errorEl.classList.add('show');
    }
  },

  async logout() {
    try {
      await fetch('/api/auth/logout', {method: 'POST'});
    } catch (e) {
    }
    this.user = null;
    this.showLogin();
  }
};

// ============ 主应用 ============
// noinspection JSUnusedGlobalSymbols
const app = {
  monitors: [],
  groups: [],
  editingId: null,
  currentDetailId: null,
  currentTimeRange: '24h',
  refreshInterval: null,
  historyChart: null,
  detailChart: null,
  // 记录每个监控的状态条签名，避免无变化重绘导致闪烁
  statusBarSignatures: new Map(),
  statusBarsState: 'loading',
  statusBarRequestId: 0,
  currentSettingsSection: 'general',
  hasLoadedSettings: false,
  /** @type {AbortController | null} */
  settingsLoadController: null,
  searchQuery: '',
  statusFilter: 'all',
  groupFilter: 'all',
  collapsedGroups: new Set(),
  eventsBound: false,
  animateNextList: true,
  hasLoadedMonitors: false,
  detailHistory: [],
  detailLoaded: false,
  detailDisplayedRange: null,
  detailFailedRange: null,
  detailHistorySignature: null,
  /** @type {AbortController | null} */
  detailRequestController: null,
  currentView: 'overview',
  viewScroll: {overview: 0, groups: 0, settings: 0, announcements: 0, maintenances: 0},
  hasLoadedGroups: false,
  groupLoadError: false,
  savingGroupOrder: false,

  buildMonitorOpenUrl(m) {
    const rawTarget = (m?.target || '').trim();
    if (!rawTarget) return null;

    // 已经是 URL
    if (/^https?:\/\//i.test(rawTarget)) return rawTarget;

    // 非 URL：尽量按域名/IP 打开（TCP/PING 也允许用户点击跳转）
    const protocol = window.location.protocol === 'https:' ? 'https' : 'http';
    const port = m?.port ? String(m.port).trim() : '';
    if (port) return `${protocol}://${rawTarget}:${port}`;
    return `${protocol}://${rawTarget}`;
  },

  initIcons() {
    // 统计卡片图标
    const setIcon = (id, icon) => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = icon;
    };

    setIcon('stat-icon-total', icons.total);
    setIcon('stat-icon-up', icons.up);
    setIcon('stat-icon-down', icons.down);
    setIcon('stat-icon-paused', icons.paused);
    setIcon('stat-icon-uptime', icons.uptime);

    // 详情弹窗图标
    setIcon('detail-icon-type', icons.type);
    setIcon('detail-icon-response-time', icons.responseTime);
    setIcon('detail-icon-interval', icons.interval);
    setIcon('detail-icon-timeout', icons.timeout);
    setIcon('detail-icon-retries', icons.retries);
    setIcon('detail-icon-last-check', icons.lastCheck);
    setIcon('detail-icon-ssl', icons.ssl);
    setIcon('detail-icon-chart', icons.chart);
    setIcon('detail-icon-records', icons.records);

    // 表格图标
    setIcon('table-icon-time', icons.time);
    setIcon('table-icon-status', icons.status);
    setIcon('table-icon-response-time', icons.responseTime);
    setIcon('table-icon-message', icons.message);

    // 详情弹窗统计信息图标
    setIcon('detail-stat-icon-avg', icons.avg);
    setIcon('detail-stat-icon-min', icons.fastest);
    setIcon('detail-stat-icon-max', icons.slowest);
    setIcon('detail-stat-icon-uptime', icons.uptime);

    // 按钮和表单图标
    setIcon('btn-icon-add', icons.add);
    setIcon('modal-icon-title', icons.add);
    setIcon('form-icon-type', icons.type);
    setIcon('form-icon-target', icons.target);
    setIcon('form-icon-interval', icons.interval);
    setIcon('form-icon-timeout', icons.timeout);
    setIcon('form-icon-retries', icons.retries);
  },

  async init() {
    await ui.runtime.load();
    this.initIcons();
    if (typeof communications !== 'undefined') communications.init();
    this.bindEvents();
    this.showWorkspaceView(['#groups', '#settings', '#announcements', '#maintenances'].includes(location.hash) ? location.hash.slice(1) : 'overview');
    versions.load();
    await this.loadGroups();
    await this.loadMonitors();
    await this.loadStats();
    // 异步加载状态条数据（不阻塞首屏渲染）
    await this.loadStatusBars();
    this.startAutoRefresh();
  },

  bindEvents() {
    if (this.eventsBound) return;
    this.eventsBound = true;
    byId('main-app').querySelector('.skip-link').addEventListener('click', event => {
      // 保留当前页面地址，避免无障碍正文跳转覆盖工作区的路由锚点。
      event.preventDefault();
      byId('main-content').focus();
    });
    document.querySelectorAll('[data-workspace-link]').forEach(link => link.addEventListener('click', event => {
      const mouseEvent = /** @type {MouseEvent} */ (event);
      if (mouseEvent.ctrlKey || mouseEvent.metaKey || mouseEvent.shiftKey || mouseEvent.altKey || mouseEvent.button !== 0) return;
      event.preventDefault();
      this.showWorkspaceView(link.getAttribute('data-workspace-link'), {updateHistory: true, focus: true});
    }));
    window.addEventListener('hashchange', () => {
      // 跳转到正文的锚点不改变当前工作区；页面导航支持浏览器前进和后退。
      if (['', '#overview', '#groups', '#settings', '#announcements', '#maintenances'].includes(location.hash)) {
        this.showWorkspaceView(location.hash.slice(1) || 'overview', {focus: true});
      }
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const top = ui.dialogOrder[ui.dialogOrder.length - 1];
        const close = {'monitor-modal': 'closeModal', 'detail-modal': 'closeDetailModal'};
        if (top && close[top.id]) this[close[top.id]]();
      }
      const target = eventElement(e);
      if (e.key === '/' && this.currentView === 'overview' && !e.ctrlKey && !e.metaKey && !e.altKey && !ui.dialogOrder.length && target && !target.closest('input, textarea, select, [contenteditable="true"]') && auth.user) {
        e.preventDefault();
        input('monitor-search').focus();
      }
    });

    document.getElementById('monitor-search').addEventListener('input', () => {
      this.searchQuery = input('monitor-search').value.trim().toLowerCase();
      this.animateNextList = true;
      this.renderList();
    });
    document.getElementById('group-filter').addEventListener('change', () => {
      this.groupFilter = input('group-filter').value;
      this.animateNextList = true;
      this.renderList();
    });
    document.querySelectorAll('[data-filter]').forEach(button => button.addEventListener('click', () => {
      this.statusFilter = button.getAttribute('data-filter');
      this.animateNextList = true;
      this.renderList();
    }));
    document.getElementById('monitor-list').addEventListener('keydown', (event) => {
      const target = eventElement(event);
      if (target && target.matches('.monitor-item') && (event.key === 'Enter' || event.key === ' ')) {
        event.preventDefault();
        this.showDetail(Number(target.getAttribute('data-id')));
      }
    });
    document.addEventListener('themechange', () => {
      if (this.detailChart) this.renderDetailChart(this.detailHistory, {range: this.detailDisplayedRange});
    });

    // 监控弹窗点击外部不关闭（避免误操作丢失数据）

    document.getElementById('detail-modal').addEventListener('click', (e) => {
      const target = eventElement(e);
      if (!target) return;

      if (hasClass(target, 'modal-overlay')) {
        this.closeDetailModal();
        return;
      }
      const delBtn = target.closest('button[data-action="deleteHistoryRecord"]');
      if (delBtn) {
        e.stopPropagation();
        const monitorId = parseInt(delBtn.getAttribute('data-monitor-id') || '', 10);
        const historyId = parseInt(delBtn.getAttribute('data-history-id') || '', 10);
        if (monitorId && historyId) this.deleteHistoryRecord(monitorId, historyId).then(_r => {
        });
      }
    });

    input('delete-all-history-confirm').addEventListener('input', () => {
      byId('delete-all-history-btn').disabled = !ui.runtime.canWrite() || input('delete-all-history-confirm').value.trim() !== 'DELETE';
    });
    // 保存包含全部设置；先展示无效字段所在分类，让浏览器能聚焦并说明原因。
    form('settings-form').addEventListener('invalid', event => {
      const target = eventElement(event);
      const section = target && target.closest('.settings-section');
      if (section && target === form('settings-form').querySelector(':invalid')) {
        this.switchSettingsSection(section.id.replace('settings-section-', ''));
      }
    }, true);
    document.querySelectorAll('.time-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const range = tab.getAttribute('data-range');
        if (!this.currentDetailId || range === this.currentTimeRange) return;
        this.currentTimeRange = range;
        this.loadDetailData(this.currentDetailId);
      });
    });

    // 监控卡片点击事件（事件委托，避免内联 onclick 使用已废弃的全局 event）
    document.getElementById('monitor-list').addEventListener('click', (e) => {
      const target = eventElement(e);
      if (!target) return;

      const card = target.closest('.monitor-item');
      if (!card) return;

      // 点击链接或操作按钮时由委托处理，不打开详情
      if (target.closest('.monitor-target-link')) return;
      const actionBtn = target.closest('.monitor-actions button[data-action][data-id]');
      if (actionBtn) {
        e.stopPropagation();
        const action = actionBtn.getAttribute('data-action');
        const id = parseInt(actionBtn.getAttribute('data-id') || '', 10);
        if (action && id && typeof this[action] === 'function') {
          this[action](id);
        }
        return;
      }

      const id = parseInt(card.getAttribute('data-id') || '', 10);
      if (id) this.showDetail(id).then(_r => {
      });
    });
  },

  showWorkspaceView(view, {updateHistory = false, focus = false} = {}) {
    if (!['overview', 'groups', 'settings', 'announcements', 'maintenances'].includes(view)) return;
    const changed = this.currentView !== view;
    if (changed) this.viewScroll[this.currentView] = window.scrollY;
    this.currentView = view;
    if (updateHistory && location.hash !== `#${view}`) history.pushState(null, '', `#${view}`);

    document.querySelectorAll('[data-workspace-view]').forEach(panel => {
      if (panel instanceof HTMLElement) panel.hidden = panel.getAttribute('data-workspace-view') !== view;
    });
    document.querySelectorAll('[data-workspace-link]').forEach(link => {
      const active = link.getAttribute('data-workspace-link') === view;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    const title = {overview: '监控概览', groups: '分组管理', settings: '系统设置', announcements: '公告管理', maintenances: '维护管理'}[view];
    byId('workspace-breadcrumb').textContent = title;
    document.title = `${title} - Xilore Uptime`;
    byId('workspace-footer-note').textContent = {announcements: '草稿仅管理员可见，发布后在公开页展示', maintenances: '维护独立于暂停，重叠时段分别合并限制', overview: '状态条展示最近 24 小时的检测记录', groups: '分组顺序同步用于监控列表与公开状态页', settings: this.currentSettingsSection === 'about' ? '版本信息来自当前实例与 GitHub 索引' : '更改设置后，点击保存使其生效'}[view];
    if (view === 'groups' && changed) this.renderGroupList();
    if (view === 'settings') this.loadSettings();
    if (typeof communications !== 'undefined' && ['announcements', 'maintenances'].includes(view)) communications.load(view);
    ui.toggleSidebar(false);
    if (focus) {
      byId(`${view}-heading`).focus({preventScroll: true});
      if (changed) window.scrollTo({top: this.viewScroll[view], behavior: 'instant'});
    }
  },

  async loadGroups() {
    try {
      const response = await fetch('/api/groups', {credentials: 'same-origin'});
      if (response.status === 401) {
        auth.showLogin();
        return;
      }
      if (response.ok) {
        this.groups = await response.json();
        await this.normalizeGroupOrder();
        this.sortGroups();
        this.updateGroupSelect();
        this.hasLoadedGroups = true;
        this.groupLoadError = false;
      } else {
        console.warn('加载分组失败，状态码:', response.status);
        this.groupLoadError = true;
      }
    } catch (error) {
      console.error('加载分组失败:', error);
      this.groupLoadError = true;
    } finally {
      if (this.currentView === 'groups') this.renderGroupList();
    }
  },

  sortGroups() {
    this.groups.sort((a, b) => {
      const aOrder = a.sort_order ?? 0;
      const bOrder = b.sort_order ?? 0;
      if (aOrder !== bOrder) return aOrder - bOrder;
      return a.id - b.id;
    });
  },

  async normalizeGroupOrder() {
    if (!ui.runtime.canWrite()) return;
    const orders = this.groups.map(g => g.sort_order ?? 0);
    const hasMissingOrZero = orders.some(v => v <= 0);
    const uniqueCount = new Set(orders).size;
    const hasDuplicates = uniqueCount !== orders.length;
    const needsInit = hasMissingOrZero || hasDuplicates;
    if (!needsInit || this.groups.length === 0) return;

    // 使用当前顺序初始化排序值
    const updates = this.groups.map((g, index) => {
      g.sort_order = index + 1;
      return {id: g.id, sort_order: g.sort_order};
    });

    try {
      await Promise.all(
        updates.map(u =>
          fetch(`/api/groups/${u.id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({sort_order: u.sort_order})
          })
        )
      );
      this.sortGroups();
    } catch (error) {
      console.error('初始化分组排序失败:', error);
    }
  },

  updateGroupSelect() {
    const select = document.getElementById('monitor-group');
    if (!select) return;

    this.sortGroups();
    select.innerHTML = '<option value="">未分组</option>' +
      this.groups.map(g => `<option value="${g.id}">${this.escapeHtml(g.name)}</option>`).join('');
    const filter = input('group-filter');
    filter.innerHTML = '<option value="all">所有分组</option><option value="0">未分组</option>' +
      this.groups.map(g => `<option value="${g.id}">${this.escapeHtml(g.name)}</option>`).join('');
    if (this.groupFilter !== 'all' && this.groupFilter !== '0' && !this.groups.some(group => String(group.id) === this.groupFilter)) this.groupFilter = 'all';
    filter.value = this.groupFilter;
  },

  async loadMonitors() {
    try {
      const response = await fetch('/api/monitors');
      if (response.status === 401) {
        auth.showLogin();
        return;
      }
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const msg = errorData.error || '加载失败';
        console.error('加载监控列表失败:', msg);
        this.showToast('加载监控列表失败: ' + msg, 'error');
        this.showLoadError();
        return;
      }
      const data = await response.json();

      // 保留已有的 statusBar24h，避免基础数据刷新时状态条先变骨架屏导致闪烁
      const prevStatusBars = new Map(this.monitors.map(m => [String(m.id), m.statusBar24h]));
      this.monitors = data.map(m => ({
        ...m,
        statusBar24h: prevStatusBars.get(String(m.id)) || null
      }));
      this.hasLoadedMonitors = true;
      ui.updateHealth(this.monitors);
      ui.connection(true);
      this.renderList();
      this.updateGroupSummary();

      // 如果详情弹窗是打开的，更新详情弹窗的基础信息
      if (this.currentDetailId) {
        this.updateDetailInfo();
      }
    } catch (error) {
      console.error('加载监控列表失败:', error);
      this.showToast('加载监控列表失败: ' + (error.message || '未知错误'), 'error');
      this.showLoadError();
    }
  },

  showLoadError() {
    ui.connection(false);
    if (!this.hasLoadedMonitors) {
      document.getElementById('monitor-list').innerHTML = `<div class="empty-state">${ui.icon('alert')}<h3>暂时无法连接服务</h3><p>请检查网络连接后重试。</p><button class="btn-secondary" onclick="app.init()">重新加载</button></div>`;
      document.getElementById('health-title').textContent = '暂时无法获取服务状态';
      document.getElementById('health-description').textContent = '等待连接恢复后继续更新。';
    }
  },

  clearFilters() {
    this.searchQuery = '';
    this.statusFilter = 'all';
    this.groupFilter = 'all';
    input('monitor-search').value = '';
    input('group-filter').value = 'all';
    this.animateNextList = true;
    this.renderList();
  },

  monitorState(monitor) {
    if (monitor.enabled === 0 || monitor.enabled === false) return 'paused';
    if (monitor.maintenance?.active) return 'maintenance';
    return ['up', 'down', 'warning'].includes(monitor.status) ? monitor.status : 'unknown';
  },

  computeStatusBarSignature(statusBar24h) {
    if (!Array.isArray(statusBar24h)) return '';
    let out = '';
    for (const h of statusBar24h) {
      out += (h?.status || '_') + ':';
      const seg = Array.isArray(h?.segments) ? h.segments : null;
      if (seg) {
        for (let i = 0; i < seg.length; i++) {
          const s = seg[i];
          out += s ? s[0] : '_'; // up/down/warning -> u/d/w
        }
      }
      out += ';';
    }
    return out;
  },

  updateMonitorStatusBarDom(monitorId, statusBar24h) {
    const item = document.querySelector(`.monitor-item[data-id="${monitorId}"]`);
    if (!item) return;

    const newHtml = statusBar24h && Array.isArray(statusBar24h) && statusBar24h.length > 0
      ? this.renderStatusBar24h(statusBar24h)
      : this.renderStatusBarSkeleton();

    const existing = item.querySelector('.monitor-status-bar');
    if (existing) {
      existing.outerHTML = newHtml;
    } else {
      item.insertAdjacentHTML('beforeend', newHtml);
    }
  },

  async loadStatusBars() {
    const requestId = ++this.statusBarRequestId;
    try {
      const statusBarsRes = await fetch('/api/monitors/statusbars', {credentials: 'same-origin'});
      if (statusBarsRes.status === 401) {
        auth.showLogin();
        return;
      }
      if (!statusBarsRes.ok) throw new Error('暂时无法获取状态记录');
      const statusBars = await statusBarsRes.json();
      if (requestId !== this.statusBarRequestId) return;
      // 更新监控数据中的状态条信息
      const statusBarMap = new Map(statusBars.map(sb => [String(sb.monitorId), sb.statusBar24h]));

      // 只更新状态条（不整页重渲染），并且无变化不重绘，避免“闪一下”
      this.monitors = this.monitors.map(m => {
        const key = String(m.id);
        if (!statusBarMap.has(key)) return m;

        const sb = statusBarMap.get(key) || null;
        const sig = this.computeStatusBarSignature(sb);
        const prevSig = this.statusBarSignatures.get(key);
        if (sig !== prevSig) {
          this.statusBarSignatures.set(key, sig);
          this.updateMonitorStatusBarDom(m.id, sb);
        }

        return {...m, statusBar24h: sb};
      });
      this.statusBarsState = 'ready';
    } catch (error) {
      if (requestId !== this.statusBarRequestId) return;
      this.statusBarsState = 'error';
      console.error('加载状态条数据失败:', error);
    } finally {
      if (requestId === this.statusBarRequestId) {
        ui.groupHistory.update(document.getElementById('monitor-list'), this.monitors, this.statusBarsState);
      }
    }
  },

  updateDetailInfo({refreshHistory = true} = {}) {
    if (!this.currentDetailId) return;

    const monitor = this.monitors.find(m => m.id === this.currentDetailId);
    if (!monitor) {
      // 监控已被删除，关闭详情弹窗
      this.closeDetailModal();
      return;
    }

    // 更新基础信息
    document.getElementById('detail-title').textContent = monitor.name;
    document.getElementById('detail-target').textContent = monitor.target + (monitor.port ? ':' + monitor.port : '');
    document.getElementById('detail-status').className = 'detail-status ' + (monitor.effective_status || monitor.status);
    document.getElementById('detail-status').setAttribute('aria-hidden', 'true');
    document.getElementById('detail-state-label').textContent = ui.statusLabel(monitor);

    document.getElementById('detail-type').textContent = monitor.type.toUpperCase();
    document.getElementById('detail-response-time').textContent = monitor.last_response_time != null ? monitor.last_response_time + ' ms' : '-';
    document.getElementById('detail-interval').textContent = monitor.interval_seconds + ' 秒';
    document.getElementById('detail-timeout').textContent = (monitor.timeout_seconds || 10) + ' 秒';
    document.getElementById('detail-retries').textContent = monitor.retries || 0;
    document.getElementById('detail-last-check').textContent = monitor.last_check ? this.formatFullTime(monitor.last_check) : '-';
    const sslRow = document.getElementById('detail-ssl-days-row');
    const sslVal = document.getElementById('detail-ssl-days');
    if (monitor.ssl_days_remaining != null) {
      sslRow.style.display = '';
      sslVal.textContent = monitor.ssl_days_remaining > 0
        ? '剩余 ' + monitor.ssl_days_remaining + ' 天'
        : monitor.ssl_days_remaining === 0
          ? '已过期'
          : '已过期 ' + Math.abs(monitor.ssl_days_remaining) + ' 天';
    } else {
      sslRow.style.display = 'none';
      sslVal.textContent = '-';
    }

    // 刷新历史数据
    if (refreshHistory) this.loadDetailData(this.currentDetailId, {background: true});
  },

  async loadStats() {
    try {
      const response = await fetch('/api/stats');
      if (response.status === 401) return;
      const stats = await response.json();

      ui.setValue(document.getElementById('stat-total'), stats.total);
      ui.setValue(document.getElementById('stat-up'), stats.up);
      ui.setValue(document.getElementById('stat-down'), stats.down);
      const pausedEl = document.getElementById('stat-paused');
      ui.setValue(pausedEl, stats.paused ?? 0);
      ui.setValue(document.getElementById('stat-uptime'),
        stats.avgUptime24h !== null && stats.avgUptime24h !== undefined
          ? stats.avgUptime24h.toFixed(2) + '%'
          : '—');
    } catch (error) {
      console.error('加载统计失败:', error);
    }
  },

  renderList() {
    try {
      const container = document.getElementById('monitor-list');
      if (!container) {
        return;
      }

      const scopedMonitors = this.monitors.filter(monitor => {
        const matchesSearch = `${monitor.name || ''} ${monitor.target || ''}`.toLowerCase().includes(this.searchQuery);
        const matchesGroup = this.groupFilter === 'all' || String(monitor.group_id || 0) === this.groupFilter;
        return matchesSearch && matchesGroup;
      });
      const filteredMonitors = scopedMonitors.filter(monitor => this.statusFilter === 'all' || this.monitorState(monitor) === this.statusFilter);
      document.getElementById('nav-monitor-count').textContent = String(this.monitors.length);
      document.getElementById('monitor-result-count').textContent = String(filteredMonitors.length);
      document.querySelectorAll('[data-filter]').forEach(button => {
        const state = button.getAttribute('data-filter');
        const active = state === this.statusFilter;
        button.classList.toggle('active', active);
        button.setAttribute('aria-pressed', String(active));
        button.querySelector('[data-filter-count]').textContent = String(state === 'all' ? scopedMonitors.length : scopedMonitors.filter(monitor => this.monitorState(monitor) === state).length);
      });
      const hasFilters = Boolean(this.searchQuery) || this.statusFilter !== 'all' || this.groupFilter !== 'all';

      if (this.monitors.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            ${ui.icon('activity')}<h3>从第一次心跳开始</h3>
            <p>添加你的第一个监控，让服务的每一刻在线都清晰可见。</p>
            <button class="btn-primary" onclick="app.showAddModal()">${icons.add} 添加监控</button>
          </div>
        `;
        return;
      }

      if (filteredMonitors.length === 0 && hasFilters) {
        container.innerHTML = `<div class="empty-state">${ui.icon('search')}<h3>没有找到匹配的监控</h3><p>试试其他关键词，或调整状态与分组筛选。</p><button class="btn-secondary" onclick="app.clearFilters()">清除筛选</button></div>`;
        return;
      }

      // 按分组组织监控
      const grouped = {};
      const ungrouped = [];

      filteredMonitors.forEach(m => {
        if (m.group_id && this.groups.some(group => String(group.id) === String(m.group_id))) {
          if (!grouped[m.group_id]) grouped[m.group_id] = [];
          grouped[m.group_id].push(m);
        } else {
          ungrouped.push(m);
        }
      });

      let html = '';

      // 渲染分组（包括空分组）
      // 确保groups已初始化
      if (!this.groups) {
        this.groups = [];
      }
      this.groups.forEach(group => {
        const monitors = (grouped[group.id] || []).sort((a, b) => {
          // 按名称排序：英文字母在中文前面
          return sortByName(a.name || '', b.name || '');
        });
        if (!hasFilters || monitors.length > 0) html += this.renderGroupSection(group, monitors);
      });

      // 渲染未分组（如果有未分组的监控，或者没有任何监控时显示）
      if (ungrouped.length > 0 || this.monitors.length === 0) {
        const sortedUngrouped = ungrouped.sort((a, b) => {
          // 按名称排序：英文字母在中文前面
          return sortByName(a.name || '', b.name || '');
        });
        html += this.renderGroupSection({id: 0, name: '未分组'}, sortedUngrouped);
      }

      // 数据轮询保留折叠状态和键盘焦点，只在首次展示或筛选后播放入场动画。
      const focused = document.activeElement;
      const focusedCard = focused instanceof Element ? focused.closest('.monitor-item') : null;
      const focusedGroup = focused instanceof Element ? focused.closest('.group-header') : null;
      const focusSelector = focusedCard
        ? `.monitor-item[data-id="${focusedCard.getAttribute('data-id')}"]${focused === focusedCard ? '' : focused.matches('button[data-action]') ? ` button[data-action="${focused.getAttribute('data-action')}"]` : ' .monitor-target-link'}`
        : focusedGroup ? `.group-section[data-group-id="${focusedGroup.parentElement.getAttribute('data-group-id')}"] .group-header` : null;
      if (container.innerHTML !== html) {
        container.innerHTML = html;
        if (focusSelector) {
          const nextFocus = container.querySelector(focusSelector);
          if (nextFocus instanceof HTMLElement) nextFocus.focus({preventScroll: true});
        }
      }
      if (this.animateNextList) ui.enter(container);
      this.animateNextList = false;
    } catch (error) {
      console.error('渲染列表失败:', error);
      const container = document.getElementById('monitor-list');
      if (container) {
        container.innerHTML = `<div class="empty-state"><h3>渲染列表时出错: ${this.escapeHtml(error.message)}</h3></div>`;
      }
      throw error;
    }
  },

  getGroupStatus(monitors) {
    if (monitors.length === 0) return 'empty'; // 空分组 - 灰色或默认样式

    // 只参与状态计算的监控（排除已暂停）
    const active = monitors.filter(m => m.enabled !== 0 && m.enabled !== false);
    if (active.length === 0) return 'empty'; // 全部暂停时按空分组显示

    if (active.some(m => m.maintenance?.active)) {
      const outside = active.filter(m => !m.maintenance?.active);
      if (outside.some(m => m.status === 'down')) return 'critical';
      if (outside.some(m => m.status === 'warning')) return 'warning';
      return 'maintenance';
    }
    const upCount = active.filter(m => m.status === 'up').length;
    const totalCount = active.length;

    if (upCount === totalCount) {
      return 'healthy'; // 全部正常 - 绿色
    } else if (active.every(monitor => monitor.status === 'down')) {
      return 'critical'; // 全部有问题 - 红色
    } else {
      return 'warning'; // 部分有问题 - 黄色
    }
  },


  renderGroupSection(group, monitors) {
    const status = this.getGroupStatus(monitors);
    const isEmpty = monitors.length === 0;
    const collapsed = this.collapsedGroups.has(String(group.id));
    const statusText = {maintenance: '维护中', healthy: '运行正常', critical: '服务离线', warning: '需要关注', empty: '暂无检测'}[status];

    return `
      <div class="group-section ${status}${collapsed ? ' collapsed' : ''}" data-group-id="${group.id}">
        <button class="group-header" type="button" onclick="app.toggleGroup(${group.id})" aria-expanded="${!collapsed}" aria-controls="group-monitors-${group.id}">
          <svg class="group-toggle" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="6 9 12 15 18 9"/>
          </svg>
          <span class="group-folder">${ui.icon('folder')}</span>
          <span class="group-title">${this.escapeHtml(group.name)}</span>
          <span class="group-count">${monitors.length} 项</span>
          <span class="group-health">${statusText}${monitors.some(m => m.maintenance?.active && m.enabled) ? ` · 维护 ${monitors.filter(m => m.maintenance?.active && m.enabled).length} 项` : ''}</span>
          ${ui.groupHistory.render(monitors, this.statusBarsState)}
          <span class="group-collapse-label" aria-hidden="true"></span>
        </button>
        <div class="group-body" id="group-monitors-${group.id}"${collapsed ? ' inert' : ''}><div class="group-content"><div class="group-monitors">
          ${isEmpty
      ? '<div class="empty-group-message">该分组暂无监控项目</div>'
      : monitors.map(m => this.renderMonitorItem(m)).join('')
    }
        </div></div></div>
      </div>
    `;
  },

  // 渲染24小时状态条（共享函数）
  renderStatusBar24h(statusBar24h) {
    if (!statusBar24h || !Array.isArray(statusBar24h) || statusBar24h.length === 0) {
      return '';
    }

    // 强制使用正常模式（不启用细竖线模式）
    const useThinLine = false;

    // 生成 tooltip 文本
    const getTooltip = (item) => {
      if (!item || !item.startTime || !item.endTime) return '';
      try {
        const startStr = this.formatFullTime(new Date(item.startTime));
        const endStr = this.formatFullTime(new Date(item.endTime));
        const totalChecks = item.totalChecks || 0;
        const failCount = (item.downChecks || 0) + (item.warningChecks || 0);
        const uptime = item.uptime !== null && item.uptime !== undefined
          ? item.uptime.toFixed(2) + '%'
          : '—';
        const detail = item.message ? this.escapeHtml(item.message) :
          (item.status === 'up' ? '服务正常' :
            (item.status === null ? '无检测数据' : '-'));

        return `时间跨度: ${startStr} ~ ${endStr}\n可用率: ${uptime}\n失败次数 / 总检测次数: ${failCount} / ${totalChecks}\n详细信息: ${detail}${item.maintenanceChecks || item.segments?.includes('maintenance') ? '\n含维护时段；排除统计 ' + (item.excludedChecks || 0) + ' 次' : ''}`;
      } catch (e) {
        return '';
      }
    };

    // 渲染每个时间段（24个，每个拆分成12个小时间段）
    const segments = statusBar24h.map(item => {
      const startTime = new Date(item.startTime);
      const endTime = new Date(item.endTime);
      const segmentDuration = (endTime - startTime) / 12; // 每个小时间段的时间长度（5分钟）
      const tooltip = getTooltip(item).replace(/"/g, '&quot;').replace(/'/g, '&#39;');

      const subItems = [];
      let subStatuses;

      // 优先使用后端已聚合好的 segments（前端只负责渲染）
      if (Array.isArray(item.segments) && item.segments.length === 12) {
        subStatuses = item.segments.slice(0, 12);
      } else {
        // 兼容旧接口：使用 checkRecords 在前端聚合（保留以防回滚）
        const checkRecords = item.checkRecords || []; // 该时间段内的所有检测记录
        subStatuses = new Array(12).fill(null);
        const priority = {down: 3, warning: 2, up: 1};

        // 将检测记录映射到对应小块（同一小块取优先级最高状态）
        for (const record of checkRecords) {
          const checkTime = new Date(record.checked_at);
          if (checkTime < startTime || checkTime >= endTime) continue;
          const idx = Math.min(11, Math.max(0, Math.floor((checkTime - startTime) / segmentDuration)));
          const current = subStatuses[idx];
          if (!current || priority[record.status] > priority[current]) {
            subStatuses[idx] = record.status;
          }
        }

        // 向前填充空缺（使用最近一次状态），避免检测间隔大时出现灰块
        let lastKnown = null;
        for (let i = 0; i < subStatuses.length; i++) {
          if (subStatuses[i]) {
            lastKnown = subStatuses[i];
          } else if (lastKnown) {
            subStatuses[i] = lastKnown;
          }
        }

        // 向后填充开头空缺（使用最早一次状态）
        const firstKnownIndex = subStatuses.findIndex(status => status !== null);
        if (firstKnownIndex > 0) {
          for (let i = 0; i < firstKnownIndex; i++) {
            subStatuses[i] = subStatuses[firstKnownIndex];
          }
        }
      }

      for (let i = 0; i < 12; i++) {
        const subStatus = subStatuses[i];
        if (useThinLine) {
          // 细竖线模式：空数据保持灰色，warning/down 用细竖线，其余绿色
          if (subStatus === 'warning') {
            subItems.push(`<div class="status-bar-segment status-bar-segment-thin-warning" title="${tooltip}"></div>`);
          } else if (subStatus === 'down') {
            subItems.push(`<div class="status-bar-segment status-bar-segment-thin-down" title="${tooltip}"></div>`);
          } else if (subStatus == null) {
            subItems.push(`<div class="status-bar-segment status-bar-segment-empty" title="${tooltip}"></div>`);
          } else {
            subItems.push(`<div class="status-bar-segment status-bar-segment-up" title="${tooltip}"></div>`);
          }
        } else {
          // 正常模式：显示实际状态颜色
          const statusClass = subStatus === 'up' ? 'status-bar-segment-up' :
            subStatus === 'down' ? 'status-bar-segment-down' :
              subStatus === 'warning' ? 'status-bar-segment-warning' :
              subStatus === 'maintenance' ? 'status-bar-segment-maintenance' :
                'status-bar-segment-empty';
          subItems.push(`<div class="status-bar-segment ${statusClass}" title="${tooltip}"></div>`);
        }
      }
      return `<div class="status-bar-group">${subItems.join('')}</div>`;
    }).join('');

    return `<div class="monitor-status-bar ${useThinLine ? 'status-bar-thin' : ''}">${segments}</div>`;
  },

  renderStatusBarSkeleton() {
    // 显示一个整体的骨架屏条，不显示小格子
    return `<div class="monitor-status-bar status-bar-skeleton-container"><div class="status-bar-skeleton-full"></div></div>`;
  },

  renderMonitorItem(m) {
    // 如果状态条数据未加载或为空数组，显示骨架屏
    const statusBarHtml = m.statusBar24h && Array.isArray(m.statusBar24h) && m.statusBar24h.length > 0
      ? this.renderStatusBar24h(m.statusBar24h)
      : this.renderStatusBarSkeleton();
    const isPaused = m.enabled === 0 || m.enabled === false;
    const pauseIcon = isPaused
      ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>`
      : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>`;
    const pauseTitle = isPaused ? '恢复检测' : '暂停检测';

    const targetText = `${this.escapeHtml(m.target)}${m.port ? ':' + m.port : ''}`;
    const openUrl = this.buildMonitorOpenUrl(m);
    const targetHtml = openUrl
      ? `<a class="monitor-target monitor-target-link" href="${this.escapeHtml(openUrl)}" target="_blank" rel="noopener noreferrer" title="打开 ${this.escapeHtml(openUrl)}">${targetText}</a>`
      : `<span class="monitor-target">${targetText}</span>`;

    return `
      <article class="monitor-item ${m.maintenance?.active && !isPaused ? 'maintenance' : m.status}${isPaused ? ' paused' : ''}" data-id="${m.id}" tabindex="0" aria-label="查看 ${this.escapeHtml(m.name).replace(/"/g, '&quot;')} 的监控详情">
        <div class="monitor-status"></div>
        <div class="monitor-info">
          <div class="monitor-name">${this.escapeHtml(m.name)}</div>
          <div class="monitor-meta">
            <span class="monitor-type">${m.type.toUpperCase()}</span>
            ${targetHtml}
          </div>
        </div>
        <span class="monitor-state-label">${ui.statusLabel(m)}</span>
        <div class="monitor-stats">
          <div class="monitor-stat monitor-stat-response-time">
            <span class="monitor-stat-value">${ui.formatResponseTime(m.last_response_time)}</span>
            <span class="monitor-stat-label" title="最近一次检测的响应时间">最新延迟</span>
          </div>
          <div class="monitor-stat monitor-stat-uptime">
            <span class="monitor-stat-value">${m.uptime_24h !== null && m.uptime_24h !== undefined ? m.uptime_24h.toFixed(2) + '%' : '—'}</span>
            <span class="monitor-stat-label">24小时可用率</span>
          </div>
          ${ui.renderResponseStats(m)}
        </div>
        <div class="monitor-secondary-stats">
          <div class="monitor-secondary-stat">
            <span class="monitor-secondary-label">${icons.ssl} SSL 证书</span>
            <span class="monitor-secondary-value">${m.ssl_days_remaining == null ? '—' : m.ssl_days_remaining > 0 ? '剩余 ' + m.ssl_days_remaining + ' 天' : m.ssl_days_remaining === 0 ? '已过期' : '已过期 ' + Math.abs(m.ssl_days_remaining) + ' 天'}</span>
          </div>
          <div class="monitor-secondary-stat">
            <span class="monitor-secondary-label">${icons.lastCheck} 最后检测</span>
            <span class="monitor-secondary-value">${m.last_check ? this.formatFullTime(m.last_check) : '—'}</span>
          </div>
        </div>
        ${statusBarHtml}
        <div class="monitor-timeline-label"><span>24 小时前</span><span>现在</span></div>
        <div class="monitor-bottom"><span class="monitor-interval">${ui.icon('clock')}${isPaused ? '检测已暂停' : `每 ${m.interval_seconds} 秒检测`}</span><div class="monitor-actions">
          <button type="button" class="btn-icon${isPaused ? ' paused' : ''}" data-ui-write data-action="toggleMonitor" data-id="${m.id}" title="${pauseTitle}">
            ${pauseIcon}
          </button>
          <button type="button" class="btn-icon btn-icon-refresh" data-ui-write data-action="checkNow" data-id="${m.id}" title="立即检测">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M23 4v6h-6M1 20v-6h6"/>
              <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
            </svg>
          </button>
          <button type="button" class="btn-icon" data-action="showHistory" data-id="${m.id}" title="查看历史">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <polyline points="12 6 12 12 16 14"/>
            </svg>
          </button>
          <button type="button" class="btn-icon" data-action="editMonitor" data-id="${m.id}" title="编辑">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
              <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
            </svg>
          </button>
          <button type="button" class="btn-icon danger" data-ui-write data-action="deleteMonitor" data-id="${m.id}" title="删除">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="3 6 5 6 21 6"/>
              <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
            </svg>
          </button>
        </div></div>
      </article>
    `;
  },

  toggleGroup(groupId) {
    const section = document.querySelector(`.group-section[data-group-id="${groupId}"]`);
    if (section) {
      const collapsed = section.classList.toggle('collapsed');
      if (collapsed) this.collapsedGroups.add(String(groupId));
      else this.collapsedGroups.delete(String(groupId));
      section.querySelector('.group-header').setAttribute('aria-expanded', String(!collapsed));
      section.querySelector('.group-body').inert = collapsed;
    }
  },

  showAddModal() {
    if (!ui.runtime.guardWrite()) return;
    this.editingId = null;
    document.getElementById('modal-title').innerHTML = `<span class="modal-icon">${icons.add}</span> 添加监控`;
    form('monitor-form').reset();
    input('monitor-id').value = '';
    input('monitor-timeout').value = '10';
    input('monitor-retries').value = '0';
    input('monitor-expected-status').value = '200';
    input('monitor-group').value = '';
    input('monitor-is-public').checked = false;
    input('monitor-email-notification').checked = false;
    input('monitor-webhook-notification').checked = false;
    input('monitor-feishu-notification').checked = false;
    this.updateGroupSelect();
    this.togglePortField();
    document.getElementById('monitor-modal').classList.add('active');
  },

  // ============ 分组管理 ============
  updateGroupSummary() {
    byId('group-page-count').textContent = this.hasLoadedGroups ? String(this.groups.length) : '—';
    // 刷新数量和公开标记时不重建列表，保留正在编辑的名称及拖拽状态。
    const counts = new Map();
    this.monitors.forEach(monitor => counts.set(String(monitor.group_id), (counts.get(String(monitor.group_id)) || 0) + 1));
    document.querySelectorAll('#group-list .group-list-item').forEach(item => {
      const id = item.getAttribute('data-id');
      item.querySelector('.group-monitor-count').textContent = `${counts.get(id) || 0} 个监控`;
      item.querySelector('.group-public-badge').hidden = !this.hasPublicMonitors(Number(id));
    });
  },

  renderGroupList() {
    const container = document.getElementById('group-list');
    if (!this.hasLoadedGroups) {
      container.innerHTML = this.groupLoadError
        ? `<div class="empty-groups">${icons.folder}<h3>暂时无法加载分组</h3><p>请检查网络连接后重试。</p><button type="button" class="btn-secondary" onclick="app.loadGroups()">重新加载</button></div>`
        : '<div class="loading-state"><span class="loading-spinner"></span><p>正在加载分组…</p></div>';
      this.updateGroupSummary();
      return;
    }

    if (this.groups.length === 0) {
      container.innerHTML = `
        <div class="empty-groups">
          ${icons.folder.replace('width="16" height="16"', 'class="empty-icon" width="48" height="48"')}
          <h3>暂无分组</h3>
          <p>创建分组来更好地组织你的监控项目</p>
        </div>
      `;
      this.updateGroupSummary();
      return;
    }

    // 计算每个分组的监控数量
    const counts = {};
    this.monitors.forEach(m => {
      if (m.group_id) {
        counts[m.group_id] = (counts[m.group_id] || 0) + 1;
      }
    });

    this.sortGroups();
    container.innerHTML = this.groups.map((g, index) => `
      <div class="group-list-item" data-id="${g.id}" draggable="${ui.runtime.canWrite() && !this.savingGroupOrder}">
        <div class="group-drag-handle" title="拖拽排序">
          ${icons.drag}
        </div>
        <div class="group-item-icon">
          ${icons.folder}
        </div>
        <div class="group-item-info">
          <span class="group-name" data-group-id="${g.id}">${this.escapeHtml(g.name)}</span>
          <span class="group-monitor-count">${counts[g.id] || 0} 个监控</span>
          <span class="group-public-badge" title="包含公开服务"${this.hasPublicMonitors(g.id) ? '' : ' hidden'}>公开</span>
        </div>
        <div class="group-item-actions">
          <button type="button" class="btn-icon group-sort-action" data-ui-write data-group-move="up" onclick="app.moveGroup(${g.id}, -1)" title="上移分组" aria-label="上移分组"${index === 0 || this.savingGroupOrder ? ' disabled' : ''}>${icons.sortUp}</button>
          <button type="button" class="btn-icon group-sort-action" data-ui-write data-group-move="down" onclick="app.moveGroup(${g.id}, 1)" title="下移分组" aria-label="下移分组"${index === this.groups.length - 1 || this.savingGroupOrder ? ' disabled' : ''}>${icons.sortDown}</button>
          <button class="btn-icon" data-ui-write onclick="app.editGroupName(${g.id})" title="编辑名称">
            ${icons.edit}
          </button>
          <button class="btn-icon danger" data-ui-write onclick="app.deleteGroup(${g.id})" title="删除分组">
            ${icons.delete}
          </button>
        </div>
      </div>
    `).join('');

    // 初始化拖拽功能
    this.initDragAndDrop();
    this.updateGroupSummary();
  },

  async moveGroup(id, offset) {
    if (!ui.runtime.guardWrite() || this.savingGroupOrder) return;
    this.sortGroups();
    const index = this.groups.findIndex(group => group.id === id);
    const nextIndex = index + offset;
    if (index < 0 || nextIndex < 0 || nextIndex >= this.groups.length) return;
    await this.updateGroupOrderFromDOM(id, nextIndex);
    const item = document.querySelector(`#group-list .group-list-item[data-id="${id}"]`);
    const direction = offset < 0 ? 'up' : 'down';
    const button = item?.querySelector(`[data-group-move="${direction}"]:not(:disabled)`) || item?.querySelector('.group-sort-action:not(:disabled)');
    if (button instanceof HTMLElement) button.focus({preventScroll: true});
  },

  initDragAndDrop() {
    if (!ui.runtime.canWrite()) return;
    const container = document.getElementById('group-list');
    if (!container) {
      console.error('找不到 group-list 容器');
      return;
    }

    // 存储当前拖拽的分组ID
    let draggingGroupId = null;

    // 在容器上监听 drop 事件（事件委托）
    // 反复切换页面或重绘列表时替换容器处理器，避免重复提交排序请求。
    container.ondrop = async (e) => {
      e.preventDefault();
      e.stopPropagation();
      const target = eventElement(e);
      if (!target) return;

      if (!draggingGroupId) {
        console.error('没有拖拽中的分组ID');
        return;
      }

      // 尝试从 target 向上查找列表项
      let targetItem = target.closest('.group-list-item');

      // 如果没找到，尝试查找最近的占位符，然后找它的兄弟元素
      if (!targetItem) {
        const placeholder = target.closest('.drag-placeholder');
        if (placeholder) {
          // 占位符的前一个或后一个兄弟元素应该是列表项
          targetItem = placeholder.previousElementSibling || placeholder.nextElementSibling;
        }
      }

      // 如果还是没找到，尝试从鼠标位置查找
      if (!targetItem) {
        const items = container.querySelectorAll('.group-list-item:not(.dragging)');
        for (const item of items) {
          const rect = item.getBoundingClientRect();
          if (e.clientY >= rect.top && e.clientY <= rect.bottom) {
            targetItem = item;
            break;
          }
        }
      }

      // 如果还是没找到，使用占位符的位置
      if (!targetItem) {
        const placeholder = container.querySelector('.drag-placeholder');
        if (placeholder) {
          targetItem = placeholder.previousElementSibling || placeholder.nextElementSibling;
        }
      }

      if (!targetItem || !hasClass(targetItem, 'group-list-item')) {
        console.error('找不到目标列表项', {
          target,
          targetClassName: target.className,
          placeholder: container.querySelector('.drag-placeholder')
        });
        draggingGroupId = null;
        return;
      }

      const targetId = parseInt(targetItem.getAttribute('data-id') || '', 10);
      if (!targetId) {
        console.error('目标项没有有效的ID', targetItem);
        draggingGroupId = null;
        return;
      }

      if (targetId === draggingGroupId) {
        console.log('拖拽到同一位置，跳过');
        draggingGroupId = null;
        return;
      }

      const rect = targetItem.getBoundingClientRect();
      const midY = rect.top + rect.height / 2;
      const insertBefore = e.clientY < midY;

      // 移除占位符
      document.querySelectorAll('.drag-placeholder').forEach(el => el.remove());

      // 获取所有列表项的当前DOM顺序（排除拖拽中的项）
      const allItems = Array.from(container.querySelectorAll('.group-list-item:not(.dragging)'));
      const targetIndex = allItems.indexOf(targetItem);

      if (targetIndex === -1) {
        console.error('找不到目标项在列表中的位置');
        draggingGroupId = null;
        return;
      }

      // 计算新的插入位置
      const newDomIndex = insertBefore ? targetIndex : targetIndex + 1;

      // 更新顺序（基于DOM顺序）
      await this.updateGroupOrderFromDOM(draggingGroupId, newDomIndex);

      // 重置拖拽ID
      draggingGroupId = null;
    };

    // 在容器上监听 dragover 事件（必须调用 preventDefault 才能触发 drop）
    container.ondragover = (e) => {
      const dragEvent = /** @type {DragEvent} */ (e);
      e.preventDefault();
      if (dragEvent.dataTransfer) {
        dragEvent.dataTransfer.dropEffect = 'move';
      }

      const target = eventElement(e);
      if (!target) return;

      const targetItem = target.closest('.group-list-item');
      if (!targetItem) return;

      const dragging = document.querySelector('.dragging');
      if (!dragging || dragging === targetItem) return;

      const rect = targetItem.getBoundingClientRect();
      const midY = rect.top + rect.height / 2;

      // 移除旧的占位符
      document.querySelectorAll('.drag-placeholder').forEach(el => el.remove());

      // 插入占位符
      if (e.clientY < midY) {
        targetItem.insertAdjacentHTML('beforebegin', '<div class="drag-placeholder"></div>');
      } else {
        targetItem.insertAdjacentHTML('afterend', '<div class="drag-placeholder"></div>');
      }
    };

    // 为每个列表项添加拖拽事件
    const items = container.querySelectorAll('.group-list-item');
    items.forEach(item => {
      item.addEventListener('dragstart', (e) => {
        if (!ui.runtime.canWrite() || this.savingGroupOrder || eventElement(e)?.closest('input, button')) {
          e.preventDefault();
          return;
        }
        const dragEvent = /** @type {DragEvent} */ (e);
        const groupIdText = item.getAttribute('data-id') || '';
        draggingGroupId = parseInt(groupIdText, 10);
        if (dragEvent.dataTransfer) {
          dragEvent.dataTransfer.effectAllowed = 'move';
          dragEvent.dataTransfer.setData('text/plain', groupIdText);
        }
        item.classList.add('dragging');
      });

      item.addEventListener('dragend', (_e) => {
        item.classList.remove('dragging');
        // 移除所有占位符
        document.querySelectorAll('.drag-placeholder').forEach(el => el.remove());
        // 如果拖拽结束但没有触发 drop，重置ID
        if (draggingGroupId) {
          draggingGroupId = null;
        }
      });
    });
  },

  async updateGroupOrderFromDOM(draggedId, newDomIndex) {
    if (!ui.runtime.guardWrite() || this.savingGroupOrder) return;
    // 先按当前顺序排序
    this.sortGroups();

    const draggedIndex = this.groups.findIndex(g => g.id === draggedId);
    if (draggedIndex === -1) {
      console.error('找不到被拖拽的分组:', draggedId);
      return;
    }
    this.savingGroupOrder = true;
    byId('group-list').setAttribute('aria-busy', 'true');
    document.querySelectorAll('#group-list .group-sort-action').forEach(button => {
      if (button instanceof HTMLButtonElement) button.disabled = true;
    });

    // 移除拖拽的项目
    const draggedGroup = this.groups.splice(draggedIndex, 1)[0];

    // 计算新的插入位置（确保在有效范围内）
    const actualNewIndex = Math.max(0, Math.min(newDomIndex, this.groups.length));

    // 插入到新位置
    this.groups.splice(actualNewIndex, 0, draggedGroup);

    // 更新所有分组的 sort_order（从1开始）
    const updates = this.groups.map((g, index) => ({
      id: g.id,
      sort_order: index + 1
    }));

    try {
      // 批量更新数据库
      await Promise.all(
        updates.map(async u => {
          const res = await fetch(`/api/groups/${u.id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            credentials: 'same-origin',
            body: JSON.stringify({sort_order: u.sort_order})
          });

          if (!res.ok) {
            const error = await res.json().catch(() => ({error: '未知错误'}));
            throw new Error(`更新分组 ${u.id} 失败: ${error.error || res.statusText}`);
          }

          return await res.json();
        })
      );


      // 更新本地数据的 sort_order
      updates.forEach(u => {
        const group = this.groups.find(g => g.id === u.id);
        if (group) {
          group.sort_order = u.sort_order;
        }
      });

      // 重新加载分组以确保数据同步
      await this.loadGroups();
      this.updateGroupSelect();
      this.renderList();
      this.showToast('分组顺序已更新', 'success');
    } catch (error) {
      console.error('更新分组顺序失败:', error);
      this.showToast(`分组排序失败: ${error.message}`, 'error');
      // 重新加载分组以恢复原状态
      await this.loadGroups();
    } finally {
      this.savingGroupOrder = false;
      byId('group-list').removeAttribute('aria-busy');
      this.renderGroupList();
    }
  },

  async addGroup(e) {
    if (!ui.runtime.guardWrite(e)) return;
    e.preventDefault();
    const nameInput = input('new-group-name');
    const name = nameInput.value.trim();

    if (!name) return;

    // 检查名称是否已存在
    const isDuplicate = this.groups.some(g => g.name === name);
    if (isDuplicate) {
      this.showToast('分组名称已存在', 'error');
      nameInput.focus();
      return;
    }

    try {
      const response = await fetch('/api/groups', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name})
      });

      if (!response.ok) {
        const data = await response.json();
        this.showToast(data.error || '添加失败', 'error');
        return;
      }

      const group = await response.json();
      if (group.sort_order === undefined || group.sort_order === null) {
        group.sort_order = this.groups.length + 1;
      }
      this.groups.push(group);
      this.sortGroups();
      this.renderGroupList();
      this.updateGroupSelect();
      nameInput.value = '';
      this.showToast('分组添加成功', 'success');
    } catch (error) {
      this.showToast(error.message || '添加分组失败', 'error');
    }
  },

  hasPublicMonitors(groupId) {
    // 检查分组下是否有公开的监控
    return this.monitors.some(m => m.group_id === groupId && (m.is_public === 1 || m.is_public === true));
  },

  editGroupName(id) {
    if (!ui.runtime.guardWrite()) return;
    const group = this.groups.find(g => g.id === id);
    if (!group) return;

    const nameSpan = document.querySelector(`.group-name[data-group-id="${id}"]`);
    if (!nameSpan) return;

    const oldName = group.name;
    const input = document.createElement('input');
    input.type = 'text';
    input.setAttribute('aria-label', '分组名称');
    input.value = oldName;
    input.className = 'group-name-input';

    let finished = false;
    const saveEdit = async () => {
      if (finished) return;
      finished = true;
      const newName = input.value.trim();
      input.remove();
      nameSpan.textContent = oldName;

      if (!newName) {
        this.showToast('分组名称不能为空', 'error');
        nameSpan.textContent = oldName;
        return;
      }

      if (newName === oldName) {
        nameSpan.textContent = oldName;
        return;
      }

      // 检查名称是否与其他分组重复
      const isDuplicate = this.groups.some(g => g.id !== id && g.name === newName);
      if (isDuplicate) {
        this.showToast('分组名称已存在', 'error');
        nameSpan.textContent = oldName;
        return;
      }

      try {
        const response = await fetch(`/api/groups/${id}`, {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({name: newName})
        });

        if (!response.ok) {
          const data = await response.json();
          this.showToast(data.error || '更新失败', 'error');
          nameSpan.textContent = oldName;
          return;
        }

        group.name = newName;
        nameSpan.textContent = newName;
        this.updateGroupSelect();
        this.renderList();
        this.showToast('分组名称已更新', 'success');
      } catch (error) {
        this.showToast(error.message || '更新失败', 'error');
        nameSpan.textContent = oldName;
      }
    };

    const cancelEdit = () => {
      if (finished) return;
      finished = true;
      input.remove();
      nameSpan.textContent = oldName;
    };

    input.addEventListener('blur', saveEdit);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        input.blur();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        cancelEdit();
      }
    });

    nameSpan.textContent = '';
    nameSpan.appendChild(input);
    input.focus();
    input.select();
  },

  async deleteGroup(id) {
    if (!ui.runtime.guardWrite()) return;
    if (!await ui.confirm('确定要删除此分组吗？分组内的监控将移至"未分组"。')) return;

    try {
      const response = await fetch(`/api/groups/${id}`, {method: 'DELETE'});
      if (!response.ok) {
        this.showToast('删除失败', 'error');
        return;
      }

      this.groups = this.groups.filter(g => g.id !== id);
      this.monitors.forEach(m => {
        if (m.group_id === id) m.group_id = null;
      });

      this.renderGroupList();
      this.updateGroupSelect();
      this.renderList();
      this.showToast('分组已删除', 'success');
    } catch (error) {
      this.showToast('删除分组失败', 'error');
    }
  },

  editMonitor(id) {
    const monitor = this.monitors.find(m => m.id === id);
    if (!monitor) return;

    // 保留详情弹窗，不关闭

    this.editingId = id;
    this.updateGroupSelect();
    document.getElementById('modal-title').innerHTML = `<span class="modal-icon">${icons.edit}</span> ${ui.runtime.canWrite() ? '编辑监控' : '查看监控配置'}`;
    input('monitor-id').value = String(id);
    input('monitor-name').value = monitor.name;
    input('monitor-type').value = monitor.type;
    input('monitor-target').value = monitor.target;
    input('monitor-port').value = monitor.port || '';
    input('monitor-interval').value = String(monitor.interval_seconds);
    input('monitor-timeout').value = String(monitor.timeout_seconds || 10);
    input('monitor-retries').value = String(monitor.retries || 0);
    input('monitor-expected-status').value = String(monitor.expected_status || 200);
    input('monitor-group').value = monitor.group_id ? String(monitor.group_id) : '';
    input('monitor-is-public').checked = monitor.is_public === 1 || monitor.is_public === true;
    input('monitor-email-notification').checked = monitor.email_notification === 1 || monitor.email_notification === true;
    input('monitor-webhook-notification').checked = monitor.webhook_notification === 1 || monitor.webhook_notification === true;
    input('monitor-feishu-notification').checked = monitor.feishu_notification === 1 || monitor.feishu_notification === true;
    input('monitor-auth-username').value = monitor.auth_username || '';
    const pwdInput = document.getElementById('monitor-auth-password');
    if (pwdInput) {
      // 不回填敏感密码
      pwdInput.value = '';
      const hasPwd = monitor.auth_password_set === true || monitor.auth_password_set === 1;
      pwdInput.placeholder = hasPwd ? '已设置（留空不修改）' : '（可选）';
    }

    this.togglePortField();
    document.getElementById('monitor-modal').classList.add('active');
  },

  closeModal() {
    document.getElementById('monitor-modal').classList.remove('active');
    this.editingId = null;
  },

  togglePortField() {
    const type = input('monitor-type').value;
    const portGroup = document.getElementById('port-group');
    const portInput = document.getElementById('monitor-port');
    const expectedStatusGroup = document.getElementById('expected-status-group');
    const authGroup = document.getElementById('auth-group');

    // TCP 端口字段
    if (type === 'tcp') {
      portGroup.style.display = 'block';
      portInput.required = true;
    } else {
      portGroup.style.display = 'none';
      portInput.required = false;
    }

    // HTTP 相关字段（期望状态码和 Basic Auth）
    if (type === 'http') {
      expectedStatusGroup.style.display = 'block';
      authGroup.style.display = 'block';
    } else {
      expectedStatusGroup.style.display = 'none';
      authGroup.style.display = 'none';
    }
  },

  async saveMonitor(e) {
    if (!ui.runtime.guardWrite(e)) return;
    e.preventDefault();

    const type = input('monitor-type').value;
    const groupId = input('monitor-group').value;
    const data = {
      name: input('monitor-name').value,
      type: type,
      target: input('monitor-target').value,
      port: input('monitor-port').value ? parseInt(input('monitor-port').value) : null,
      interval_seconds: parseInt(input('monitor-interval').value),
      timeout_seconds: parseInt(input('monitor-timeout').value),
      retries: parseInt(input('monitor-retries').value),
      expected_status: type === 'http' ? parseInt(input('monitor-expected-status').value) : 200,
      group_id: (groupId && groupId !== '') ? parseInt(groupId) : null,
      is_public: input('monitor-is-public').checked,
      email_notification: input('monitor-email-notification').checked,
      webhook_notification: input('monitor-webhook-notification').checked,
      feishu_notification: input('monitor-feishu-notification').checked,
      auth_username: type === 'http' ? input('monitor-auth-username').value.trim() || null : null,
      auth_password: type === 'http' ? (input('monitor-auth-password').value || null) : null
    };

    // 编辑模式下：密码留空代表“不修改”，不要发送 auth_password 字段（避免覆盖为 null）
    if (this.editingId && type === 'http') {
      const pwdVal = input('monitor-auth-password').value;
      if (!pwdVal) {
        delete data.auth_password;
      }
    }

    try {
      const isEdit = !!this.editingId;
      const url = isEdit ? `/api/monitors/${this.editingId}` : '/api/monitors';
      const method = isEdit ? 'PUT' : 'POST';

      const response = await fetch(url, {
        method,
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
      });

      if (response.status === 401) {
        auth.showLogin();
        return;
      }

      if (!response.ok) {
        const error = await response.json();
        this.showToast(error.error || '保存失败', 'error');
        return;
      }

      const savedMonitor = await response.json();
      const monitorId = savedMonitor.id || this.editingId;

      this.showToast(isEdit ? '监控已更新' : '监控已添加', 'success');
      this.closeModal();

      // 重新加载列表和统计
      await this.loadMonitors();
      await this.loadStats();
      // 异步加载状态条数据
      await this.loadStatusBars();

      // 如果详情弹窗是打开的，刷新详情数据
      if (this.currentDetailId === monitorId) {
        await this.loadDetailData(monitorId);
      }

      // 立即执行一次检测（静默模式，不显示额外的提示）
      // 注意：如果该监控处于暂停状态（enabled=0），不要自动触发检测
      if (monitorId) {
        // 延迟一下，确保列表已更新
        setTimeout(async () => {
          const m = this.monitors.find(x => x.id === monitorId);
          const enabled = m ? (m.enabled === 1 || m.enabled === true) : (savedMonitor?.enabled === 1 || savedMonitor?.enabled === true);
          if (enabled) {
            await this.checkNow(monitorId, true);
          }
        }, 300);
      }
    } catch (error) {
      this.showToast(error.message, 'error');
    }
  },

  /** 暂停/恢复监控。由监控卡片上的 data-ui-write data-action="toggleMonitor" 按钮通过事件委托调用，勿删。 */
  async toggleMonitor(id) {
    if (!ui.runtime.guardWrite()) return;
    try {
      // 找到当前监控
      const monitor = this.monitors.find(m => m.id === id);
      if (!monitor) return;

      const newEnabled = monitor.enabled === 0 || monitor.enabled === false ? 1 : 0;
      const action = newEnabled ? '恢复' : '暂停';

      const response = await fetch(`/api/monitors/${id}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: newEnabled})
      });

      if (response.status === 401) {
        auth.showLogin();
        return;
      }

      if (!response.ok) {
        this.showToast('操作失败', 'error');
        return;
      }

      this.showToast(`监控已${action}`, 'success');
      await this.loadMonitors();
      await this.loadStats();
      // 异步加载状态条数据
      await this.loadStatusBars();
    } catch (error) {
      this.showToast('操作失败', 'error');
    }
  },

  /** 删除监控。由监控卡片上的 data-ui-write data-action="deleteMonitor" 按钮通过事件委托调用，勿删。 */
  // eslint-disable-next-line no-unused-vars -- 通过 this[action](id) 动态调用
  async deleteMonitor(id) {
    if (!ui.runtime.guardWrite()) return;
    if (!await ui.confirm('确定要删除这个监控吗？')) return;

    try {
      const response = await fetch(`/api/monitors/${id}`, {method: 'DELETE'});
      if (response.status === 401) {
        auth.showLogin();
        return;
      }
      this.showToast('监控已删除', 'success');
      await this.loadMonitors();
      await this.loadStats();
      // 异步加载状态条数据
      await this.loadStatusBars();
    } catch (error) {
      this.showToast('删除失败', 'error');
    }
  },

  async checkNow(id, silent = false) {
    if (!ui.runtime.guardWrite()) return;
    // 查找主页的按钮（刷新按钮是第二个 btn-icon）
    const item = document.querySelector(`.monitor-item[data-id="${id}"]`);
    const btn = item?.querySelector('.btn-icon-refresh');

    // 查找详情弹窗的按钮
    const detailModal = byId('detail-modal');
    const detailBtn = hasClass(detailModal, 'active')
      ? detailModal.querySelector('.detail-footer .btn-primary')
      : null;

    // 添加加载动画
    if (btn) {
      btn.classList.add('loading');
      const btnSvg = btn.querySelector('svg');
      if (btnSvg) btnSvg.style.animation = 'spin 1s linear infinite';
    }

    if (detailBtn) {
      detailBtn.classList.add('loading');
      const detailSvg = detailBtn.querySelector('svg');
      if (detailSvg) detailSvg.style.animation = 'spin 1s linear infinite';
      detailBtn.disabled = true;
    }

    try {
      const response = await fetch(`/api/monitors/${id}/check`, {method: 'POST'});
      if (response.status === 401) {
        auth.showLogin();
        return;
      }
      const result = await response.json();
      if (!response.ok) {if (!silent) this.showToast(result.error || '检测失败', 'error'); return;}

      // 如果不是静默模式，显示检测结果提示
      if (!silent) {
        const responseTimeText = result.responseTime !== null && result.responseTime !== undefined
          ? `${result.responseTime}ms`
          : '超时';
        this.showToast(`${result.status === 'up' ? '在线' : '离线'} - ${responseTimeText}`,
          result.status === 'up' ? 'success' : 'error');
      }

      await this.loadMonitors();
      await this.loadStats();
      // 异步加载状态条数据
      await this.loadStatusBars();

      // 如果详情弹窗是打开的，刷新详情数据
      if (this.currentDetailId === id) {
        await this.loadDetailData(id);
      }
    } catch (error) {
      if (!silent) {
        this.showToast('检测失败', 'error');
      }
    } finally {
      // 移除加载动画
      if (btn) {
        btn.classList.remove('loading');
        const btnSvg = btn.querySelector('svg');
        if (btnSvg) btnSvg.style.animation = '';
      }

      if (detailBtn) {
        detailBtn.classList.remove('loading');
        const detailSvg = detailBtn.querySelector('svg');
        if (detailSvg) detailSvg.style.animation = '';
        detailBtn.disabled = false;
      }
    }
  },

  async refreshAll() {
    if (!ui.runtime.guardWrite()) return;
    const btn = document.getElementById('btn-refresh');
    btn.classList.add('loading');

    try {
      const response = await fetch('/api/check-all', {method: 'POST'});
      if (response.status === 401) {
        auth.showLogin();
        return;
      }
      const results = await response.json();

      if (!response.ok) throw new Error(results.error || '批量检测失败');
      const checked = results.filter(result => !result.skipped);
      const skipped = results.length - checked.length;
      const upCount = checked.filter(r => r.status === 'up').length;
      this.showToast(`检测完成: ${upCount}/${checked.length} 在线${skipped ? `，维护跳过 ${skipped} 项` : ''}`, 'success');

      await this.loadMonitors();
      await this.loadStats();
      // 异步加载状态条数据
      await this.loadStatusBars();
    } catch (error) {
      this.showToast('批量检测失败', 'error');
    } finally {
      btn.classList.remove('loading');
    }
  },

  // ============ 详情弹窗 ============
  async showDetail(id) {
    if (!this.monitors.some(monitor => monitor.id === id)) return;
    this.resetDetailData();
    this.currentDetailId = id;
    this.currentTimeRange = '24h';
    this.updateDetailInfo({refreshHistory: false});

    // 在弹窗入场前准备等高占位，避免显示上一个监控的数据。
    this.renderDetailStats(null);
    byId('detail-history-body').innerHTML = Array.from({length: 6}, () =>
      '<tr class="history-skeleton" aria-hidden="true"><td colspan="5"><span></span></td></tr>'
    ).join('');
    this.setDetailChartPlaceholder('正在加载趋势…', true);
    this.setDetailLoading(true);
    byId('detail-modal').classList.add('active');
    byId('detail-content').scrollTop = 0;
    document.querySelector('.detail-history-container').scrollTop = 0;
    await this.loadDetailData(id);
  },

  resetDetailData() {
    this.detailRequestController?.abort();
    this.detailRequestController = null;
    this.detailLoaded = false;
    this.detailDisplayedRange = null;
    this.detailFailedRange = null;
    this.detailHistorySignature = null;
    this.detailHistory = [];
    canvas('detail-chart').getAnimations().forEach(animation => animation.cancel());
    if (this.detailChart) {
      this.detailChart.destroy();
      this.detailChart = null;
    }
  },

  detailRangeLabel(range) {
    return {'1h': '1 小时', '6h': '6 小时', '12h': '12 小时', '24h': '24 小时', '7d': '7 天', '30d': '30 天'}[range] || range;
  },

  setDetailChartPlaceholder(message, loading = false, overChart = false) {
    const placeholder = byId('detail-chart-placeholder');
    placeholder.hidden = !message;
    placeholder.classList.toggle('is-loading', loading);
    placeholder.classList.toggle('over-chart', overChart);
    byId('detail-chart-placeholder-text').textContent = message;
  },

  setDetailLoading(loading) {
    byId('detail-content').classList.toggle('is-detail-loading', loading && !this.detailLoaded);
    byId('detail-range-feedback').classList.toggle('is-loading', loading);
    document.querySelectorAll('.detail-chart-section, .detail-history-section').forEach(section => {
      section.setAttribute('aria-busy', String(loading));
    });
    document.querySelectorAll('.time-tab').forEach(tab => {
      const active = tab.getAttribute('data-range') === this.currentTimeRange;
      tab.classList.toggle('active', active);
      tab.classList.toggle('is-pending', active && loading);
      tab.setAttribute('aria-pressed', String(active));
    });
  },

  retryDetailData() {
    if (!this.currentDetailId) return;
    this.currentTimeRange = this.detailFailedRange || this.currentTimeRange;
    this.loadDetailData(this.currentDetailId);
  },

  async loadDetailData(id, {background = false} = {}) {
    if (this.currentDetailId !== id || !byId('detail-modal').classList.contains('active')) return;
    // 自动刷新不打断用户正在切换的范围；手动操作以最后一次请求为准。
    if (background && this.detailRequestController) return;
    this.detailRequestController?.abort();
    const controller = new AbortController();
    this.detailRequestController = controller;
    const range = this.currentTimeRange;
    const isCurrent = () => !controller.signal.aborted && this.detailRequestController === controller && this.currentDetailId === id;
    const rangeLabel = this.detailRangeLabel(range);
    const previousRange = this.detailDisplayedRange;
    const feedback = byId('detail-range-feedback');
    const message = byId('detail-range-message');
    this.detailFailedRange = null;
    feedback.classList.remove('is-error');
    byId('detail-retry-btn').hidden = true;
    message.textContent = previousRange && previousRange !== range
      ? `正在加载 ${rangeLabel}，当前显示 ${this.detailRangeLabel(previousRange)}`
      : `正在${this.detailLoaded ? '更新' : '加载'}最近 ${rangeLabel}的数据…`;
    message.removeAttribute('title');
    this.setDetailLoading(true);
    if (!this.detailLoaded) this.setDetailChartPlaceholder('正在加载趋势…', true);

    try {
      const response = await fetch(`/api/monitors/${id}/history?range=${range}`, {
        credentials: 'same-origin', signal: controller.signal
      });
      if (!isCurrent()) return;
      if (response.status === 401) {
        auth.showLogin();
        return;
      }
      const data = await response.json();
      if (!isCurrent()) return;
      if (!response.ok) throw new Error(data.error || '请求失败');

      const chartData = data.chartData || [];
      const history = data.history || [];
      const stats = data.stats || {};
      const hasRecords = Number(stats.total) > 0 || history.length > 0 || chartData.some(point => Number(point.count) > 0);
      const hasMaintenance = chartData.some(point => point.in_maintenance);
      const hasResponses = chartData.some(point => point.response_time != null);
      const hasOffline = chartData.some(point => point.status === 'down');
      this.renderDetailChart(chartData, {range, animate: this.detailLoaded && previousRange !== range});
      this.renderDetailStats(hasRecords ? stats : null, hasResponses);
      this.renderDetailHistory(history, {resetScroll: previousRange !== range});
      this.detailDisplayedRange = range;
      this.detailLoaded = true;
      this.setDetailChartPlaceholder(hasResponses ? '' : hasRecords
        ? hasOffline ? '已记录离线检测，未获得有效响应时间' : '已完成检测，未获得有效响应时间'
        : hasMaintenance ? '此时间范围包含维护区间，暂无检测样本' : '此时间范围内暂无检测记录', false, hasRecords || hasMaintenance);
      message.textContent = `最近 ${rangeLabel}的响应趋势与检测记录`;
      canvas('detail-chart').setAttribute('aria-label', `最近 ${rangeLabel}的响应时间与检测状态${hasMaintenance ? '，包含维护区间' : ''}${hasOffline ? '，包含离线检测' : ''}${hasRecords && !hasResponses ? '，未获得有效响应时间' : ''}`);
    } catch (error) {
      if (!isCurrent()) return;
      this.detailFailedRange = range;
      // 失败时保留已展示的数据，并恢复对应选中项，避免把旧图误读为新范围。
      if (this.detailLoaded) this.currentTimeRange = this.detailDisplayedRange;
      else {
        this.setDetailChartPlaceholder('数据加载失败，请重试');
        this.renderDetailHistory([], {message: '暂时无法读取检测记录'});
      }
      message.textContent = this.detailLoaded
        ? `${rangeLabel}加载失败，保留 ${this.detailRangeLabel(this.detailDisplayedRange)}的结果`
        : '详情数据加载失败，请重新加载';
      message.title = error.message || '网络连接失败';
      feedback.classList.add('is-error');
      byId('detail-retry-btn').hidden = false;
    } finally {
      if (this.detailRequestController === controller) {
        this.detailRequestController = null;
        this.setDetailLoading(false);
      }
    }
  },


  renderDetailChart(history, {range = this.currentTimeRange, animate = false} = {}) {
    this.detailHistory = history || [];
    const chartCanvas = canvas('detail-chart');
    const ctx = chartCanvas.getContext('2d');
    if (!ctx) return;
    chartCanvas.getAnimations().forEach(animation => animation.cancel());

    // 后端已经聚合好数据，直接使用（按时间正序）
    const data = this.detailHistory;
    const hasResponses = data.some(point => point.response_time != null);
    const hasRecord = point => point.in_maintenance || Number(point.count) > 0 || point.response_time != null || point.status != null;

    // 获取主题相关的颜色(与 style.css 设计令牌对齐)
    const styles = getComputedStyle(document.documentElement);
    const color = name => styles.getPropertyValue(name).trim();
    const colors = {
      grid: color('--border-subtle'), text: color('--text-secondary'),
      tooltipBg: color('--bg-elevated'), tooltipTitle: color('--text-primary'),
      tooltipBody: color('--text-secondary'), tooltipBorder: color('--border')
    };
    const pointColors = data.map(h => color(h.status === 'down' ? '--status-down'
      : h.status === 'warning' ? '--status-warning' : '--accent'));
    const statusBackgrounds = data.map(point => !hasRecord(point) ? color('--chart-empty-fill')
      : point.in_maintenance ? color('--chart-fill')
      : point.status === 'down' ? color('--chart-down-fill')
        : point.status === 'warning' ? color('--chart-warning-fill') : 'transparent');
    const statusBorders = data.map(point => !hasRecord(point) ? color('--border-strong')
      : point.in_maintenance ? color('--accent')
      : point.status === 'down' ? color('--status-down')
        : point.status === 'warning' ? color('--status-warning') : 'transparent');

    const config = {
      type: 'line',
      data: {
        labels: data.map(h => this.formatChartTime(h.checked_at, range)),
        datasets: [{
          label: '响应时间',
          order: 0,
          data: data.map(h => h.response_time !== null && h.response_time !== undefined ? h.response_time : null),
          borderColor: color('--accent'),
          backgroundColor: color('--chart-fill'),
          fill: true,
          cubicInterpolationMode: 'monotone',
          // 稀疏曲线展示真实采样点；单次有效响应也不能因两侧无数据而不可见。
          pointRadius: data.map((point, index) => point.response_time != null &&
            (data.length <= 36 || (data[index - 1]?.response_time == null &&
              data[index + 1]?.response_time == null)) ? 3 : 0),
          pointHoverRadius: 5,
          borderWidth: 2,
          spanGaps: false,
          pointBackgroundColor: pointColors,
          pointBorderColor: pointColors,
        }, {
          // 状态使用独立隐藏轴铺满对应时间段，不能把无响应的离线记录伪装成 0 ms。
          type: 'bar',
          label: '检测状态',
          order: 1,
          yAxisID: 'status',
          data: data.map(() => 1),
          backgroundColor: statusBackgrounds,
          borderColor: statusBorders,
          borderWidth: {bottom: 3, top: 0, left: 0, right: 0},
          borderSkipped: false,
          categoryPercentage: 1,
          barPercentage: 1,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        // 不同跨度的采样点无法逐点对应；几何动画会让新增点从零基线拉起。
        animation: false,
        interaction: {
          intersect: false,
          mode: 'index'
        },
        plugins: {
          legend: {display: false},
          tooltip: {
            backgroundColor: colors.tooltipBg,
            titleColor: colors.tooltipTitle,
            bodyColor: colors.tooltipBody,
            borderColor: colors.tooltipBorder,
            borderWidth: 1,
            padding: 10,
            displayColors: false,
            // 每个时间段只生成一份提示，离线及无记录的时段也可悬浮查看。
            filter: item => item.datasetIndex === 1,
            callbacks: {
              title: items => items.length ? this.formatFullTime(data[items[0].dataIndex]?.checked_at) : '',
              label: (context) => {
                const dataIndex = context.dataIndex;
                const dataPoint = data[dataIndex];
                if (!dataPoint || !hasRecord(dataPoint)) return '无检测记录';
                const status = dataPoint.status;
                const statusLabel = status === 'down' ? '包含离线' : status === 'warning' ? '存在波动'
                  : status === 'up' ? '在线' : '状态未知';
                const lines = [`时段状态: ${statusLabel}${dataPoint.in_maintenance ? ' · 含维护时段' : ''}`,
                  dataPoint.response_time != null ? `平均: ${dataPoint.response_time} ms` : '未获得响应时间'];

                // 如果有最小和最大响应时间，显示它们
                if (dataPoint.min_response_time !== null && dataPoint.min_response_time !== undefined &&
                  dataPoint.max_response_time !== null && dataPoint.max_response_time !== undefined) {
                  lines.push(`最小: ${dataPoint.min_response_time} ms`);
                  lines.push(`最大: ${dataPoint.max_response_time} ms`);
                }

                if (dataPoint.excluded_count) lines.push(`排除统计: ${dataPoint.excluded_count} 次`);
                // 显示聚合数量（检测次数）
                if (dataPoint.count !== null && dataPoint.count !== undefined) {
                  lines.push(`检测次数: ${dataPoint.count}`);
                }

                return lines;
              }
            }
          }
        },
        scales: {
          x: {
            offset: false,
            grid: {display: false},
            ticks: {color: colors.text, maxRotation: 0, autoSkip: true, autoSkipPadding: 24, maxTicksLimit: 8}
          },
          y: {
            display: hasResponses,
            grid: {color: colors.grid},
            ticks: {color: colors.text},
            beginAtZero: true
          },
          status: {
            display: false,
            min: 0,
            max: 1,
            grid: {display: false}
          }
        }
      }
    };
    if (this.detailChart) {
      // 一次提交坐标轴与曲线，再用透明度过渡，避免曲线伸缩和新增点弹跳。
      this.detailChart.stop();
      this.detailChart.setActiveElements([]);
      this.detailChart.tooltip?.setActiveElements([], {x: 0, y: 0});
      this.detailChart.data.labels = config.data.labels;
      config.data.datasets.forEach((dataset, index) => {
        Object.assign(this.detailChart.data.datasets[index], dataset);
      });
      this.detailChart.options = config.options;
      this.detailChart.update('none');
      if (animate && !ui.motion.matches) {
        chartCanvas.animate([{opacity: 0.65}, {opacity: 1}], {duration: 160, easing: 'ease-out'});
      }
    } else {
      this.detailChart = createChart(ctx, config);
    }
  },

  renderDetailStats(stats, hasResponses = true) {
    const response = value => hasResponses && value != null ? `${value} ms` : '—';
    byId('detail-stat-avg').textContent = response(stats?.avgResponse);
    byId('detail-stat-min').textContent = response(stats?.minResponse);
    byId('detail-stat-max').textContent = response(stats?.maxResponse);
    byId('detail-stat-p99').textContent = ui.formatResponseTime(stats?.p99Response);
    const range = this.detailRangeLabel(this.currentTimeRange);
    byId('detail-label-avg').title = ui.responseStatDescription('avg', range);
    byId('detail-label-p99').title = ui.responseStatDescription('p99', range);
    byId('detail-stat-uptime').textContent = stats?.uptime != null ? `${stats.uptime}%` : '—';
  },

  renderDetailHistory(history, {resetScroll = false, message = '此时间范围内暂无检测记录'} = {}) {
    const tbody = document.getElementById('detail-history-body');
    const historyContainer = document.querySelector('.detail-history-container');
    const scrollTop = resetScroll ? 0 : historyContainer.scrollTop;
    const signature = JSON.stringify([history, message]);
    if (signature === this.detailHistorySignature) {
      historyContainer.scrollTop = scrollTop;
      return;
    }

    // 显示所有返回的历史记录（不再限制100条）
    tbody.innerHTML = history.map(h => `
      <tr>
        <td>${this.formatFullTime(h.checked_at)}</td>
        <td>${(() => {
      const status = h.status;
      if (status === 'up') {
        return `<span class="history-status up">${icons.up} 在线</span>`;
      }
      if (status === 'warning') {
        return `<span class="history-status warning">${icons.warning} 警告</span>`;
      }
      if (status === 'down') {
        return `<span class="history-status down">${icons.down} 离线</span>`;
      }
      return `<span class="history-status unknown">${icons.unknown} 未知</span>`;
    })()}${h.in_maintenance ? '<span class="content-badge">维护' + (h.stats_excluded ? ' · 不计统计' : '') + '</span>' : ''}</td>
        <td>${h.response_time !== null && h.response_time !== undefined ? h.response_time + ' ms' : '-'}</td>
        <td class="history-cell-message" title="${this.escapeHtml(h.message || '-').replace(/"/g, '&quot;')}">${this.escapeHtml(h.message || '-')}</td>
        <td>
          <button type="button" class="btn-icon-small danger" data-ui-write data-action="deleteHistoryRecord" data-monitor-id="${this.currentDetailId}" data-history-id="${h.id}" title="删除">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
              <polyline points="3 6 5 6 21 6"/>
              <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
            </svg>
          </button>
        </td>
      </tr>
    `).join('') || `<tr><td colspan="5" class="history-message">${this.escapeHtml(message)}</td></tr>`;

    this.detailHistorySignature = signature;
    historyContainer.scrollTop = scrollTop;
  },

  closeDetailModal() {
    document.getElementById('detail-modal').classList.remove('active');
    this.currentDetailId = null;
    this.resetDetailData();
  },

  async clearHistory(id) {
    if (!ui.runtime.guardWrite()) return;
    if (!await ui.confirm('确定要清空此监控的所有历史记录吗？此操作不可恢复。')) {
      return;
    }

    try {
      const response = await fetch(`/api/monitors/${id}/history`, {
        method: 'DELETE',
        credentials: 'same-origin'
      });

      if (response.status === 401) {
        auth.showLogin();
        return;
      }

      if (!response.ok) {
        this.showToast('清空失败', 'error');
        return;
      }

      this.showToast('历史记录已清空', 'success');

      // 重新加载数据
      if (this.currentDetailId === id) {
        await this.loadDetailData(id);
      }
    } catch (error) {
      console.error('清空历史失败:', error);
      this.showToast('清空历史记录失败', 'error');
    }
  },

  async deleteHistoryRecord(monitorId, historyId) {
    if (!ui.runtime.guardWrite()) return;
    if (!await ui.confirm('确定要删除这条历史记录吗？')) {
      return;
    }

    try {
      const response = await fetch(`/api/monitors/${monitorId}/history/${historyId}`, {
        method: 'DELETE',
        credentials: 'same-origin'
      });

      if (response.status === 401) {
        auth.showLogin();
        return;
      }

      if (!response.ok) {
        this.showToast('删除失败', 'error');
        return;
      }

      this.showToast('历史记录已删除', 'success');

      // 重新加载数据
      if (this.currentDetailId === monitorId) {
        await this.loadDetailData(monitorId);
      }
    } catch (error) {
      console.error('删除历史记录失败:', error);
      this.showToast('删除历史记录失败', 'error');
    }
  },

  formatChartTime(dateStr, range = this.currentTimeRange) {
    if (!dateStr) return '';
    const date = new Date(dateStr);

    if (isNaN(date.getTime())) return '';
    if (['1h', '6h', '12h', '24h'].includes(range)) {
      return new Intl.DateTimeFormat('zh-CN', {hour: '2-digit', minute: '2-digit', hour12: false}).format(date);
    }
    // 跨日范围保留日期，完整时间始终可在图表提示中查看。
    return new Intl.DateTimeFormat('zh-CN', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    }).format(date);
  },

  formatFullTime(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return '-';
    return new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    }).format(date);
  },

  /** 查看历史。由监控卡片上的 data-action="showHistory" 按钮通过事件委托调用，内部重定向到详情弹窗，勿删。 */
  // eslint-disable-next-line no-unused-vars -- 通过 this[action](id) 动态调用
  async showHistory(id) {
    // 重定向到详情弹窗
    await this.showDetail(id);
  },

  startAutoRefresh() {
    clearInterval(this.refreshInterval);
    this.refreshInterval = setInterval(async () => {
      if (!auth.user || this.autoRefreshing) return;
      this.autoRefreshing = true;
      try {
        await this.loadMonitors();
        await this.loadStats();
        // 异步加载状态条数据；详情已在 loadMonitors 中刷新。
        await this.loadStatusBars();
        if (typeof communications !== 'undefined') await communications.load(this.currentView);
        if (!document.hidden && Date.now() - versions.loadedAt >= 6 * 60 * 60 * 1000) versions.load({quiet: true});
      } finally {
        this.autoRefreshing = false;
      }
    }, 30000);
  },

  showToast(message, type = 'success', allowHtml = false) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icon = type === 'success'
      ? '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
      : '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';

    // 如果消息包含 SVG（图标），则允许 HTML，否则转义
    const messageContent = allowHtml || message.includes('<svg')
      ? message
      : this.escapeHtml(message);

    toast.innerHTML = `${icon}<span>${messageContent}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => toast.remove(), 200);
    }, 3000);
  },

  escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  },

  // ============ 设置管理 ============
  resetSettings() {
    this.settingsLoadController?.abort();
    this.settingsLoadController = null;
    this.hasLoadedSettings = false;
    form('settings-form').reset();
    form('settings-form').hidden = true;
    form('settings-form').inert = true;
    form('settings-form').removeAttribute('aria-busy');
    input('smtp-password').placeholder = 'SMTP 登录密码';
    input('feishu-secret').placeholder = '机器人安全设置中的签名密钥';
    byId('delete-all-history-btn').disabled = true;
    this.switchSettingsSection('general');
  },

  async loadSettings() {
    // 工作区切换复用已加载的表单，避免请求覆盖未保存的输入。
    if (this.hasLoadedSettings || this.settingsLoadController) return;
    const controller = new AbortController();
    this.settingsLoadController = controller;
    const settingsForm = form('settings-form');
    const loadState = byId('settings-load-state');
    settingsForm.hidden = true;
    settingsForm.inert = true;
    settingsForm.setAttribute('aria-busy', 'true');
    loadState.hidden = false;
    loadState.classList.remove('is-error');
    byId('settings-load-message').textContent = '正在加载系统设置…';
    byId('settings-load-spinner').hidden = false;
    byId('settings-retry-btn').hidden = true;

    try {
      const response = await fetch('/api/settings', {credentials: 'same-origin', signal: controller.signal});

      if (response.status === 401) {
        auth.showLogin();
        return;
      }

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || '加载设置失败，请重试');
      }

      const settings = await response.json();
      if (controller.signal.aborted) return;
      input('public-page-title').value = settings.publicPageTitle || '服务状态监控';
      input('log-retention-days').value = String(settings.logRetentionDays || 30);
      input('admin-email-settings').value = settings.adminEmail || '';

      // 加载邮件配置（无论当前显示哪个面板，都先加载数据）
      input('smtp-host').value = settings.smtpHost || '';
      input('smtp-port').value = String(settings.smtpPort || '587');
      input('smtp-user').value = settings.smtpUser || '';
      // 不回填敏感密码
      input('smtp-password').value = '';
      input('smtp-password').placeholder = settings.smtpPasswordSet ? '已设置（留空不修改）' : 'SMTP 登录密码';
      input('smtp-from').value = settings.smtpFrom || '';
      input('smtp-secure').checked = settings.smtpSecure || false;

      // 加载 Webhook 配置（无论当前显示哪个面板，都先加载数据）
      input('webhook-url').value = settings.webhookUrl || '';
      input('webhook-method').value = settings.webhookMethod || 'POST';
      input('webhook-headers').value = settings.webhookHeaders || '';

      // 加载飞书配置（不回填签名密钥）
      input('feishu-webhook-url').value = settings.feishuWebhookUrl || '';
      input('feishu-secret').value = '';
      input('feishu-secret').placeholder = settings.feishuSecretSet ? '已设置（留空不修改）' : '机器人安全设置中的签名密钥';

      // 显示日志表大小
      const logTableSizeText = document.getElementById('log-table-size-text');
      if (logTableSizeText) {
        if (settings.logTableSize) {
          const sizeMB = settings.logTableSize.sizeMB || 0;
          const rows = settings.logTableSize.rows || 0;
          let sizeText = `总大小: ${sizeMB.toFixed(2)} MB`;
          if (rows > 0) {
            sizeText += ` | 记录数: ${rows.toLocaleString()} 条`;
          }
          logTableSizeText.textContent = sizeText;
        } else {
          logTableSizeText.textContent = '无法获取日志表信息';
        }
      }

      // 清空密码字段
      input('admin-password-settings').value = '';
      input('admin-password-confirm-settings').value = '';
      this.hasLoadedSettings = true;
      settingsForm.hidden = false;
      loadState.hidden = true;
    } catch (error) {
      if (controller.signal.aborted) return;
      console.error('加载设置失败:', error);
      loadState.classList.add('is-error');
      byId('settings-load-message').textContent = error.message || '加载设置失败，请重试';
      byId('settings-load-spinner').hidden = true;
      byId('settings-retry-btn').hidden = false;
    } finally {
      if (this.settingsLoadController === controller) {
        this.settingsLoadController = null;
        settingsForm.inert = !this.hasLoadedSettings;
        settingsForm.removeAttribute('aria-busy');
      }
    }
  },

  switchSettingsSection(section) {
    if (!['general', 'admin', 'email', 'webhook', 'feishu', 'about', 'danger'].includes(section)) return;
    this.currentSettingsSection = section;

    // 更新菜单项状态
    document.querySelectorAll('.settings-menu-item').forEach(item => {
      const active = item.getAttribute('data-section') === section;
      item.classList.toggle('active', active);
      if (active) item.setAttribute('aria-current', 'true');
      else item.removeAttribute('aria-current');
    });

    // 显示对应的内容区域
    document.querySelectorAll('.settings-section').forEach(sec => {
      if (sec instanceof HTMLElement) {
        sec.hidden = sec.id !== `settings-section-${section}`;
      }
    });

    // 打开设置时已统一加载各面板，切换时保留未保存的输入。

    // “清空配置”按钮（放在保存旁边），仅通知配置显示
    const clearBtn = document.getElementById('settings-clear-btn');
    if (clearBtn) {
      if (section === 'email') {
        clearBtn.style.display = 'inline-flex';
        clearBtn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="margin-right: 6px; vertical-align: middle;">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
          </svg>
          清空邮件配置
        `;
        clearBtn.title = '清空并删除已保存的邮件配置';
      } else if (section === 'webhook') {
        clearBtn.style.display = 'inline-flex';
        clearBtn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="margin-right: 6px; vertical-align: middle;">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
          </svg>
          清空 Webhook 配置
        `;
        clearBtn.title = '清空并删除已保存的 Webhook 配置';
      } else if (section === 'feishu') {
        clearBtn.style.display = 'inline-flex';
        clearBtn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="margin-right: 6px; vertical-align: middle;">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
          </svg>
          清空飞书配置
        `;
        clearBtn.title = '清空并删除已保存的飞书配置';
      } else {
        clearBtn.style.display = 'none';
      }
    }

    // 危险操作与版本信息不需要保存按钮/底部操作区
    const footer = document.getElementById('settings-page-footer');
    if (footer) {
      footer.style.display = section === 'danger' || section === 'about' ? 'none' : 'flex';
    }
    if (this.currentView === 'settings') {
      byId('workspace-footer-note').textContent = section === 'about'
        ? '版本信息来自当前实例与 GitHub 索引'
        : '更改设置后，点击保存使其生效';
    }
    if (section === 'about') versions.render();
  },

  async testEmail() {
    if (!ui.runtime.guardWrite()) return;
    const btn = document.getElementById('test-email-btn');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span>发送中...</span>';

    // 从页面获取邮件配置
    const smtpHost = input('smtp-host').value.trim();
    const smtpPort = input('smtp-port').value.trim();
    const smtpUser = input('smtp-user').value.trim();
    const smtpPassword = input('smtp-password').value;
    const smtpFrom = input('smtp-from').value.trim();
    const smtpSecure = input('smtp-secure').checked;

    // 验证必填项
    if (!smtpHost || !smtpUser || !smtpPassword || !smtpFrom) {
      this.showToast('请先填写完整的邮件配置信息', 'error');
      btn.disabled = false;
      btn.innerHTML = originalText;
      return;
    }

    // 获取管理员邮箱
    const adminSection = document.getElementById('settings-section-admin');
    const adminEmailInput = adminSection ? asInput(adminSection.querySelector('#admin-email-settings')) : null;
    const adminEmail = adminEmailInput ? adminEmailInput.value.trim() : null;

    if (!adminEmail) {
      this.showToast('请先设置管理员邮箱', 'error');
      btn.disabled = false;
      btn.innerHTML = originalText;
      return;
    }

    try {
      const response = await fetch('/api/settings/test-email', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'same-origin',
        body: JSON.stringify({
          smtpHost,
          smtpPort: smtpPort || '587',
          smtpUser,
          smtpPassword,
          smtpFrom,
          smtpSecure,
          toEmail: adminEmail
        })
      });

      const data = await response.json();

      if (response.ok) {
        this.showToast(data.message || '测试邮件发送成功', 'success');
      } else {
        this.showToast(data.error || '测试邮件发送失败', 'error');
      }
    } catch (error) {
      this.showToast('测试邮件发送失败: ' + error.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = originalText;
    }
  },

  async testWebhook() {
    if (!ui.runtime.guardWrite()) return;
    const btn = document.getElementById('test-webhook-btn');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span>发送中...</span>';

    // 从页面获取 Webhook 配置
    const webhookUrl = input('webhook-url').value.trim();
    const webhookMethod = input('webhook-method').value;
    const webhookHeaders = input('webhook-headers').value.trim();

    // 验证必填项
    if (!webhookUrl) {
      this.showToast('请先填写 Webhook URL', 'error');
      btn.disabled = false;
      btn.innerHTML = originalText;
      return;
    }

    try {
      const response = await fetch('/api/settings/test-webhook', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'same-origin',
        body: JSON.stringify({
          webhookUrl,
          webhookMethod,
          webhookHeaders
        })
      });

      const data = await response.json();

      if (response.ok) {
        this.showToast(data.message || 'Webhook 测试成功', 'success');
      } else {
        this.showToast(data.error || 'Webhook 测试失败', 'error');
      }
    } catch (error) {
      this.showToast('Webhook 测试失败: ' + error.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = originalText;
    }
  },

  async testFeishu() {
    if (!ui.runtime.guardWrite()) return;
    const btn = document.getElementById('test-feishu-btn');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span>发送中...</span>';

    const feishuWebhookUrl = input('feishu-webhook-url').value.trim();
    const feishuSecret = input('feishu-secret').value;

    if (!feishuWebhookUrl) {
      this.showToast('请先填写飞书 Webhook URL', 'error');
      btn.disabled = false;
      btn.innerHTML = originalText;
      return;
    }

    try {
      const requestBody = {
        feishuWebhookUrl
      };
      if (feishuSecret) {
        requestBody.feishuSecret = feishuSecret;
      }

      const response = await fetch('/api/settings/test-feishu', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'same-origin',
        body: JSON.stringify(requestBody)
      });

      const data = await response.json();

      if (response.ok) {
        this.showToast(data.message || '飞书测试成功', 'success');
      } else {
        this.showToast(data.error || '飞书测试失败', 'error');
      }
    } catch (error) {
      this.showToast('飞书测试失败: ' + error.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = originalText;
    }
  },

  async clearCurrentSettingsConfig() {
    if (!ui.runtime.guardWrite()) return;
    if (this.currentSettingsSection === 'email') {
      return this.clearEmailConfig('settings-clear-btn');
    }
    if (this.currentSettingsSection === 'webhook') {
      return this.clearWebhookConfig('settings-clear-btn');
    }
    if (this.currentSettingsSection === 'feishu') {
      return this.clearFeishuConfig('settings-clear-btn');
    }
  },

  async clearEmailConfig(buttonId = 'clear-email-btn') {
    if (!ui.runtime.guardWrite()) return;
    if (!await ui.confirm('确定要清空邮件配置吗？这将删除已保存的 SMTP 配置（包含密码），用于停用邮件通知。')) {
      return;
    }

    const btn = document.getElementById(buttonId);
    const originalText = btn ? btn.innerHTML : null;
    if (btn) {
      btn.disabled = true;
      btn.classList.add('loading');
      btn.innerHTML = '<span>清空中...</span>';
    }

    try {
      const response = await fetch('/api/settings', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        credentials: 'same-origin',
        body: JSON.stringify({
          smtpHost: '',
          smtpPort: '587',
          smtpUser: '',
          smtpPassword: '',
          smtpFrom: '',
          smtpSecure: false
        })
      });

      if (response.status === 401) {
        auth.showLogin();
        return;
      }

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        this.showToast(data.error || '清空邮件配置失败', 'error');
        return;
      }

      const settings = await response.json().catch(() => ({}));

      input('smtp-host').value = settings.smtpHost || '';
      input('smtp-port').value = settings.smtpPort || '587';
      input('smtp-user').value = settings.smtpUser || '';
      input('smtp-from').value = settings.smtpFrom || '';
      input('smtp-secure').checked = settings.smtpSecure || false;
      const smtpPwdInput = document.getElementById('smtp-password');
      if (smtpPwdInput) {
        smtpPwdInput.value = '';
        smtpPwdInput.placeholder = settings.smtpPasswordSet ? '已设置（留空不修改）' : '';
      }

      this.showToast('邮件配置已清空', 'success');
    } catch (error) {
      this.showToast(error.message || '清空邮件配置失败', 'error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove('loading');
        if (originalText !== null) btn.innerHTML = originalText;
      }
    }
  },

  async clearWebhookConfig(buttonId = 'clear-webhook-btn') {
    if (!ui.runtime.guardWrite()) return;
    if (!await ui.confirm('确定要清空 Webhook 配置吗？这将删除已保存的 Webhook 配置，用于停用 Webhook 通知。')) {
      return;
    }

    const btn = document.getElementById(buttonId);
    const originalText = btn ? btn.innerHTML : null;
    if (btn) {
      btn.disabled = true;
      btn.classList.add('loading');
      btn.innerHTML = '<span>清空中...</span>';
    }

    try {
      const response = await fetch('/api/settings', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        credentials: 'same-origin',
        body: JSON.stringify({
          webhookUrl: '',
          webhookMethod: 'POST',
          webhookHeaders: ''
        })
      });

      if (response.status === 401) {
        auth.showLogin();
        return;
      }

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        this.showToast(data.error || '清空 Webhook 配置失败', 'error');
        return;
      }

      const settings = await response.json().catch(() => ({}));
      input('webhook-url').value = settings.webhookUrl || '';
      input('webhook-method').value = settings.webhookMethod || 'POST';
      input('webhook-headers').value = settings.webhookHeaders || '';

      this.showToast('Webhook 配置已清空', 'success');
    } catch (error) {
      this.showToast(error.message || '清空 Webhook 配置失败', 'error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove('loading');
        if (originalText !== null) btn.innerHTML = originalText;
      }
    }
  },

  async clearFeishuConfig(buttonId = 'clear-feishu-btn') {
    if (!ui.runtime.guardWrite()) return;
    if (!await ui.confirm('确定要清空飞书配置吗？这将删除已保存的飞书 Webhook 和签名密钥，用于停用飞书通知。')) {
      return;
    }

    const btn = document.getElementById(buttonId);
    const originalText = btn ? btn.innerHTML : null;
    if (btn) {
      btn.disabled = true;
      btn.classList.add('loading');
      btn.innerHTML = '<span>清空中...</span>';
    }

    try {
      const response = await fetch('/api/settings', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        credentials: 'same-origin',
        body: JSON.stringify({
          feishuWebhookUrl: '',
          feishuSecret: ''
        })
      });

      if (response.status === 401) {
        auth.showLogin();
        return;
      }

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        this.showToast(data.error || '清空飞书配置失败', 'error');
        return;
      }

      const settings = await response.json().catch(() => ({}));
      input('feishu-webhook-url').value = settings.feishuWebhookUrl || '';
      const feishuSecretInput = document.getElementById('feishu-secret');
      if (feishuSecretInput) {
        feishuSecretInput.value = '';
        feishuSecretInput.placeholder = settings.feishuSecretSet ? '已设置（留空不修改）' : '机器人安全设置中的签名密钥';
      }

      this.showToast('飞书配置已清空', 'success');
    } catch (error) {
      this.showToast(error.message || '清空飞书配置失败', 'error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove('loading');
        if (originalText !== null) btn.innerHTML = originalText;
      }
    }
  },

  async saveSettings(e) {
    if (!ui.runtime.guardWrite(e)) return;
    e.preventDefault();
    if (!this.hasLoadedSettings) return;

    const publicPageTitle = input('public-page-title').value.trim() || '服务状态监控';
    const logRetentionDays = parseInt(input('log-retention-days').value, 10);

    if (isNaN(logRetentionDays) || logRetentionDays < 30) {
      this.showToast('日志保留天数必须至少为30天', 'error');
      return;
    }

    // 获取管理员邮箱（只在管理员账户面板中查找）
    const adminSection = document.getElementById('settings-section-admin');
    const adminEmailInput = adminSection ? asInput(adminSection.querySelector('#admin-email-settings')) : null;
    const adminEmail = adminEmailInput ? adminEmailInput.value.trim() || null : null;

    // 获取密码（如果填写了）
    const adminPassword = input('admin-password-settings').value;
    const adminPasswordConfirm = input('admin-password-confirm-settings').value;

    // 如果填写了密码，验证密码
    if (adminPassword) {
      if (adminPassword.length < 6) {
        this.showToast('密码长度至少6位', 'error');
        return;
      }

      if (adminPassword !== adminPasswordConfirm) {
        this.showToast('两次输入的密码不一致', 'error');
        return;
      }
    }

    // 获取邮件配置
    const smtpHost = input('smtp-host').value.trim();
    const smtpPort = input('smtp-port').value.trim();
    const smtpUser = input('smtp-user').value.trim();
    const smtpPassword = input('smtp-password').value;
    const smtpFrom = input('smtp-from').value.trim();
    const smtpSecure = input('smtp-secure').checked;

    // 获取 Webhook 配置
    const webhookUrl = input('webhook-url').value.trim();
    const webhookMethod = input('webhook-method').value;
    const webhookHeadersText = input('webhook-headers').value.trim();
    let webhookHeaders = {};
    if (webhookHeadersText) {
      try {
        webhookHeaders = JSON.parse(webhookHeadersText);
      } catch (e) {
        this.showToast('Webhook 请求头格式错误，必须是有效的 JSON', 'error');
        return;
      }
    }

    // 获取飞书配置
    const feishuWebhookUrl = input('feishu-webhook-url').value.trim();
    const feishuSecret = input('feishu-secret').value;

    try {
      const requestBody = {
        publicPageTitle,
        logRetentionDays,
        adminEmail: adminEmail || null,
        smtpHost,
        smtpPort,
        smtpUser,
        smtpFrom,
        smtpSecure,
        webhookUrl,
        webhookMethod,
        webhookHeaders: webhookHeadersText ? JSON.stringify(webhookHeaders) : '',
        feishuWebhookUrl
      };

      // SMTP 密码：只有用户输入了才更新（留空表示不修改）
      if (smtpPassword) {
        requestBody.smtpPassword = smtpPassword;
      }

      // 飞书签名密钥：只有用户输入了才更新（留空表示不修改）
      if (feishuSecret) {
        requestBody.feishuSecret = feishuSecret;
      }

      // 只有在填写了密码时才发送密码字段
      if (adminPassword) {
        requestBody.adminPassword = adminPassword;
        requestBody.adminPasswordConfirm = adminPasswordConfirm;
      }

      const response = await fetch('/api/settings', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        credentials: 'same-origin',
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        const data = await response.json();
        this.showToast(data.error || '保存失败', 'error');
        return;
      }

      // 如果更新了密码，清空密码字段
      if (adminPassword) {
        input('admin-password-settings').value = '';
        input('admin-password-confirm-settings').value = '';
      }

      // 更新显示
      const settings = await response.json();
      const adminSection = document.getElementById('settings-section-admin');
      if (adminSection) {
        const adminEmailInput = asInput(adminSection.querySelector('#admin-email-settings'));
        if (adminEmailInput) {
          adminEmailInput.value = settings.adminEmail || '';
        }
      }

      // 更新邮件配置显示
      input('smtp-host').value = settings.smtpHost || '';
      input('smtp-port').value = settings.smtpPort || '587';
      input('smtp-user').value = settings.smtpUser || '';
      // 不回填敏感密码，仅更新 placeholder
      const smtpPwdInput = document.getElementById('smtp-password');
      if (smtpPwdInput) {
        smtpPwdInput.value = '';
        smtpPwdInput.placeholder = settings.smtpPasswordSet ? '已设置（留空不修改）' : '';
      }
      input('smtp-from').value = settings.smtpFrom || '';
      input('smtp-secure').checked = settings.smtpSecure || false;

      // 更新 Webhook 配置显示
      input('webhook-url').value = settings.webhookUrl || '';
      input('webhook-method').value = settings.webhookMethod || 'POST';
      input('webhook-headers').value = settings.webhookHeaders || '';

      // 更新飞书配置显示
      input('feishu-webhook-url').value = settings.feishuWebhookUrl || '';
      const feishuSecretInput = document.getElementById('feishu-secret');
      if (feishuSecretInput) {
        feishuSecretInput.value = '';
        feishuSecretInput.placeholder = settings.feishuSecretSet ? '已设置（留空不修改）' : '机器人安全设置中的签名密钥';
      }

      // 保存成功后刷新页面以应用新设置
      this.showToast('设置已保存，页面即将刷新...', 'success');
      setTimeout(() => {
        location.reload();
      }, 1000);
    } catch (error) {
      this.showToast(error.message || '保存设置失败', 'error');
    }
  },

  async deleteAllHistory() {
    if (!ui.runtime.guardWrite()) return;
    const confirmInput = input('delete-all-history-confirm');
    const confirmValue = confirmInput.value.trim();

    if (confirmValue !== 'DELETE') {
      this.showToast('请输入 "DELETE" 以确认删除操作', 'warning');
      return;
    }

    if (!await ui.confirm('确定要删除所有检测历史吗？此操作无法撤销！')) {
      return;
    }

    const btn = document.getElementById('delete-all-history-btn');
    btn.disabled = true;
    btn.classList.add('loading');

    try {
      const response = await fetch('/api/history/all', {
        method: 'DELETE',
        credentials: 'same-origin'
      });

      if (response.status === 401) {
        auth.showLogin();
        return;
      }

      if (!response.ok) {
        const data = await response.json();
        this.showToast(data.error || '删除失败', 'error');
        return;
      }

      await response.json().catch(() => ({}));
      this.showToast('已成功清空所有历史记录，页面即将刷新...', 'success');

      // 刷新页面以更新所有数据（包括日志表大小）
      setTimeout(() => {
        location.reload();
      }, 1000);
    } catch (error) {
      this.showToast(error.message || '删除所有历史记录失败', 'error');
    } finally {
      btn.disabled = false;
      btn.classList.remove('loading');
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  // 使用 addEventListener 绑定表单提交，避免内联 onsubmit 使用已废弃的全局 event
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', (e) => {
      e.preventDefault();
      auth.login(e).then(_r => {
      });
    });
  }
  const monitorForm = document.getElementById('monitor-form');
  if (monitorForm) {
    monitorForm.addEventListener('submit', (e) => {
      e.preventDefault();
      app.saveMonitor(e).then(_r => {
      });
    });
  }
  const groupAddForm = document.getElementById('group-add-form');
  if (groupAddForm) {
    groupAddForm.addEventListener('submit', (e) => {
      e.preventDefault();
      app.addGroup(e).then(_r => {
      });
    });
  }
  const settingsForm = document.getElementById('settings-form');
  if (settingsForm) {
    settingsForm.addEventListener('submit', (e) => {
      e.preventDefault();
      app.saveSettings(e).then(_r => {
      });
    });
  }

  // 如果当前页面是 setup.html（独立页面），则不执行 setup.init
  // setup.html 有自己的初始化逻辑
  if (window.location.pathname !== '/setup') {
    setup.init().then(_r => {
    });
  }
});
