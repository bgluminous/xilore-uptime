// 共享工具函数

// 排序函数：英文字母在中文前面
function sortByName(a, b) {
  const nameA = (a || '').trim();
  const nameB = (b || '').trim();

  if (!nameA && !nameB) return 0;
  if (!nameA) return 1;
  if (!nameB) return -1;

  // 获取首字符
  const firstCharA = nameA.charAt(0);
  const firstCharB = nameB.charAt(0);

  // 判断首字符是否是英文字母（a-z, A-Z）
  const isEnglishA = /^[a-zA-Z]/.test(firstCharA);
  const isEnglishB = /^[a-zA-Z]/.test(firstCharB);

  // 如果一个是英文，一个是中文，英文排在前面
  if (isEnglishA && !isEnglishB) return -1;
  if (!isEnglishA && isEnglishB) return 1;

  // 如果都是英文或都是中文，使用 localeCompare 排序
  return nameA.localeCompare(nameB, 'zh-CN', {numeric: true});
}

// ============ 共享界面能力：主题、动效、状态与键盘导航 ============
const ui = {
  formatResponseTime(value) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? `${value} ms` : '—';
  },

  responseStatDescription(stat, range) {
    return `最近 ${range}内，${stat === 'avg' ? '全部有效响应时间的算术平均值，四舍五入到毫秒' : '至少 99% 的有效响应时间不超过此值'}；无响应、超时及标记排除的维护样本不参与统计。`;
  },

  renderResponseStats(monitor) {
    return [['avg', '平均延迟'], ['p99', 'P99']].map(([stat, label]) => `
      <div class="monitor-stat">
        <span class="monitor-stat-value">${this.formatResponseTime(monitor[`${stat}_response_24h`])}</span>
        <span class="monitor-stat-label" title="${this.responseStatDescription(stat, '24 小时')}">${label}</span>
      </div>`).join('');
  },

  hasCurrentProblem(monitors) {
    return monitors.some(monitor => monitor.enabled !== 0 && monitor.enabled !== false &&
      !monitor.maintenance?.active &&
      (monitor.status === 'down' || monitor.status === 'warning'));
  },

  describeProblems(monitors, groups = []) {
    const groupOrder = new Map(groups.map((group, index) => [String(group.id), index]));
    const orderOf = monitor => groupOrder.get(String(monitor.group_id)) ?? groups.length;
    const active = monitors.filter(monitor => monitor.enabled !== 0 && monitor.enabled !== false && !monitor.maintenance?.active)
      .sort((a, b) => orderOf(a) - orderOf(b) || sortByName(a.name || '', b.name || ''));
    return [['down', '离线'], ['warning', '波动']].flatMap(([status, label]) => {
      const affected = active.filter(monitor => monitor.status === status);
      if (!affected.length) return [];
      const names = affected.slice(0, 3).map(monitor => {
        const characters = Array.from(monitor.name || '未命名服务');
        return characters.length > 20 ? characters.slice(0, 19).join('') + '…' : characters.join('');
      });
      return [`${label} ${affected.length} 个：${names.join('、')}${affected.length > 3 ? `等 ${affected.length} 个` : ''}`];
    }).join('；');
  },

  groupHistory: {
    signatures: new WeakMap(),
    timeFormat: new Intl.DateTimeFormat('zh-CN', {
      month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    }),

    aggregate(monitors) {
      const active = monitors.filter(monitor => monitor.enabled !== 0 && monitor.enabled !== false);
      const histories = active.map(monitor => Array.isArray(monitor.statusBar24h) ? monitor.statusBar24h : []);
      // 同一次接口返回的时间格完全一致；不同批次的旧记录不能按下标错位合并。
      const template = histories.filter(hours => hours.length === 24 && hours.every(hour =>
        Number.isFinite(Date.parse(hour?.startTime)) && Number.isFinite(Date.parse(hour?.endTime)) &&
        Date.parse(hour.endTime) > Date.parse(hour.startTime)))
        .sort((a, b) => Date.parse(b[23].endTime) - Date.parse(a[23].endTime))[0];
      if (!template) return [];
      const byWindow = histories.map(hours => new Map(hours.map(hour => [
        `${hour?.startTime}/${hour?.endTime}`, hour
      ])));
      return template.map(hour => ({
        startTime: hour.startTime,
        endTime: hour.endTime,
        segments: Array.from({length: 12}, (_, index) => {
          const counts = {up: 0, down: 0, warning: 0, unknown: 0};
          for (const history of byWindow) {
            const status = history.get(`${hour.startTime}/${hour.endTime}`)?.segments?.[index];
            if (status === 'maintenance') counts.maintenance = (counts.maintenance || 0) + 1;
            else counts[status === 'up' || status === 'down' || status === 'warning' ? status : 'unknown']++;
          }
          return {...counts, status: counts.down ? 'down' : counts.warning ? 'warning' : counts.maintenance ? 'maintenance' : counts.up ? 'up' : null};
        })
      }));
    },

    render(monitors, state = 'loading') {
      const active = monitors.filter(monitor => monitor.enabled !== 0 && monitor.enabled !== false);
      const hours = this.aggregate(monitors);
      const label = '最近 24 小时分组状态，红色离线、黄色波动、紫色维护、绿色有正常记录、灰色无数据；已暂停服务不参与';
      const escape = value => String(value).replace(/[&<>"']/g, character =>
        ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[character]);
      if (!hours.length) {
        const loading = active.length > 0 && state === 'loading';
        const unavailable = active.length > 0 && state === 'error';
        const message = !active.length ? '无参与统计的服务' : loading ? '正在加载分组状态记录' :
          unavailable ? '状态记录暂不可用' : '无检测数据';
        const content = loading ? '<span class="status-bar-skeleton-full"></span>' : unavailable
          ? '<span class="group-status-message">状态记录暂不可用</span>'
          : '<span class="status-bar-group status-bar-segment-empty"></span>'.repeat(24);
        return `<span class="group-status-bar" role="img" aria-label="${label}；${message}" title="最近 24 小时；${message}">${content}</span>`;
      }
      const stale = state === 'error' ? '；更新失败，显示上次成功记录' : '';
      const content = hours.map(hour => {
        const start = Date.parse(hour.startTime);
        const duration = (Date.parse(hour.endTime) - start) / 12;
        const segments = hour.segments.map((segment, index) => {
          const range = `${this.timeFormat.format(start + duration * index)} ~ ${this.timeFormat.format(start + duration * (index + 1))}`;
          const detail = `离线 ${segment.down} 个 · 波动 ${segment.warning} 个 · 正常 ${segment.up} 个 · 无数据 ${segment.unknown} 个${segment.maintenance ? ` · 维护 ${segment.maintenance} 个` : ''}`;
          const tooltip = escape(`${range}\n${detail}${stale}`);
          return `<span class="status-bar-segment status-bar-segment-${segment.status || 'empty'}" title="${tooltip}"></span>`;
        }).join('');
        return `<span class="status-bar-group">${segments}</span>`;
      }).join('');
      return `<span class="group-status-bar" role="img" aria-label="${label}${stale}" title="最近 24 小时${stale}">${content}</span>`;
    },

    update(container, monitors, state) {
      if (!container) return;
      const byId = new Map(monitors.map(monitor => [String(monitor.id), monitor]));
      container.querySelectorAll('.group-section').forEach(section => {
        const bar = section.querySelector('.group-status-bar');
        if (!bar) return;
        // 折叠的服务仍在 DOM 中；取当前分组实际渲染的成员，与筛选后的数量一致。
        const members = [...section.querySelectorAll('.monitor-item[data-id]')]
          .map(item => byId.get(item.getAttribute('data-id'))).filter(Boolean);
        const html = this.render(members, state);
        if (this.signatures.get(bar) === html) return;
        bar.outerHTML = html;
        this.signatures.set(section.querySelector('.group-status-bar'), html);
      });
    }
  },

  confirm(message, {title = '确认操作', confirmText = '确认'} = {}) {
    if (this.pendingConfirmation) return Promise.resolve(false);
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay active';
    overlay.id = 'confirmation-modal';
    overlay.innerHTML = '<section class="modal confirmation-dialog" role="dialog" aria-modal="true" aria-labelledby="confirmation-title" aria-describedby="confirmation-message"><div class="modal-header"><h2 id="confirmation-title"></h2></div><div class="modal-body"><p id="confirmation-message"></p></div><div class="modal-footer"><button type="button" class="btn-secondary" data-confirm="cancel">取消</button><button type="button" class="btn-primary" data-confirm="accept">确认</button></div></section>';
    overlay.querySelector('#confirmation-title').textContent = title;
    overlay.querySelector('#confirmation-message').textContent = message;
    overlay.querySelector('[data-confirm="accept"]').textContent = confirmText;
    document.body.append(overlay);
    return new Promise(resolve => {
      const finish = accepted => {
        document.removeEventListener('keydown', onKey, true);
        overlay.classList.remove('active');
        this.syncDialogs();
        overlay.remove();
        this.pendingConfirmation = null;
        resolve(accepted);
      };
      const onKey = event => {
        if (event.key === 'Escape') {event.preventDefault(); event.stopImmediatePropagation(); finish(false);}
      };
      this.pendingConfirmation = () => finish(false);
      document.addEventListener('keydown', onKey, true);
      overlay.addEventListener('click', event => {
        if (!(event.target instanceof Element)) return;
        if (event.target === overlay || event.target.closest('[data-confirm="cancel"]')) finish(false);
        else if (event.target.closest('[data-confirm="accept"]')) finish(true);
      });
      this.syncDialogs();
    });
  },

  dialogOrder: [],
  dialogTriggers: new Map(),
  motion: window.matchMedia('(prefers-reduced-motion: reduce)'),

  // 服务端状态确认前保持只读；浏览器控件限制只负责体验，后端独立保护数据。
  runtime: {
    ready: false,
    uiDevMode: true,
    /** @type {Promise<{installed: boolean, initialized: boolean, uiDevMode: boolean} | null> | null} */
    request: null,
    /** @type {MutationObserver | null} */
    observer: null,
    /** @type {WeakMap<Element, {disabled: boolean, readOnly: boolean, title: string}>} */
    original: new WeakMap(),

    canWrite() {
      return this.ready && !this.uiDevMode;
    },

    guardWrite(event) {
      if (this.canWrite()) return true;
      if (event) event.preventDefault();
      return false;
    },

    load() {
      if (this.request) return this.request;
      this.request = (async () => {
        try {
          const response = await fetch('/api/install/status', {cache: 'no-store', credentials: 'same-origin'});
          if (!response.ok) throw new Error('无法确认运行模式');
          const status = await response.json();
          if (typeof status.uiDevMode !== 'boolean') throw new Error('运行模式响应无效');
          this.uiDevMode = status.uiDevMode;
          this.ready = true;
          return status;
        } catch (error) {
          console.error('无法确认运行模式，修改操作保持禁用:', error);
          return null;
        } finally {
          this.apply();
          if (this.canWrite() && this.observer) this.observer.disconnect();
        }
      })();
      return this.request;
    },

    apply() {
      const locked = !this.canWrite();
      document.documentElement.setAttribute('data-ui-readonly', String(locked));
      const selector = '[data-ui-write], [data-ui-write-form] input, [data-ui-write-form] select, ' +
        '[data-ui-write-form] textarea, [data-ui-write-form] button[type="submit"], [data-ui-write-form] button:not([type])';
      document.querySelectorAll(selector).forEach(element => {
        if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement ||
              element instanceof HTMLSelectElement || element instanceof HTMLButtonElement)) return;
        const field = element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement ? element : null;
        const textField = field && (field instanceof HTMLTextAreaElement ||
          ['text', 'email', 'number', 'password', 'search', 'url', 'tel'].includes(field.type));
        if (locked) {
          if (!this.original.has(element)) this.original.set(element, {
            disabled: element.disabled, readOnly: field ? field.readOnly : false, title: element.title
          });
          if (textField && !field.readOnly) field.readOnly = true;
          if (!textField && !element.disabled) element.disabled = true;
          const originalTitle = this.original.get(element).title;
          const title = (originalTitle ? originalTitle + ' · ' : '') + '只读模式：禁止修改';
          if (element.title !== title) element.title = title;
        } else {
          const previous = this.original.get(element);
          if (previous) {
            element.disabled = previous.disabled;
            if (field) field.readOnly = previous.readOnly;
            element.title = previous.title;
            this.original.delete(element);
          }
        }
      });
      document.querySelectorAll('[data-ui-pending]').forEach(element => {
        element.removeAttribute('inert');
        element.removeAttribute('data-ui-pending');
      });
      if (this.ready && this.uiDevMode) {
        document.querySelectorAll('#group-list [draggable="true"]').forEach(element => element.setAttribute('draggable', 'false'));
        document.querySelectorAll('[data-action="editMonitor"], [data-ui-view-config]').forEach(element => {
          if (element.getAttribute('title') !== '查看配置') element.setAttribute('title', '查看配置');
          element.setAttribute('aria-label', '查看配置');
        });
        document.querySelectorAll('[data-ui-edit-label]').forEach(element => {
          if (element.textContent !== '查看配置') element.textContent = '查看配置';
        });
      } else {
        document.querySelectorAll('[data-ui-edit-label]').forEach(element => {
          if (element.textContent !== '编辑') element.textContent = '编辑';
        });
      }
      const message = this.ready ? 'UI 开发模式 · 只读' : '模式未确认 · 修改已禁用';
      document.querySelectorAll('[data-ui-runtime-status]').forEach(element => {
        if (element.textContent !== message) element.textContent = message;
        element.hidden = !locked;
      });
    },

    init() {
      document.querySelectorAll('.auth-topbar, .header-right, .public-nav-actions, .setup-topbar').forEach(host => {
        const badge = document.createElement('span');
        badge.className = 'ui-dev-badge';
        badge.setAttribute('data-ui-runtime-status', '');
        badge.setAttribute('role', 'status');
        host.prepend(badge);
      });
      this.apply();
      // 动态卡片、异步表单加载以及旧逻辑重新启用按钮时，都重新应用只读属性。
      this.observer = new MutationObserver(() => this.apply());
      this.observer.observe(document.body, {subtree: true, childList: true, attributes: true, attributeFilter: ['disabled', 'readonly', 'draggable']});
      ['click', 'submit', 'beforeinput', 'dragstart', 'drop'].forEach(type => {
        document.addEventListener(type, event => {
          if (this.canWrite() || !(event.target instanceof Element)) return;
          const target = event.target;
          const blocked = target.closest('[data-ui-write]') ||
            ((type === 'submit' || type === 'beforeinput') && target.closest('[data-ui-write-form]')) ||
            ((type === 'dragstart' || type === 'drop') && target.closest('#group-list'));
          if (blocked) {
            event.preventDefault();
            event.stopImmediatePropagation();
          }
        }, true);
      });
      this.load();
    }
  },

  icon(name) {
    const paths = {
      activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
      grid: '<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>',
      folder: '<path d="M3 7V5a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/>',
      globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
      settings: '<path d="M4 7h16M4 17h16"/><circle cx="8" cy="7" r="3"/><circle cx="16" cy="17" r="3"/>',
      plus: '<path d="M12 5v14M5 12h14"/>',
      arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
      external: '<path d="M14 3h7v7m0-7L10 14M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5"/>',
      search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
      refresh: '<path d="M20 7v5h-5M4 17v-5h5M6.1 6.1A8 8 0 0 1 20 12M4 12a8 8 0 0 0 13.9 5.9"/>',
      clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
      check: '<path d="m5 12 4 4L19 6"/>',
      shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6Z"/><path d="m8 12 3 3 5-6"/>',
      alert: '<path d="m12 3 10 18H2Z"/><path d="M12 9v4m0 4h.01"/>',
      user: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-2a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v2"/>',
      logout: '<path d="M9 4H4v16h5m5-12 4 4-4 4m-6-4h10"/>',
      menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
      sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
      moon: '<path d="M21 13A9 9 0 0 1 11 3a9 9 0 1 0 10 10Z"/>',
      chevron: '<path d="m9 5 7 7-7 7"/>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.activity}</svg>`;
  },

  theme: {
    preference() {
      try { return localStorage.getItem('theme'); } catch (_error) { return null; }
    },
    init() {
      this.set(this.preference() || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (event) => {
        if (!this.preference()) this.set(event.matches ? 'dark' : 'light');
      });
    },
    set(mode) {
      document.documentElement.setAttribute('data-theme', mode === 'dark' ? 'dark' : 'light');
      document.querySelectorAll('.btn-theme').forEach(button => {
        button.setAttribute('aria-label', mode === 'dark' ? '切换浅色主题' : '切换深色主题');
        button.setAttribute('title', mode === 'dark' ? '切换浅色主题' : '切换深色主题');
      });
      document.dispatchEvent(new CustomEvent('themechange'));
    },
    toggle() {
      const mode = this.current === 'dark' ? 'light' : 'dark';
      this.set(mode);
      try { localStorage.setItem('theme', mode); } catch (_error) { /* 隐私模式仍可在当前页面切换。 */ }
    },
    get current() {
      return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    }
  },

  enter(container) {
    if (!container || this.motion.matches) return;
    container.querySelectorAll('.monitor-item, .empty-state').forEach((element, index) => {
      element.animate([
        {opacity: 0, transform: 'translateY(16px)'},
        {opacity: 1, transform: 'translateY(0)'}
      ], {duration: 420, delay: Math.min(index, 7) * 45, easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'backwards'});
    });
  },

  setValue(element, value) {
    if (!element || element.textContent === String(value)) return;
    element.textContent = String(value);
    if (!this.motion.matches) element.animate([{opacity: 0.35, transform: 'translateY(5px)'}, {opacity: 1, transform: 'translateY(0)'}], {duration: 320});
  },

  statusLabel(monitor) {
    if (monitor.enabled === 0 || monitor.enabled === false) return '已暂停';
    if (monitor.maintenance?.active) return '维护中';
    return {up: '运行正常', down: '服务离线', warning: '服务波动'}[monitor.status] || '等待检测';
  },

  updateHealth(monitors, {detailed = false, groups = []} = {}) {
    const banner = document.getElementById('health-banner');
    if (!banner) return;
    const active = monitors.filter(monitor => monitor.enabled !== 0 && monitor.enabled !== false);
    const maintained = active.filter(monitor => monitor.maintenance?.active).length;
    const outside = active.filter(monitor => !monitor.maintenance?.active);
    const down = outside.filter(monitor => monitor.status === 'down').length;
    const warning = outside.filter(monitor => monitor.status === 'warning').length;
    const unknown = outside.filter(monitor => !['up', 'down', 'warning'].includes(monitor.status)).length;
    let state = 'healthy';
    let title = '所有服务运行正常';
    let description = `${active.length} 个服务正在守护中，每一次检测都有迹可循。`;
    if (!monitors.length) {
      state = 'empty'; title = '准备好，迎接第一次心跳'; description = '暂无监控服务，服务状态将在这里汇总。';
    } else if (!active.length) {
      state = 'paused'; title = '所有服务已暂停检测'; description = '恢复检测后，这里将继续展示实时服务状态。';
    } else if (down) {
      state = 'down'; title = `${down} 个服务需要关注`; description = '检测到服务离线，请查看监控详情与最近的检测记录。';
    } else if (warning) {
      state = 'warning'; title = `${warning} 个服务出现波动`; description = '服务检测存在重试或异常，建议关注后续状态变化。';
    } else if (maintained) {
      state = 'maintenance'; title = `${maintained} 个服务正在维护`; description = '维护信息与实际检测结果分别保留，维护结束后将恢复常规展示。';
    } else if (unknown) {
      state = 'unknown'; title = `${unknown} 个服务等待检测`; description = '正在等待检测结果，尚未确定所有服务的运行状态。';
    }
    if (detailed && down + warning > 0) {
      title = `${down + warning} 个服务异常`;
      description = this.describeProblems(monitors, groups);
    }
    if (maintained && (down || warning)) description += `；另有 ${maintained} 个服务正在维护。`;
    banner.setAttribute('data-state', state);
    document.getElementById('health-title').textContent = title;
    document.getElementById('health-description').textContent = description;
    document.getElementById('health-symbol').innerHTML = this.icon(down || warning ? 'alert' : state === 'healthy' ? 'shield' : 'activity');
  },

  connection(ok) {
    const label = document.getElementById('last-sync');
    if (label) label.textContent = ok ? `更新于 ${new Intl.DateTimeFormat('zh-CN', {hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false}).format(new Date())}` : '更新失败，正在等待重试';
    document.querySelectorAll('.connection-status').forEach(element => {
      element.classList.toggle('disconnected', !ok);
      const text = element.querySelector('span:last-child');
      if (text) text.textContent = ok ? '自动更新已开启' : '连接暂时中断';
    });
  },

  toggleSidebar(force) {
    const wasOpen = document.body.classList.contains('sidebar-open');
    const open = typeof force === 'boolean' ? force : !document.body.classList.contains('sidebar-open');
    document.body.classList.toggle('sidebar-open', open);
    const button = document.getElementById('sidebar-toggle');
    if (button) button.setAttribute('aria-expanded', String(open));
    const workspace = document.querySelector('.app-workspace');
    if (workspace instanceof HTMLElement) workspace.inert = open;
    if (open) {
      const link = document.querySelector('.app-sidebar .nav-item');
      if (link instanceof HTMLElement) link.focus({preventScroll: true});
    } else if (wasOpen && button) button.focus({preventScroll: true});
  },

  focusableElements(root) {
    return Array.from(root.querySelectorAll('button, a[href], input:not([type="hidden"]), select, textarea, [tabindex="0"]'))
      .filter(element => element instanceof HTMLElement && !element.matches(':disabled') && !element.closest('[inert]') && element.getClientRects().length);
  },

  syncDialogs() {
    const overlays = Array.from(document.querySelectorAll('.modal-overlay'));
    let restore = null;
    this.dialogOrder = this.dialogOrder.filter(overlay => {
      if (overlay.classList.contains('active')) return true;
      restore = this.dialogTriggers.get(overlay) || restore;
      this.dialogTriggers.delete(overlay);
      return false;
    });
    let opened = false;
    overlays.forEach(overlay => {
      if (overlay.classList.contains('active') && !this.dialogOrder.includes(overlay)) {
        this.dialogTriggers.set(overlay, document.activeElement);
        this.dialogOrder.push(overlay);
        opened = true;
      }
    });
    const top = this.dialogOrder[this.dialogOrder.length - 1];
    overlays.forEach(overlay => {
      const active = overlay === top;
      overlay.setAttribute('aria-hidden', String(!active));
      overlay.inert = !active;
      overlay.style.zIndex = String(100 + Math.max(0, this.dialogOrder.indexOf(overlay)));
    });
    document.body.classList.toggle('modal-open', Boolean(top));
    document.querySelectorAll('#main-app, #login-page, #setup-wizard').forEach(element => { element.inert = Boolean(top); });
    if (opened && top) {
      const fields = this.focusableElements(top);
      const field = fields.find(element => element.matches('input, select, textarea')) || fields[0];
      if (field instanceof HTMLElement) field.focus({preventScroll: true});
    } else if (restore instanceof HTMLElement && restore.isConnected && !restore.closest('[inert]') && restore.getClientRects().length) {
      restore.focus({preventScroll: true});
    }
  },

  init() {
    this.runtime.init();
    document.querySelectorAll('[data-ui-icon]').forEach(element => { element.innerHTML = this.icon(element.getAttribute('data-ui-icon')); });
    this.theme.set(this.theme.current);
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
      const dialog = overlay.querySelector('.modal');
      const heading = dialog.querySelector('h2');
      if (heading && !heading.id) heading.id = `${overlay.id}-title`;
      dialog.setAttribute('role', 'dialog');
      dialog.setAttribute('aria-modal', 'true');
      if (heading) dialog.setAttribute('aria-labelledby', heading.id);
      dialog.setAttribute('tabindex', '-1');
      new MutationObserver(() => this.syncDialogs()).observe(overlay, {attributes: true, attributeFilter: ['class']});
    });
    this.syncDialogs();
    document.querySelectorAll('.btn-close').forEach(button => button.setAttribute('aria-label', '关闭对话框'));
    window.matchMedia('(max-width: 800px)').addEventListener('change', event => {
      if (!event.matches) this.toggleSidebar(false);
    });
    document.addEventListener('keydown', event => {
      const top = this.dialogOrder[this.dialogOrder.length - 1] || (document.body.classList.contains('sidebar-open') ? document.getElementById('app-sidebar') : null);
      if (event.key === 'Tab' && top) {
        const focusable = this.focusableElements(top);
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && (document.activeElement === first || !top.contains(document.activeElement))) {
          event.preventDefault(); if (last instanceof HTMLElement) last.focus();
        } else if (!event.shiftKey && (document.activeElement === last || !top.contains(document.activeElement))) {
          event.preventDefault(); if (first instanceof HTMLElement) first.focus();
        }
      }
      if (event.key === 'Escape') this.toggleSidebar(false);
    });
    document.querySelectorAll('.sidebar-nav button, .sidebar-nav a').forEach(button => button.addEventListener('click', () => this.toggleSidebar(false)));
  }
};

ui.theme.init();
document.addEventListener('DOMContentLoaded', () => ui.init());
