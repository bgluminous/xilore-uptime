// ============ 图标定义（与管理页保持一致）============
const publicIcons = {
  responseTime: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
  uptime: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M13 2L3 14h8l-1 8 10-12h-8l1-8z"/></svg>',
  lastCheck: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>'
};

// ============ 公开展示页应用对象 ============
const publicApp = {
  monitors: [],
  groups: [],
  hasLoadedData: false,
  hasRendered: false,
  collapsedGroups: new Set(),
  initializedGroups: new Set(),
  statusBarsState: 'loading',
  statusBarRequestId: 0,
  // 记录每个监控的状态条签名，避免无变化重绘导致闪烁
  statusBarSignatures: new Map(),

  async init() {
    this.initGroupControls();
    if (typeof communications !== 'undefined') communications.refreshPublic();
    await ui.runtime.load();
    // 标题由服务端在 / 路由渲染注入，这里只加载数据
    await this.loadBasicData();
    this.loadVersion();

    this.render();

    // 异步加载状态条数据（不阻塞首屏渲染）
    await this.loadStatusBars();

    // 每30秒自动刷新
    setInterval(() => {
      if (typeof communications !== 'undefined') communications.refreshPublic();
      this.loadBasicData().then(() => {
        this.render();
        this.loadStatusBars();
      });
    }, 30000);
  },

  initGroupControls() {
    document.getElementById('public-monitor-list').addEventListener('click', event => {
      if (!(event.target instanceof Element)) return;
      const button = event.target.closest('.group-header');
      const section = button?.closest('.group-section');
      if (!section) return;
      this.setGroupCollapsed(section, !section.classList.contains('collapsed'));
      this.updateGroupControls();
    });
    document.getElementById('public-expand-all').addEventListener('click', () => this.toggleAllGroups(false));
    document.getElementById('public-collapse-all').addEventListener('click', () => this.toggleAllGroups(true));
  },

  setGroupCollapsed(section, collapsed) {
    const id = section.getAttribute('data-group-id');
    if (collapsed) this.collapsedGroups.add(id);
    else this.collapsedGroups.delete(id);
    section.classList.toggle('collapsed', collapsed);
    const button = section.querySelector('.group-header');
    button.setAttribute('aria-expanded', String(!collapsed));
    button.setAttribute('title', collapsed ? '展开分组' : '折叠分组');
    section.querySelector('.public-collapse-label').textContent = collapsed ? '展开' : '收起';
    // 折叠动画期间也隐藏无障碍树和焦点，避免进入不可见内容。
    section.querySelector('.group-body').toggleAttribute('inert', collapsed);
  },

  toggleAllGroups(collapsed) {
    document.querySelectorAll('#public-monitor-list .group-section').forEach(section => this.setGroupCollapsed(section, collapsed));
    this.updateGroupControls();
  },

  isGroupCollapsed(groupId, monitors) {
    const id = String(groupId);
    if (!this.initializedGroups.has(id)) {
      this.initializedGroups.add(id);
      if (!ui.hasCurrentProblem(monitors)) this.collapsedGroups.add(id);
    }
    return this.collapsedGroups.has(id);
  },

  updateGroupControls() {
    const sections = [...document.querySelectorAll('#public-monitor-list .group-section')];
    const collapsedCount = sections.filter(section => section.classList.contains('collapsed')).length;
    document.getElementById('public-group-controls').hidden = sections.length === 0;
    document.getElementById('public-group-summary').textContent = sections.length ? `${sections.length} 个分组 · ${this.monitors.length} 个服务` : '';
    // 保留按钮焦点；无可执行变化时用 aria-disabled 描述当前状态。
    document.getElementById('public-expand-all').setAttribute('aria-disabled', String(collapsedCount === 0));
    document.getElementById('public-collapse-all').setAttribute('aria-disabled', String(collapsedCount === sections.length));
  },

  async loadBasicData() {
    try {
      const [groupsRes, monitorsRes, statsRes] = await Promise.all([
        fetch('/api/public/groups'),
        fetch('/api/public/monitors'),
        fetch('/api/public/stats')
      ]);
      if (!groupsRes.ok || !monitorsRes.ok || !statsRes.ok) throw new Error('暂时无法获取服务状态');

      if (groupsRes.ok) {
        this.groups = await groupsRes.json();
      }

      if (monitorsRes.ok) {
        const nextMonitors = await monitorsRes.json();
        // 保留已有的 statusBar24h，避免基础数据刷新时状态条先变骨架屏导致闪烁
        const prevStatusBars = new Map(this.monitors.map(m => [String(m.id), m.statusBar24h]));
        this.monitors = nextMonitors.map(m => ({
          ...m,
          statusBar24h: prevStatusBars.get(String(m.id)) || null
        }));
      }

      if (statsRes.ok) {
        const stats = await statsRes.json();
        ui.setValue(document.querySelector('.public-stat-card.up .public-stat-value'), stats.up || 0);
        ui.setValue(document.querySelector('.public-stat-card.down .public-stat-value'), stats.down || 0);

        // 计算平均24小时可用率（从监控数据中计算）
        const monitorsWithUptime = this.monitors.filter(m => {
          const hasUptime = m.uptime_24h !== null && m.uptime_24h !== undefined;
          const isPaused = m.enabled === 0 || m.enabled === false;
          // 暂停服务不计入平均可用率
          return hasUptime && !isPaused;
        });
        if (monitorsWithUptime.length > 0) {
          const avgUptime = monitorsWithUptime.reduce((sum, m) => sum + m.uptime_24h, 0) / monitorsWithUptime.length;
          ui.setValue(document.querySelector('.public-stat-card.uptime .public-stat-value'), avgUptime.toFixed(2) + '%');
        } else {
          ui.setValue(document.querySelector('.public-stat-card.uptime .public-stat-value'), '—');
        }
      }
      this.hasLoadedData = true;
      ui.updateHealth(this.monitors, {detailed: true, groups: this.groups});
      ui.connection(true);
    } catch (error) {
      console.error('加载基础数据失败:', error);
      ui.connection(false);
      if (!this.hasLoadedData) {
        document.getElementById('health-title').textContent = '暂时无法获取服务状态';
        document.getElementById('health-description').textContent = '请稍后重试，页面会自动尝试重新连接。';
      }
    }
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
          out += s ? s[0] : '_';
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
      const statusBarsRes = await fetch('/api/public/monitors/statusbars');
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
        ui.groupHistory.update(document.getElementById('public-monitor-list'), this.monitors, this.statusBarsState);
      }
    }
  },

  render() {
    const container = document.getElementById('public-monitor-list');
    const focusedGroup = document.activeElement?.closest('.group-header')?.closest('.group-section')?.getAttribute('data-group-id');

    if (!this.hasLoadedData) {
      container.innerHTML = `<div class="empty-state">${ui.icon('alert')}<h3>服务状态暂时不可用</h3><p>请检查网络连接，或稍后刷新页面。</p><button class="btn-secondary" onclick="location.reload()">重新加载</button></div>`;
      this.updateGroupControls();
      return;
    }

    if (this.monitors.length === 0) {
      container.innerHTML = `<div class="empty-state">${ui.icon('globe')}<h3>暂无公开的服务</h3><p>服务公开后，将在这里展示最新状态。</p></div>`;
      this.updateGroupControls();
      return;
    }

    // 按分组组织监控
    const grouped = {};
    const ungrouped = [];

    this.monitors.forEach(m => {
      if (m.group_id && this.groups.some(group => String(group.id) === String(m.group_id))) {
        if (!grouped[m.group_id]) grouped[m.group_id] = [];
        grouped[m.group_id].push(m);
      } else {
        ungrouped.push(m);
      }
    });

    let html = '';

    // 渲染分组
    this.groups.forEach(group => {
      const monitors = (grouped[group.id] || []).sort((a, b) => {
        // 按名称排序：英文字母在中文前面
        return sortByName(a.name || '', b.name || '');
      });
      if (monitors.length > 0) {
        html += this.renderGroupSection(group, monitors);
      }
    });

    // 渲染未分组
    if (ungrouped.length > 0) {
      const sortedUngrouped = ungrouped.sort((a, b) => {
        // 按名称排序：英文字母在中文前面
        return sortByName(a.name || '', b.name || '');
      });
      if (sortedUngrouped.length > 0) {
        html += this.renderGroupSection({id: 0, name: '未分组'}, sortedUngrouped);
      }
    }

    container.innerHTML = html;
    this.updateGroupControls();
    // 定时刷新重建列表后，恢复正在操作的分组按钮焦点。
    if (focusedGroup !== undefined && focusedGroup !== null) {
      const section = [...container.querySelectorAll('.group-section')].find(item => item.getAttribute('data-group-id') === focusedGroup);
      const button = section?.querySelector('.group-header');
      if (button instanceof HTMLElement) button.focus({preventScroll: true});
    }
    if (!this.hasRendered) ui.enter(container);
    this.hasRendered = true;
  },

  getGroupStatus(monitors) {
    if (monitors.length === 0) return 'empty';
 
    // 只参与状态计算的监控（排除已暂停）
    const active = monitors.filter(m => m.enabled !== 0 && m.enabled !== false);
    if (active.length === 0) return 'empty';

    if (active.some(m => m.maintenance?.active)) {
      const outside = active.filter(m => !m.maintenance?.active);
      if (outside.some(m => m.status === 'down')) return 'critical';
      if (outside.some(m => m.status === 'warning')) return 'warning';
      return 'maintenance';
    }
    const upCount = active.filter(m => m.status === 'up').length;
    const totalCount = active.length;

    if (upCount === totalCount) {
      return 'healthy';
    } else if (active.every(monitor => monitor.status === 'down')) {
      return 'critical';
    } else {
      return 'warning';
    }
  },

  renderGroupSection(group, monitors) {
    const status = this.getGroupStatus(monitors);
    const collapsed = this.isGroupCollapsed(group.id, monitors);
    const bodyId = `public-group-body-${group.id}`;
    const buttonId = `public-group-toggle-${group.id}`;
    const healthLabel = {maintenance: '维护中', healthy: '运行正常', critical: '服务离线', warning: '需要关注', empty: '已暂停检测'}[status];
    return `
      <section class="group-section ${status}${collapsed ? ' collapsed' : ''}" data-group-id="${group.id}" aria-labelledby="${buttonId}">
        <h3 class="public-group-heading">
          <button type="button" class="group-header" id="${buttonId}" aria-expanded="${!collapsed}" aria-controls="${bodyId}" title="${collapsed ? '展开分组' : '折叠分组'}">
            <span class="group-folder" aria-hidden="true">${ui.icon('folder')}</span>
            <span class="group-title">${this.escapeHtml(group.name)}</span>
            <span class="group-count">${monitors.length} 项服务</span>
            <span class="group-health">${healthLabel}${monitors.some(m => m.maintenance?.active && m.enabled) ? ` · 维护 ${monitors.filter(m => m.maintenance?.active && m.enabled).length} 项` : ''}</span>
            ${ui.groupHistory.render(monitors, this.statusBarsState)}
            <span class="public-collapse-label" aria-hidden="true">${collapsed ? '展开' : '收起'}</span>
            <span class="group-toggle" aria-hidden="true">${ui.icon('chevron')}</span>
          </button>
        </h3>
        <div class="group-body" id="${bodyId}"${collapsed ? ' inert' : ''}><div class="group-monitors">
          ${monitors.map(m => this.renderMonitorItem(m)).join('')}
        </div></div>
      </section>
    `;
  },

  // 渲染24小时状态条（与管理页共享逻辑）
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
    const statusClass = m.maintenance?.active && m.enabled ? 'maintenance' : ['up', 'down', 'warning'].includes(m.status) ? m.status : 'unknown';
    const isPaused = m.enabled === 0 || m.enabled === false;
    const uptimeText = m.uptime_24h !== null && m.uptime_24h !== undefined
      ? m.uptime_24h.toFixed(2) + '%'
      : '—';

    // 如果状态条数据未加载或为空数组，显示骨架屏
    const statusBarHtml = m.statusBar24h && Array.isArray(m.statusBar24h) && m.statusBar24h.length > 0
      ? this.renderStatusBar24h(m.statusBar24h)
      : this.renderStatusBarSkeleton();

    // 保留全部公开指标，按服务、运行记录与关键数值对齐为紧凑行。
    return `
      <div class="monitor-item ${statusClass}${isPaused ? ' paused' : ''}" data-id="${m.id}">
        <div class="public-service-identity">
          <div class="monitor-status" aria-hidden="true"></div>
          <div class="monitor-info">
            <div class="public-service-heading"><div class="monitor-name">${this.escapeHtml(m.name)}</div><span class="monitor-state-label">${ui.statusLabel(m)}</span></div>
            <div class="monitor-stat monitor-stat-last-check">
              <span class="monitor-stat-label">${publicIcons.lastCheck}<span>最后检测</span></span>
              <span class="monitor-stat-value">${m.last_check ? this.formatFullTime(m.last_check) : '—'}</span>
            </div>
          </div>
        </div>
        <div class="public-service-history">
          ${statusBarHtml}
          <div class="monitor-timeline-label"><span>24 小时前</span><span>现在</span></div>
        </div>
        <div class="monitor-stats">
          <div class="monitor-stat monitor-stat-response-time">
            <span class="monitor-stat-value">${m.last_response_time != null ? m.last_response_time + ' ms' : '—'}</span>
            <span class="monitor-stat-label">${publicIcons.responseTime} 响应时间</span>
          </div>
          <div class="monitor-stat monitor-stat-uptime">
            <span class="monitor-stat-value">${uptimeText}</span>
            <span class="monitor-stat-label">${publicIcons.uptime} 24小时可用率</span>
          </div>
          ${ui.renderResponseStats(m)}
        </div>
      </div>
    `;
  },

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  async loadVersion() {
    try {
      const response = await fetch('/api/version', {credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok) return;
      const data = await response.json();
      const label = document.getElementById('public-version');
      if (label && data.version) label.textContent = `v${data.version} · `;
    } catch (_error) { /* 公开页页脚没有版本号时仍显示原有署名。 */ }
  },

  formatFullTime(timeStr) {
    const date = new Date(timeStr);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
  },

};

// 初始化
publicApp.init().then(_r => {});
