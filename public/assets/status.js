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
  // 记录每个监控的状态条签名，避免无变化重绘导致闪烁
  statusBarSignatures: new Map(),
  
  async init() {
    // 标题由服务端在 / 路由渲染注入，这里只加载数据
    await this.loadBasicData();
    
    this.render();
    
    // 异步加载状态条数据（不阻塞首屏渲染）
    this.loadStatusBars();
    
    // 每30秒自动刷新
    setInterval(() => {
      this.loadBasicData().then(() => {
        this.render();
        this.loadStatusBars();
      });
    }, 30000);
  },
  
  async loadBasicData() {
    try {
      const [groupsRes, monitorsRes, statsRes] = await Promise.all([
        fetch('/api/public/groups'),
        fetch('/api/public/monitors'),
        fetch('/api/public/stats')
      ]);
      
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
        document.querySelector('.public-stat-card.up .public-stat-value').textContent = stats.up || 0;
        document.querySelector('.public-stat-card.down .public-stat-value').textContent = stats.down || 0;
        
        // 计算平均24小时可用率（从监控数据中计算）
        const monitorsWithUptime = this.monitors.filter(m => {
          const hasUptime = m.uptime_24h !== null && m.uptime_24h !== undefined;
          const isPaused = m.enabled === 0 || m.enabled === false;
          // 暂停服务不计入平均可用率
          return hasUptime && !isPaused;
        });
        if (monitorsWithUptime.length > 0) {
          const avgUptime = monitorsWithUptime.reduce((sum, m) => sum + m.uptime_24h, 0) / monitorsWithUptime.length;
          document.querySelector('.public-stat-card.uptime .public-stat-value').textContent = avgUptime.toFixed(2) + '%';
        } else {
          document.querySelector('.public-stat-card.uptime .public-stat-value').textContent = '-';
        }
      }
    } catch (error) {
      console.error('加载基础数据失败:', error);
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
    try {
      const statusBarsRes = await fetch('/api/public/monitors/statusbars');
      if (statusBarsRes.ok) {
        const statusBars = await statusBarsRes.json();
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

          return { ...m, statusBar24h: sb };
        });
      }
    } catch (error) {
      console.error('加载状态条数据失败:', error);
    }
  },
  
  render() {
    const container = document.getElementById('public-monitor-list');
    
    if (this.monitors.length === 0) {
      container.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-muted);">暂无公开的服务</div>';
      return;
    }
    
    // 按分组组织监控
    const grouped = {};
    const ungrouped = [];
    
    this.monitors.forEach(m => {
      if (m.group_id) {
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
        html += this.renderGroupSection({ id: 0, name: '未分组' }, sortedUngrouped);
      }
    }
    
    container.innerHTML = html;
  },
  
  getGroupStatus(monitors) {
    if (monitors.length === 0) return 'empty';
    
    const upCount = monitors.filter(m => m.status === 'up').length;
    const totalCount = monitors.length;
    
    if (upCount === totalCount) {
      return 'healthy';
    } else if (upCount === 0) {
      return 'critical';
    } else {
      return 'warning';
    }
  },
  
  renderGroupSection(group, monitors) {
    const status = this.getGroupStatus(monitors);
    return `
      <div class="group-section ${status}" data-group-id="${group.id}">
        <div class="group-header">
          <h3>${this.escapeHtml(group.name)}</h3>
          <span class="group-count">${monitors.length}</span>
        </div>
        <div class="group-monitors">
          ${monitors.map(m => this.renderMonitorItem(m)).join('')}
        </div>
      </div>
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
          : '-';
        const detail = item.message ? this.escapeHtml(item.message) : 
                      (item.status === 'up' ? '服务正常' : 
                       (item.status === null ? '无检测数据' : '-'));
        
        return `时间跨度: ${startStr} ~ ${endStr}\n可用率: ${uptime}\n失败次数 / 总检测次数: ${failCount} / ${totalChecks}\n详细信息: ${detail}`;
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
      let subStatuses = null;

      // 优先使用后端已聚合好的 segments（前端只负责渲染）
      if (Array.isArray(item.segments) && item.segments.length === 12) {
        subStatuses = item.segments.slice(0, 12);
      } else {
        // 兼容旧接口：使用 checkRecords 在前端聚合（保留以防回滚）
        const checkRecords = item.checkRecords || []; // 该时间段内的所有检测记录
        subStatuses = new Array(12).fill(null);
        const priority = { down: 3, warning: 2, up: 1 };

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
    const statusClass = m.status === 'up' ? 'up' : m.status === 'down' ? 'down' : 'unknown';
    const isPaused = m.enabled === 0 || m.enabled === false;
    const uptimeText = m.uptime_24h !== null && m.uptime_24h !== undefined 
      ? m.uptime_24h.toFixed(2) + '%' 
      : '-';
    
    // 如果状态条数据未加载或为空数组，显示骨架屏
    const statusBarHtml = m.statusBar24h && Array.isArray(m.statusBar24h) && m.statusBar24h.length > 0
      ? this.renderStatusBar24h(m.statusBar24h)
      : this.renderStatusBarSkeleton();
    
    return `
      <div class="monitor-item ${statusClass}${isPaused ? ' paused' : ''}" data-id="${m.id}">
        <div class="monitor-status"></div>
        <div class="monitor-info">
          <div class="monitor-name">${this.escapeHtml(m.name)}${isPaused ? '<span class="monitor-paused-badge">已暂停</span>' : ''}</div>
        </div>
        <div class="monitor-stats">
          <div class="monitor-stat">
            <span class="monitor-stat-value">${m.last_response_time ? m.last_response_time + 'ms' : '-'}</span>
            <span class="monitor-stat-label">${publicIcons.responseTime} 响应时间</span>
          </div>
          <div class="monitor-stat">
            <span class="monitor-stat-value">${uptimeText}</span>
            <span class="monitor-stat-label">${publicIcons.uptime} 24小时可用率</span>
          </div>
          <div class="monitor-stat monitor-stat-last-check">
            <span class="monitor-stat-value">${m.last_check ? this.formatFullTime(m.last_check) : '-'}</span>
            <span class="monitor-stat-label">${publicIcons.lastCheck} 最后检测时间</span>
          </div>
        </div>
        ${statusBarHtml}
      </div>
    `;
  },
  
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
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
  
  formatTime(timeStr) {
    // 使用准确时间格式，不再使用"刚刚"等相对时间
    return this.formatFullTime(timeStr);
  }
};

// 初始化
publicApp.init();
