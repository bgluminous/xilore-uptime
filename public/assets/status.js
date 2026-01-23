// ============ 立即加载标题（在页面渲染前就准备好）============
(function() {
  function loadTitleEarly() {
    fetch('/api/public/title')
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data && data.title) {
          // 等待 DOM 加载完成后再更新
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function() {
              updateTitle(data.title);
            });
          } else {
            updateTitle(data.title);
          }
        }
      })
      .catch(() => {
        // 静默失败，使用默认标题
      });
  }
  
  function updateTitle(title) {
    const titleEl = document.getElementById('public-title');
    if (titleEl && titleEl.textContent !== title) {
      titleEl.textContent = title;
    }
    document.title = title;
  }
  
  // 立即开始加载标题
  loadTitleEarly();
})();

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
  
  async init() {
    // 标题已经在页面头部提前加载，这里只加载数据
    await this.loadData();
    
    this.render();
    // 每30秒自动刷新
    setInterval(() => {
      Promise.all([
        this.loadTitle(),
        this.loadData()
      ]).then(() => this.render());
    }, 30000);
  },
  
  setTitle(title) {
    const titleElement = document.getElementById('public-title');
    if (titleElement) {
      // 只有当标题不同时才更新，避免不必要的 DOM 操作导致抖动
      if (titleElement.textContent !== title) {
        titleElement.textContent = title;
      }
    }
    // 更新 document.title（这个更新不会造成视觉抖动）
    document.title = title;
  },
  
  async loadTitle() {
    try {
      const res = await fetch('/api/public/title');
      if (res.ok) {
        const data = await res.json();
        const title = data.title || '服务状态监控';
        this.setTitle(title);
      }
    } catch (error) {
      console.error('加载标题失败:', error);
    }
  },
  
  async loadData() {
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
        this.monitors = await monitorsRes.json();
      }
      
      if (statsRes.ok) {
        const stats = await statsRes.json();
        document.querySelector('.public-stat-card.up .public-stat-value').textContent = stats.up || 0;
        document.querySelector('.public-stat-card.down .public-stat-value').textContent = stats.down || 0;
        
        // 计算平均24小时可用率（从监控数据中计算）
        const monitorsWithUptime = this.monitors.filter(m => m.uptime_24h !== null && m.uptime_24h !== undefined);
        if (monitorsWithUptime.length > 0) {
          const avgUptime = monitorsWithUptime.reduce((sum, m) => sum + m.uptime_24h, 0) / monitorsWithUptime.length;
          document.querySelector('.public-stat-card.uptime .public-stat-value').textContent = avgUptime.toFixed(2) + '%';
        } else {
          document.querySelector('.public-stat-card.uptime .public-stat-value').textContent = '-';
        }
      }
    } catch (error) {
      console.error('加载数据失败:', error);
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
    
    // 渲染分组（只显示有公开服务的分组）
    this.groups.forEach(group => {
      const monitors = grouped[group.id] || [];
      // 只显示有公开服务的分组
      const publicMonitors = monitors
        .filter(m => m.is_public === 1 || m.is_public === true)
        .sort((a, b) => {
          // 按名称排序：英文字母在中文前面
          return sortByName(a.name || '', b.name || '');
        });
      if (publicMonitors.length > 0) {
        html += this.renderGroupSection(group, publicMonitors);
      }
    });
    
    // 渲染未分组
    if (ungrouped.length > 0) {
      const sortedUngrouped = ungrouped
        .filter(m => m.is_public === 1 || m.is_public === true)
        .sort((a, b) => {
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
      const checkRecords = item.checkRecords || []; // 该时间段内的所有检测记录
      const tooltip = getTooltip(item).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
      
      const subItems = [];
      const subStatuses = new Array(12).fill(null);
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

  renderMonitorItem(m) {
    const statusClass = m.status === 'up' ? 'up' : m.status === 'down' ? 'down' : 'unknown';
    const uptimeText = m.uptime_24h !== null && m.uptime_24h !== undefined 
      ? m.uptime_24h.toFixed(2) + '%' 
      : '-';
    
    const statusBarHtml = this.renderStatusBar24h(m.statusBar24h);
    
    return `
      <div class="monitor-item ${statusClass}" data-id="${m.id}">
        <div class="monitor-status"></div>
        <div class="monitor-info">
          <div class="monitor-name">${this.escapeHtml(m.name)}</div>
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
