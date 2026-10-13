// 公告与维护工作区；公开页也使用同一份只读内容卡片。
const communications = {
  initialized: false,
  rows: {announcements: [], maintenances: []},
  pages: {announcements: 1, maintenances: 1},
  editing: {},
  requests: {},
  previewRequests: {},
  editRequests: {},
  closeArmed: {},
  editorTriggers: {},
  savingEditor: null,
  publicPages: {},
  publicExpanded: false,
  publicTotal: 0,
  labels: {draft: '草稿', published: '已发布', archived: '已归档', scheduled: '待开始', active: '维护中', completed: '已结束', cancelled: '已取消'},
  escape(value) { return String(value ?? '').replace(/[&<>"']/g, ch => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[ch]); },
  time(value) { return value ? new Date(value).toLocaleString('zh-CN', {hour12: false}) : '手动结束'; },
  localTime(value) {
    if (!value) return '';
    const date = new Date(value);
    return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  },
  async request(path, options = {}) {
    const response = await fetch(path, {credentials: 'same-origin', cache: 'no-store', ...options,
      headers: {'Content-Type': 'application/json', ...options.headers}});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '暂时无法完成操作');
    return data;
  },
  checkbox(kind, name, label, checked = false) {
    return `<label class="content-check"><input id="${kind}-${name}" name="${name}" type="checkbox"${checked ? ' checked' : ''}>${label}</label>`;
  },
  init() {
    if (this.initialized) return;
    this.initialized = true;
    for (const kind of ['announcements', 'maintenances']) {
      const maintenance = kind === 'maintenances';
      const title = maintenance ? '维护管理' : '公告管理';
      const root = byId(`${kind}-view`);
      root.innerHTML = `<div class="page-heading"><div><div class="eyebrow">${maintenance ? 'MAINTENANCE' : 'ANNOUNCEMENTS'}</div>
        <h1 id="${kind}-heading" tabindex="-1">${title}</h1><p>${maintenance ? '提前安排维护，让服务状态有据可循。' : '让服务的重要消息及时传达。'}</p></div>
        <button type="button" class="btn-primary" data-content-action="new" data-ui-write>新建${maintenance ? '维护' : '公告'}</button></div>
        <div id="${kind}-error" class="content-error" role="alert" hidden></div>
        <div id="${kind}-editor" class="modal-overlay content-editor-overlay" aria-hidden="true">
        <form id="${kind}-form" class="modal content-editor" role="dialog" aria-modal="true" aria-labelledby="${kind}-editor-title" aria-describedby="${kind}-editor-help" tabindex="-1" data-ui-write-form>
          <div class="modal-header"><h2 id="${kind}-editor-title">新建${maintenance ? '维护' : '公告'}</h2>
            <button class="btn-close" type="button" data-content-action="close" aria-label="关闭${maintenance ? '维护' : '公告'}编辑"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
          <div class="content-editor-body">
          <p id="${kind}-editor-help" class="content-muted content-editor-help">通过关闭按钮退出；点击浮窗外会先提示，再点一次才关闭。</p>
          <label class="content-field">标题<input id="${kind}-title" name="title" type="text" required maxlength="200"></label>
          <div class="content-editor-columns"><label class="content-field">${maintenance ? '维护说明' : '公告正文'} · Markdown
            <textarea id="${kind}-body" name="body" rows="8" maxlength="20000" placeholder="支持标题、列表、链接和代码"></textarea></label>
            <section class="content-preview"><div class="content-preview-heading">预览<button type="button" class="btn-secondary" data-content-action="preview">更新预览</button></div>
              <div class="markdown-content" id="${kind}-preview" aria-live="polite"><p class="content-muted">点击更新预览查看排版。</p></div></section></div>
          ${maintenance ? `<fieldset class="content-scope"><legend>维护范围</legend><p id="maintenances-locked-note" class="content-muted" hidden>维护已开始，监控范围、开始时间和处理方式已锁定。</p><div id="maintenances-groups" class="content-actions"></div><div id="maintenances-monitors" class="content-monitor-picker"></div></fieldset>
            <div class="content-options">${this.checkbox(kind, 'immediate', '立即开始', true)}
              <label class="content-field">开始时间<input id="maintenances-start" type="datetime-local" name="starts_at" disabled></label>
              <label class="content-field">结束时间<input id="maintenances-end" type="datetime-local" name="ends_at"></label></div>
            <p class="content-muted">时区：${this.escape(Intl.DateTimeFormat().resolvedOptions().timeZone)}。立即维护可留空结束时间；预约维护必须填写起止时间。</p>
            <fieldset class="content-options"><legend>维护期间</legend>${this.checkbox(kind, 'continue_checks', '继续检测', true)}${this.checkbox(kind, 'suppress_alerts', '抑制异常与恢复告警', true)}${this.checkbox(kind, 'exclude_stats', '维护样本排除统计', true)}</fieldset>
            <p class="content-muted">停止检测时不产生样本；多个维护时段重叠时，暂停、静默和统计排除分别合并生效。</p>
            ${this.checkbox(kind, 'is_public', '在公开状态页展示维护说明')}` : this.checkbox(kind, 'pinned', '置顶公告')}
          <fieldset class="content-options"><legend>主动通知</legend>${this.checkbox(kind, 'email', '邮件')}${this.checkbox(kind, 'webhook', 'Webhook')}${this.checkbox(kind, 'feishu', '飞书')}</fieldset>
          <p class="content-muted">沿用系统设置中的接收方。${maintenance ? '预约、开始、结束、取消和改期时发送。' : '发布时发送，编辑正文不会重复通知。'}</p>
          </div>
          <div class="content-editor-footer">
          <div id="${kind}-editor-error" class="content-error" role="alert" tabindex="-1" hidden></div>
          <p id="${kind}-close-hint" class="content-close-hint" role="status" aria-live="polite" hidden></p>
          <div class="content-editor-actions"><button class="btn-secondary" type="button" data-content-action="close">关闭</button>
            <button class="btn-primary" type="submit" data-ui-write>保存</button>
            ${!maintenance ? '<button class="btn-secondary" type="submit" name="publish" value="1" data-ui-write>保存并发布</button>' : ''}
          </div></div>
        </form></div>
        <div class="content-toolbar"><label>${maintenance ? '维护记录' : '公告状态'} <select id="${kind}-filter">
          ${maintenance ? '<option value="current">当前与预约</option><option value="history">历史维护</option>' : '<option value="">全部状态</option><option value="draft">草稿</option><option value="published">已发布</option><option value="archived">已归档</option>'}</select></label>
          <button type="button" class="btn-secondary" data-content-action="refresh">刷新</button></div>
        <div class="content-list" id="${kind}-list" aria-live="polite"></div>
        <div class="content-pagination"><button type="button" class="btn-secondary" data-content-action="previous">上一页</button><span id="${kind}-page"></span><button type="button" class="btn-secondary" data-content-action="next">下一页</button></div>`;
      const overlay = byId(`${kind}-editor`);
      // 浮窗放在工作区外，避免被共用对话框管理器设为 inert。
      document.body.append(overlay);
      overlay.inert = true;
      const onAction = event => {
        if (!(event.target instanceof Element)) return;
        const button = event.target.closest('[data-content-action]');
        if (!button || button.matches(':disabled')) return;
        const sequence = this.editRequests[kind];
        this.action(kind, button.dataset.contentAction, Number(button.dataset.id), button).catch(error => {
          if (overlay.contains(button)) {
            if (this.editRequests[kind] === sequence) this.editorError(kind, error.message);
          } else this.error(kind, error.message);
        });
      };
      root.addEventListener('click', onAction);
      overlay.addEventListener('click', onAction);
      let backdropPointer = false;
      overlay.addEventListener('pointerdown', event => {
        backdropPointer = event.target === overlay && event.button === 0 && event.isPrimary;
        if (event.target !== overlay) this.resetCloseHint(kind);
      });
      overlay.addEventListener('pointercancel', () => {backdropPointer = false;});
      overlay.addEventListener('click', event => {
        // 从表单内拖到遮罩的松手事件不计作关闭操作。
        const outside = backdropPointer && event.target === overlay;
        backdropPointer = false;
        if (outside) this.requestBackdropClose(kind);
      });
      overlay.addEventListener('input', () => this.resetCloseHint(kind));
      overlay.addEventListener('keydown', event => {
        this.resetCloseHint(kind);
        if (event.key === 'Escape') {
          event.preventDefault();
          event.stopPropagation();
          this.closeHint(kind, '请点击关闭按钮退出；未保存的内容不会保留。');
        }
      });
      form(`${kind}-form`).addEventListener('submit', event => {event.preventDefault(); this.save(kind, event.submitter);});
      byId(`${kind}-filter`).addEventListener('change', () => {this.pages[kind] = 1; this.load(kind);});
    }
    input('maintenances-immediate').addEventListener('change', () => this.syncTimeFields());
    ui.runtime.apply();
  },
  error(kind, message = '') {
    const element = byId(`${kind}-error`);
    element.textContent = message;
    element.hidden = !message;
  },
  editorError(kind, message = '') {
    const element = byId(`${kind}-editor-error`);
    element.textContent = message;
    element.hidden = !message;
    if (message && byId(`${kind}-editor`).classList.contains('active')) element.focus({preventScroll: true});
  },
  closeHint(kind, message) {
    const hint = byId(`${kind}-close-hint`);
    hint.textContent = message;
    hint.hidden = !message;
  },
  resetCloseHint(kind) {
    this.closeArmed[kind] = false;
    this.closeHint(kind, '');
  },
  requestBackdropClose(kind) {
    if (this.savingEditor === kind) {
      this.closeHint(kind, '正在保存，请稍候。');
      return;
    }
    if (this.closeArmed[kind]) this.closeEditor(kind);
    else {
      this.closeArmed[kind] = true;
      this.closeHint(kind, '再次点击浮窗外将关闭，未保存的内容会丢失。继续编辑可取消关闭。');
      form(`${kind}-form`).focus({preventScroll: true});
    }
  },
  closeEditor(kind, force = false) {
    if (!force && this.savingEditor === kind) return;
    const overlay = byId(`${kind}-editor`);
    const wasOpen = overlay.classList.contains('active');
    overlay.classList.remove('active');
    this.editRequests[kind] = (this.editRequests[kind] || 0) + 1;
    this.previewRequests[kind] = (this.previewRequests[kind] || 0) + 1;
    this.editing[kind] = null;
    this.resetCloseHint(kind);
    this.editorError(kind);
    ui.syncDialogs();
    // 列表自动刷新可能替换原来的编辑按钮，此时回到该工作区的新建按钮。
    if (wasOpen && !ui.dialogOrder.length) {
      const trigger = this.editorTriggers[kind];
      const root = byId(`${kind}-view`);
      const replacement = trigger?.rowId ? root.querySelector(`[data-content-action="edit"][data-id="${trigger.rowId}"]`) : null;
      const fallback = root.querySelector('[data-content-action="new"]:not(:disabled)') || byId(`${kind}-heading`);
      const target = trigger?.element?.isConnected ? trigger.element : replacement || fallback;
      if (target instanceof HTMLElement && !target.matches(':disabled') && !target.closest('[inert]') && target.getClientRects().length) target.focus({preventScroll: true});
    }
    delete this.editorTriggers[kind];
  },
  async load(kind) {
    if (!this.initialized || !['announcements', 'maintenances'].includes(kind)) return;
    const sequence = (this.requests[kind] || 0) + 1;
    this.requests[kind] = sequence;
    const filter = input(`${kind}-filter`).value;
    const query = new URLSearchParams({page: String(this.pages[kind])});
    if (kind === 'announcements' && filter) query.set('state', filter);
    if (kind === 'maintenances' && filter === 'history') query.set('history', '1');
    try {
      const result = await this.request(`/api/${kind}?${query}`);
      if (this.requests[kind] !== sequence) return;
      this.rows[kind] = result.items;
      const list = byId(`${kind}-list`);
      const open = new Set([...list.querySelectorAll('details[open]')].map(node => node.getAttribute('data-content-id')));
      list.innerHTML = result.items.map(row => this.card(kind, row, true)).join('') || '<div class="content-empty">暂无记录，可以从右上角开始创建。</div>';
      list.querySelectorAll('details').forEach(node => {node.open = open.has(node.getAttribute('data-content-id'));});
      byId(`${kind}-page`).textContent = `第 ${result.page} 页`;
      const root = byId(`${kind}-view`);
      root.querySelector('[data-content-action="previous"]').disabled = result.page === 1;
      root.querySelector('[data-content-action="next"]').disabled = !result.has_more;
      this.error(kind);
      ui.runtime.apply();
    } catch (error) { if (this.requests[kind] === sequence) this.error(kind, error.message + '，可点击刷新重试。'); }
  },
  card(kind, row, manage = false) {
    const maintenance = kind === 'maintenances';
    const e = value => this.escape(value);
    const action = (name, label, writable = true) => `<button type="button" class="btn-secondary" data-content-action="${name}" data-id="${row.id}"${writable ? ' data-ui-write' : ''}>${label}</button>`;
    const notifications = (row.deliveries || []).slice(0, 12).map(item => {
      const state = {pending: '待发送', sending: '发送中', sent: '已发送', failed: '失败', skipped: '已跳过'}[item.state] || item.state;
      return `<span class="content-delivery ${item.state === 'failed' ? 'failed' : ''}" title="${e(item.last_error || item.event_key)}">${e(item.channel)} · ${e(state)}${item.attempts ? ` (${item.attempts})` : ''}</span>`;
    }).join('');
    return `<article class="content-card ${maintenance && row.state === 'active' ? 'is-active' : ''}">
      <div class="content-card-heading"><span class="content-badge">${row.pinned ? '置顶 · ' : ''}${e(this.labels[row.state])}</span>
        ${manage && maintenance ? `<span class="content-muted">${row.is_public ? '公开说明' : '内部维护'}</span>` : ''}</div>
      <h3>${e(row.title)}</h3><p class="content-meta">${maintenance ? `${e(this.time(row.starts_at))} → ${e(this.time(row.ends_at))}` : row.published_at ? e(this.time(row.published_at)) : '尚未发布'}</p>
      ${maintenance ? `<p class="content-meta">影响服务：${(row.monitors || []).map(monitor => e(monitor.name)).join('、') || '关联服务已删除'}</p>` : ''}
      <details data-content-id="${row.id}"><summary>查看${maintenance ? '维护说明' : '公告内容'}</summary><div class="markdown-content">${row.body_html || '<p>暂无补充说明。</p>'}</div></details>
      ${manage ? `<div class="content-actions">${action('edit', ui.runtime.canWrite() ? '编辑' : '查看配置', false)}
        ${maintenance ? (row.state === 'scheduled' ? action('cancel', '取消预约') : row.state === 'active' ? action('finish', '结束维护') : '')
          : (row.state !== 'published' ? action('publish', '发布') : action('withdraw', '撤回') + action('archive', '归档')) +
            action('pin', row.pinned ? '取消置顶' : '置顶') + (row.state === 'draft' ? action('delete', '删除草稿') : '')}</div>
        ${notifications ? `<details class="content-deliveries"><summary>通知投递记录</summary><div class="content-actions">${notifications}</div></details>` : ''}` : ''}
    </article>`;
  },
  syncTimeFields() {
    const locked = this.editing.maintenances?.state === 'active';
    input('maintenances-start').disabled = locked || input('maintenances-immediate').checked;
    input('maintenances-start').required = !input('maintenances-immediate').checked;
    input('maintenances-end').required = !input('maintenances-immediate').checked;
    ui.runtime.apply();
  },
  async edit(kind, row = null) {
    if (this.saving) return;
    this.editorTriggers[kind] = {element: document.activeElement, rowId: row?.id};
    const sequence = (this.editRequests[kind] || 0) + 1;
    this.editRequests[kind] = sequence;
    this.previewRequests[kind] = (this.previewRequests[kind] || 0) + 1;
    const editor = form(`${kind}-form`);
    editor.reset();
    this.editing[kind] = row ? {...row} : null;
    this.error(kind);
    this.editorError(kind);
    this.resetCloseHint(kind);
    input(`${kind}-title`).value = row?.title || '';
    input(`${kind}-body`).value = row?.body || '';
    for (const channel of ['email', 'webhook', 'feishu']) input(`${kind}-${channel}`).checked = row?.channels?.includes(channel) || false;
    byId(`${kind}-preview`).innerHTML = row?.body_html || '<p class="content-muted">点击更新预览查看排版。</p>';
    byId(`${kind}-editor-title`).textContent = `${row ? ui.runtime.canWrite() ? '编辑' : '查看' : '新建'}${kind === 'announcements' ? '公告' : '维护'}`;
    if (kind === 'announcements') {
      input('announcements-pinned').checked = !!row?.pinned;
      editor.querySelector('[name="publish"]').hidden = !!row;
    } else {
      await app.loadGroups();
      await app.loadMonitors();
      if (this.editRequests[kind] !== sequence || app.currentView !== kind) return;
      const locked = !!row && row.state !== 'scheduled';
      const selected = new Set(row?.monitors?.map(monitor => monitor.id) || []);
      byId('maintenances-monitors').innerHTML = app.monitors.map(monitor => `<label class="content-check"><input type="checkbox" name="monitor_ids" value="${monitor.id}" data-group="${monitor.group_id || 0}"${selected.has(monitor.id) ? ' checked' : ''}${locked ? ' disabled' : ''}>${this.escape(monitor.name)}${monitor.is_public ? '' : '（私有）'}</label>`).join('') || '<p class="content-muted">请先添加监控项。</p>';
      byId('maintenances-groups').innerHTML = [...app.groups, {id: 0, name: '未分组'}].map(group => `<button class="btn-secondary" type="button" data-content-action="group" data-id="${group.id}" data-ui-write${locked ? ' disabled' : ''}>选择${this.escape(group.name)}</button>`).join('');
      input('maintenances-immediate').checked = !row || row.state === 'active';
      input('maintenances-immediate').disabled = !!row;
      input('maintenances-start').value = this.localTime(row?.starts_at);
      input('maintenances-end').value = this.localTime(row?.ends_at);
      input('maintenances-is_public').checked = !!row?.is_public;
      for (const option of ['continue_checks', 'suppress_alerts', 'exclude_stats']) {
        input(`maintenances-${option}`).checked = row ? !!row[option] : true;
        input(`maintenances-${option}`).disabled = locked;
      }
      byId('maintenances-locked-note').hidden = !locked;
      editor.querySelector('button[type="submit"]').hidden = !!row && ['completed', 'cancelled'].includes(row.state);
      this.syncTimeFields();
    }
    ui.runtime.apply();
    byId(`${kind}-editor`).classList.add('active');
    editor.querySelector('.content-editor-body').scrollTop = 0;
    ui.syncDialogs();
  },
  async save(kind, submitter) {
    if (!ui.runtime.guardWrite() || this.saving) return;
    const editor = form(`${kind}-form`);
    if (!editor.reportValidity()) return;
    const row = this.editing[kind];
    const payload = {title: input(`${kind}-title`).value, body: input(`${kind}-body`).value,
      channels: ['email', 'webhook', 'feishu'].filter(channel => input(`${kind}-${channel}`).checked), revision: row?.revision};
    if (kind === 'announcements') {
      payload.pinned = input('announcements-pinned').checked;
      if (!row) payload.publish = submitter?.name === 'publish';
    } else {
      payload.is_public = input('maintenances-is_public').checked;
      const endValue = input('maintenances-end').value;
      if (!row || endValue !== this.localTime(row.ends_at)) payload.ends_at = endValue ? new Date(endValue).toISOString() : null;
      if (!row || row.state === 'scheduled') {
        payload.monitor_ids = [...editor.querySelectorAll('[name="monitor_ids"]:checked')].map(element => Number(element.value));
        for (const option of ['continue_checks', 'suppress_alerts', 'exclude_stats']) payload[option] = input(`maintenances-${option}`).checked;
        payload.immediate = input('maintenances-immediate').checked;
        if (!payload.immediate && (!row || input('maintenances-start').value !== this.localTime(row.starts_at))) {
          payload.starts_at = new Date(input('maintenances-start').value).toISOString();
        }
      }
    }
    this.saving = true;
    this.savingEditor = kind;
    const sequence = this.editRequests[kind];
    this.editorError(kind);
    this.resetCloseHint(kind);
    editor.setAttribute('aria-busy', 'true');
    const buttons = [...editor.querySelectorAll('button[type="submit"], [data-content-action="close"]')];
    buttons.forEach(button => {button.disabled = true;});
    try {
      await this.request(`/api/${kind}${row ? '/' + row.id : ''}`, {method: row ? 'PUT' : 'POST', body: JSON.stringify(payload)});
      if (this.editRequests[kind] !== sequence) return;
      this.pages[kind] = 1;
      await this.load(kind);
      if (this.editRequests[kind] !== sequence) return;
      this.closeEditor(kind, true);
      await app.loadMonitors();
      await app.loadStats();
      app.showToast('保存成功');
    } catch (error) {
      if (this.editRequests[kind] === sequence) this.editorError(kind, error.message);
    } finally {
      this.saving = false;
      this.savingEditor = null;
      editor.removeAttribute('aria-busy');
      this.resetCloseHint(kind);
      buttons.forEach(button => {button.disabled = false;});
      ui.runtime.apply();
    }
  },
  async action(kind, action, id, button) {
    const row = this.rows[kind].find(item => item.id === id);
    if (action === 'new') {if (ui.runtime.guardWrite()) await this.edit(kind); return;}
    if (action === 'edit') {if (row) await this.edit(kind, row); return;}
    if (action === 'close') {this.closeEditor(kind); return;}
    if (action === 'preview') {
      const sequence = (this.previewRequests[kind] || 0) + 1;
      this.previewRequests[kind] = sequence;
      const result = await this.request('/api/content/preview', {method: 'POST', body: JSON.stringify({body: input(`${kind}-body`).value})});
      if (this.previewRequests[kind] === sequence) byId(`${kind}-preview`).innerHTML = result.html;
      return;
    }
    if (['refresh', 'next', 'previous'].includes(action)) {
      if (action === 'next') this.pages[kind]++;
      if (action === 'previous') this.pages[kind] = Math.max(1, this.pages[kind] - 1);
      await this.load(kind); return;
    }
    if (!ui.runtime.guardWrite()) return;
    if (action === 'group') {
      const boxes = [...byId('maintenances-monitors').querySelectorAll(`input[data-group="${id}"]:not(:disabled)`)];
      const checked = !boxes.every(box => box.checked);
      boxes.forEach(box => {box.checked = checked;}); return;
    }
    if (!row || this.saving) return;
    if (['delete', 'cancel', 'finish', 'withdraw'].includes(action) && !await ui.confirm(`确定${{delete: '删除草稿', cancel: '取消预约', finish: '结束维护', withdraw: '撤回公告'}[action]}「${row.title}」？`)) return;
    this.saving = true;
    button.disabled = true;
    try {
      const path = `/api/${kind}/${id}${['pin', 'delete'].includes(action) ? '' : '/' + action}`;
      await this.request(path, {method: action === 'pin' ? 'PUT' : action === 'delete' ? 'DELETE' : 'POST',
        body: JSON.stringify({revision: row.revision, ...(action === 'pin' ? {pinned: !row.pinned} : {})})});
      await this.load(kind);
      await app.loadMonitors();
      await app.loadStats();
    } finally {this.saving = false; button.disabled = false; ui.runtime.apply();}
  },
  reset() {
    ui.pendingConfirmation?.();
    for (const kind of ['announcements', 'maintenances']) {
      this.requests[kind] = (this.requests[kind] || 0) + 1;
      this.previewRequests[kind] = (this.previewRequests[kind] || 0) + 1;
      this.editRequests[kind] = (this.editRequests[kind] || 0) + 1;
      this.editing[kind] = null;
      this.rows[kind] = [];
      if (this.initialized) {this.closeEditor(kind, true); form(`${kind}-form`).reset(); byId(`${kind}-list`).replaceChildren();}
    }
  },
  timelineCard(row, history) {
    const maintenance = row.kind === 'maintenances';
    const e = value => this.escape(value);
    const date = new Date(row.timeline_at);
    const dateText = date.toLocaleDateString('zh-CN', {year: 'numeric', month: '2-digit', day: '2-digit'});
    const clockText = date.toLocaleTimeString('zh-CN', {hour: '2-digit', minute: '2-digit', hour12: false});
    const momentLabel = history ? maintenance ? row.state === 'cancelled' ? '取消' : '结束' : '归档'
      : maintenance ? '开始' : '发布';
    const key = row.kind + '-' + row.id;
    return `<li class="public-timeline-item ${maintenance ? 'is-maintenance' : 'is-announcement'} is-${e(row.state)}" data-timeline-key="${e(key)}">
      <time class="public-timeline-time" datetime="${e(row.timeline_at)}"><span>${e(dateText)}</span><span>${e(clockText)} · ${momentLabel}</span></time>
      <article class="public-timeline-content">
        <div class="public-timeline-tags"><span class="content-badge">${maintenance ? '维护' : '公告'}</span>${row.pinned && !history ? '<span class="content-badge">置顶</span>' : ''}<span class="public-timeline-state">${e(this.labels[row.state])}</span></div>
        <h3>${e(row.title)}</h3>
        ${maintenance ? `<p class="content-meta">${e(this.time(row.starts_at))} → ${e(this.time(row.ends_at))}</p><p class="content-meta">影响服务：${(row.monitors || []).map(monitor => e(monitor.name)).join('、') || '关联服务已删除'}</p>` : ''}
        <details data-content-id="${e(key)}"><summary>查看${maintenance ? '维护说明' : '公告内容'}</summary><div class="markdown-content">${row.body_html || '<p>暂无补充说明。</p>'}</div></details>
      </article>
    </li>`;
  },
  initPublic() {
    const root = document.getElementById('public-communications');
    const historyRoot = document.getElementById('public-communications-history');
    if (!root || !historyRoot || root.dataset.initialized) return;
    root.dataset.initialized = 'true';
    document.getElementById('public-updates-toggle').addEventListener('click', async event => {
      const button = event.currentTarget;
      if (!(button instanceof HTMLButtonElement)) return;
      if (this.publicExpanded && (this.publicPages.updates > 1 || this.publicLoading?.updates)) {
        button.disabled = true;
        try {await this.loadPublic(false, 1);} finally {button.disabled = false;}
        // 第一页读取失败时保留展开状态和重试入口。
        if (this.publicPages.updates !== 1) return;
      }
      this.publicExpanded = !this.publicExpanded;
      this.updatePublicVisibility();
      button.focus({preventScroll: true});
    });
    document.getElementById('public-updates-history-disclosure').addEventListener('toggle', event => {
      if (event.currentTarget.open) this.loadPublic(true);
    });
    for (const section of [root, historyRoot]) section.addEventListener('click', event => {
      if (!(event.target instanceof Element)) return;
      const button = event.target.closest('[data-public-page]');
      if (!button || button.disabled) return;
      this.loadPublic(button.dataset.history === 'true', Number(button.dataset.publicPage));
    });
  },
  refreshPublic() {
    this.initPublic();
    this.loadPublic(false);
    if (document.getElementById('public-updates-history-disclosure')?.open) this.loadPublic(true);
  },
  updatePublicVisibility() {
    const list = document.getElementById('public-updates');
    const button = document.getElementById('public-updates-toggle');
    if (!list || !(button instanceof HTMLButtonElement)) return;
    list.querySelectorAll('.public-timeline-item').forEach((item, index) => {
      item.hidden = !this.publicExpanded && index > 0;
    });
    document.getElementById('public-communications').classList.toggle('is-collapsed', !this.publicExpanded);
    const pagination = document.querySelector('#public-updates-paging nav');
    if (pagination) pagination.hidden = !this.publicExpanded;
    button.hidden = this.publicTotal <= 1;
    button.setAttribute('aria-expanded', String(this.publicExpanded));
    button.querySelector('span').textContent = this.publicExpanded ? '收起，仅显示第一条' : `展开剩余 ${this.publicTotal - 1} 条`;
  },
  async loadPublic(history, requestedPage) {
    const key = history ? 'updates-history' : 'updates';
    const list = document.getElementById(`public-${key}`);
    const paging = document.getElementById(`public-${key}-paging`);
    if (!list || !paging) return;
    const requestKey = key + '-public';
    // 定时刷新不打断正在翻页的请求。
    if (requestedPage === undefined && this.publicLoading?.[key]) return;
    this.publicLoading ||= {};
    this.publicLoading[key] = true;
    const sequence = (this.requests[requestKey] || 0) + 1;
    this.requests[requestKey] = sequence;
    const page = requestedPage ?? this.publicPages[key] ?? 1;
    const previousPage = this.publicPages[key] || 1;
    const focused = document.activeElement;
    const focusKey = list.contains(focused) ? focused.closest('[data-content-id]')?.dataset.contentId : null;
    list.setAttribute('aria-busy', 'true');
    if (!list.childElementCount) list.innerHTML = '<li class="content-muted public-timeline-empty">正在读取动态…</li>';
    try {
      const result = await this.request(`/api/public/updates?page=${page}${history ? '&history=1' : ''}`);
      if (this.requests[requestKey] !== sequence) return;
      if (!result.items.length && page > 1) return this.loadPublic(history, page - 1);
      this.publicSignatures ||= {};
      const signature = JSON.stringify(result);
      if (this.publicSignatures[key] === signature && !paging.querySelector('.content-error')) return;
      const open = new Set([...list.querySelectorAll('details[open]')].map(node => node.getAttribute('data-content-id')));
      list.innerHTML = result.items.map(row => this.timelineCard(row, history)).join('') ||
        `<li class="content-muted public-timeline-empty">${history ? '暂无历史公告或维护记录' : '暂无公告或维护安排'}</li>`;
      list.querySelectorAll('details').forEach(node => {node.open = open.has(node.getAttribute('data-content-id'));});
      this.publicPages[key] = result.page;
      this.publicSignatures[key] = signature;
      paging.innerHTML = `<nav class="content-pagination" aria-label="${history ? '历史动态' : '公告与维护'}分页">
        ${page > 1 ? `<button type="button" class="btn-secondary" data-history="${history}" data-public-page="${page - 1}">上一页</button>` : ''}
        ${page > 1 || result.has_more ? `<span>第 ${page} 页 · 共 ${result.total} 条</span>` : ''}
        ${result.has_more ? `<button type="button" class="btn-secondary" data-history="${history}" data-public-page="${page + 1}">下一页</button>` : ''}</nav>`;
      if (!history) {
        this.publicTotal = result.total;
        this.updatePublicVisibility();
      }
      if (requestedPage !== undefined && page !== previousPage) {
        list.tabIndex = -1;
        list.focus({preventScroll: true});
        list.scrollIntoView({block: 'nearest', behavior: 'auto'});
      } else if (focusKey && document.activeElement === document.body) {
        const details = [...list.querySelectorAll('details')].find(node => node.dataset.contentId === focusKey);
        const focusTarget = details?.closest('li').hidden ? document.getElementById('public-updates-toggle') : details?.querySelector('summary');
        focusTarget?.focus({preventScroll: true});
      }
    } catch {
      if (this.requests[requestKey] !== sequence) return;
      if (!this.publicPages[key]) list.innerHTML = '<li class="content-muted public-timeline-empty">暂时无法读取动态</li>';
      paging.innerHTML = `<p class="content-error" role="status">内容更新失败${this.publicPages[key] ? '，保留上次记录' : ''}。<button type="button" class="btn-secondary" data-history="${history}" data-public-page="${page}">重试</button></p>`;
    } finally {
      if (this.requests[requestKey] === sequence) {this.publicLoading[key] = false; list.setAttribute('aria-busy', 'false');}
    }
  }
};
