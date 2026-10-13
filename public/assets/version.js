// 管理端版本提示。更新检查仅发出读取请求，容器升级由部署者完成。
const versions = {
  info: null,
  controller: null,
  historyController: null,
  loadedAt: 0,
  historyPage: 0,

  reset() {
    this.controller?.abort();
    this.historyController?.abort();
    this.controller = this.historyController = null;
    this.info = null;
    this.loadedAt = this.historyPage = 0;
    byId('version-history-list').replaceChildren();
    byId('version-history').removeAttribute('open');
    byId('version-history-error').hidden = true;
    byId('version-history-paging').hidden = true;
    byId('version-meta').hidden = true;
    byId('version-latest').hidden = true;
  },

  async request(url, signal) {
    const response = await fetch(url, {credentials: 'same-origin', cache: 'no-store', signal});
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    return body;
  },

  async load(options = {}) {
    if (!auth.user || (this.controller && options.quiet)) return;
    this.controller?.abort();
    const controller = new AbortController();
    this.controller = controller;
    const button = byId('version-retry-btn');
    const restoreFocus = document.activeElement === button;
    button.disabled = true;
    button.textContent = '正在检查…';
    if (!options.quiet) {
      byId('version-load-message').hidden = false;
      byId('version-load-message').textContent = '正在检查 GitHub 版本索引…';
    }
    try {
      const data = await this.request(`/api/version/check${options.refresh ? '?refresh=1' : ''}`, controller.signal);
      if (controller !== this.controller || !auth.user) return;
      this.info = data;
      this.loadedAt = Date.now();
      this.render();
    } catch (error) {
      if (controller !== this.controller || controller.signal.aborted) return;
      this.loadedAt = Date.now();
      byId('version-load-message').hidden = false;
      byId('version-load-message').textContent = `版本检查失败：${error.message}。${this.info ? '保留上次结果。' : ''}`;
    } finally {
      if (controller === this.controller) {
        this.controller = null;
        button.disabled = false;
        button.textContent = '重新检查';
        if (restoreFocus && button.getClientRects().length
          && (document.activeElement === document.body || document.activeElement === button)) button.focus();
      }
    }
  },

  setLink(link, value) {
    link.hidden = true;
    link.removeAttribute('href');
    try {
      const url = new URL(value);
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return;
      link.href = url.href;
      link.hidden = false;
    } catch (_error) { /* 无合法链接时保留更新日志。 */ }
  },

  render() {
    const data = this.info;
    if (!data) return;
    byId('sidebar-version').hidden = false;
    byId('sidebar-version-text').textContent = `版本 ${data.version}`;
    byId('workspace-version').textContent = `v${data.version}`;
    byId('sidebar-version-badge').hidden = !data.updateAvailable;
    byId('version-load-message').hidden = true;
    byId('version-meta').hidden = false;
    byId('version-current').textContent = data.version;
    byId('version-code').textContent = String(data.versionCode);
    byId('version-platform').textContent = data.platform || '当前架构暂不查询更新';
    byId('version-checked-at').textContent = data.checkedAt ? new Date(data.checkedAt).toLocaleString() : '尚未检查';
    byId('version-status').textContent = !data.checkEnabled ? '未启用更新检查'
      : data.checkFailed ? '暂时无法检查更新'
        : data.updateAvailable ? `可更新到 ${data.latest.version}`
          : data.latest?.versionCode < data.versionCode ? '当前版本高于已发布版本' : '已是最新版本';
    const error = byId('version-check-error');
    error.hidden = !data.checkFailed;
    error.textContent = data.checkFailed ? `${data.checkError || '查询失败'}。${data.latest ? '下方保留上次成功获取的内容。' : '请稍后重新检查。'}` : '';
    byId('version-latest').hidden = !data.latest;
    byId('version-latest').classList.toggle('has-update', data.updateAvailable);
    if (data.latest) {
      byId('version-latest-title').textContent = data.updateAvailable
        ? (data.latest.forceUpdate ? '重要更新可用' : '发现新版本') : '最新发布日志';
      byId('version-latest-summary').textContent = `v${data.latest.version}${data.latest.version === data.version ? ' · 当前运行版本' : ''}`;
      byId('version-changelog').innerHTML = data.latest.changelogHtml || '<p>此版本暂无更新说明。</p>';
      this.setLink(byId('version-download'), data.latest.downloadUrl);
    }
  },

  toggleHistory() {
    if (byId('version-history').hasAttribute('open') && !this.historyPage) this.loadHistory();
  },

  async loadHistory(page = 1, refresh = false) {
    if (!auth.user) return;
    this.historyController?.abort();
    const controller = new AbortController();
    this.historyController = controller;
    const list = byId('version-history-list');
    const error = byId('version-history-error');
    const paging = byId('version-history-paging');
    const focusedPagingId = paging.contains(document.activeElement) ? document.activeElement.id : null;
    error.hidden = true;
    list.setAttribute('aria-busy', 'true');
    byId('version-history-loading').hidden = false;
    byId('version-history-paging').querySelectorAll('button').forEach(button => { button.disabled = true; });
    try {
      const data = await this.request(`/api/version/history?page=${page}${refresh ? '&refresh=1' : ''}`, controller.signal);
      if (controller !== this.historyController || !auth.user) return;
      this.historyPage = data.page;
      list.replaceChildren();
      for (const item of data.items) {
        const details = document.createElement('details');
        details.className = 'version-history-item';
        const summary = document.createElement('summary');
        summary.textContent = `v${item.version}${item.version === this.info?.version ? ' · 当前运行版本' : ''}`;
        const body = document.createElement('div');
        body.className = 'markdown-content';
        body.innerHTML = item.changelogHtml || '<p>此版本暂无更新说明。</p>';
        details.append(summary, body);
        list.append(details);
      }
      if (!data.total) list.textContent = '尚无已登记的更新日志。';
      byId('version-history-paging').hidden = data.pages <= 1;
      byId('version-history-page').textContent = `${data.page} / ${data.pages} · 共 ${data.total} 个版本`;
      byId('version-history-prev').disabled = data.page <= 1;
      byId('version-history-next').disabled = data.page >= data.pages;
      if (focusedPagingId) {
        const focused = byId(focusedPagingId);
        const fallback = data.page >= data.pages ? byId('version-history-prev') : byId('version-history-next');
        (data.pages <= 1 ? byId('version-history').querySelector('summary') : focused.disabled ? fallback : focused).focus();
      }
    } catch (cause) {
      if (controller !== this.historyController || controller.signal.aborted) return;
      error.hidden = false;
      byId('version-history-error-text').textContent = cause.message;
      byId('version-history-paging').hidden = true;
      if (focusedPagingId) error.querySelector('button').focus();
    } finally {
      if (controller === this.historyController) {
        this.historyController = null;
        list.removeAttribute('aria-busy');
        byId('version-history-loading').hidden = true;
      }
    }
  }
};
