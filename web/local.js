/* Local-only orchestration; no card/device identity, remote calls or storage. */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  let selected = null, job = '', report = null, xhr = null, busy = false, ready = false;
  let epoch = 0, poll = null, timer = null, started = 0;
  let removeReady = false;
  const wheel = window.VRCA_WHEEL.create($('wheel-mount'));
  const stages = {hashing: '核对文件摘要', extracting: '提取模型结构', analyzing: '分析密码与终态',
    deep_read: '补读相关深层结构', deep_analyze: '复核深层分析结果', verifying: '复核原文件未修改',
    planning: '核对安全计划与来源', writing: '生成移除副本', reparsing: '独立复解析与非目标字节核验',
    starting: '启动本地导出组件', loading: '读取模型资源', exporting: '导出工程资源',
    restoring: '恢复工程结构', checking_references: '检查工程引用与依赖', packaging: '生成并校验两个下载包'};
  function error(message) { $('error-text').textContent = message || ''; $('form-error').hidden = !message; }
  function buttons() {
    $('go').disabled = !ready || !selected || busy;
    $('file').disabled = busy;
    $('file-drop').setAttribute('aria-disabled', String(busy));
    $('clear').hidden = !busy && !job;
    $('clear').disabled = !!xhr;
    $('clear').textContent = busy ? '取消并清理' : '清理本次结果';
    $('quit').disabled = !!xhr;
    $('remove').disabled = !ready || !job || busy || !removeReady || !$('remove-confirm').checked;
    $('export').disabled = !ready || !job || busy;
    $('remove-confirm').disabled = busy || !removeReady;
    $('export-source').disabled = busy;
  }
  async function api(path, method = 'GET', requestBody) {
    const response = await fetch(path, {method, headers: {'X-VRCA-Local': '1', ...(requestBody ? {'Content-Type': 'application/json'} : {})},
      body: requestBody ? JSON.stringify(requestBody) : undefined, cache: 'no-store'});
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || '本机请求失败，请重试。');
    return body;
  }
  function choose(file) {
    if (busy) return;
    error(''); selected = null;
    if (file && (!/\.vrca$/i.test(file.name) || file.size < 8 || file.size > 450 * 1024 * 1024)) {
      error('请选择 450 MiB 以内的非空 .vrca 文件。');
    } else selected = file;
    $('file-name').textContent = selected ? selected.name : '尚未选择 VRCA 文件';
    $('file-meta').textContent = selected ? (selected.size / 1048576).toFixed(2) + ' MiB · 仅本机处理' : '点击选择，或拖放到这里';
    buttons();
  }
  function upload(file, current) {
    return new Promise((resolve, reject) => {
      xhr = new XMLHttpRequest(); xhr.open('POST', '/api/analyses'); xhr.timeout = 120000;
      xhr.setRequestHeader('X-VRCA-Local', '1');
      xhr.setRequestHeader('X-File-Name', encodeURIComponent(file.name));
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.upload.onprogress = event => {
        if (current !== epoch) return;
        if (event.lengthComputable) { $('progress').value = Math.round(event.loaded / event.total * 100); }
      };
      xhr.onload = () => {
        try {
          const body = JSON.parse(xhr.responseText);
          if (xhr.status !== 202) throw new Error(body.error || '本机接收文件失败。');
          resolve(body);
        } catch (failure) { reject(failure); }
      };
      xhr.onerror = () => reject(new Error('无法连接本机服务，请确认启动窗口仍在运行。'));
      xhr.ontimeout = () => reject(new Error('本机接收超时，请检查磁盘空间后重试。'));
      xhr.onabort = () => reject(new Error('本次接收已取消。'));
      xhr.send(file);
    }).finally(() => { xhr = null; buttons(); });
  }
  function node(tag, text, className) {
    const value = document.createElement(tag); value.textContent = text;
    if (className) value.className = className; return value;
  }
  function render(data) {
    report = data.report;
    const valid = rows => (Array.isArray(rows) ? rows : []).filter(row => row && typeof row.password === 'string' && row.password.trim());
    let candidates = valid(report.password_candidates);
    if (!candidates.length) candidates = valid(report.results);
    $('high-list').replaceChildren(); $('reference-list').replaceChildren();
    for (const row of candidates) {
      const high = row.confidence === '高' || row.confidence === 'high';
      const li = node('li', '', 'analysis-password-item');
      li.append(node('code', row.password, 'analysis-password-value'));
      li.append(node('p', high ? '高可信候选 · 未经游戏验证' : '参考候选 · ' + (row.confidence || '未标明置信度'), 'analysis-result-hint'));
      for (const key of ['controller', 'parameter', 'note', 'runtime_status']) {
        if (typeof row[key] === 'string' && row[key]) li.append(node('p', row[key], 'analysis-candidate-note'));
      }
      const copy = node('button', '复制候选', 'v-btn v-btn-quiet'); copy.type = 'button';
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(row.password); copy.textContent = '已复制'; }
        catch (_) { copy.textContent = '请选中上方候选手动复制'; }
      });
      li.append(copy); $(high ? 'high-list' : 'reference-list').append(li);
    }
    $('high-group').hidden = !$('high-list').children.length;
    $('reference-group').hidden = !$('reference-list').children.length;
    $('result-summary').textContent = candidates.length ? '发现 ' + candidates.length + ' 个密码候选，请按下方置信度查看。' : '本次未得到密码候选；不代表模型没有密码锁。';
    $('incomplete').hidden = !(report.analysis_incomplete === true || report.analysis_complete === false || report.controller_fail > 0);
    $('features').replaceChildren();
    for (const row of [...(Array.isArray(report.features) ? report.features : []), ...(Array.isArray(report.manual_unlock_candidates) ? report.manual_unlock_candidates : [])]) {
      if (!row) continue;
      for (const key of ['name', 'evidence', 'instructions', 'note']) if (typeof row[key] === 'string') $('features').append(node('p', row[key]));
    }
    if (!$('features').children.length) $('features').append(node('p', '没有附加结构说明。'));
    $('report-output').textContent = JSON.stringify(report, null, 2);
    $('result').hidden = false;
    $('operations').hidden = false;
    removeReady = report.local_writeback && report.local_writeback.available === true;
    $('remove-reason').textContent = removeReady ? '已有可执行计划，勾选确认后生成副本。' : (report.local_writeback && report.local_writeback.reason) || '未得到可安全执行的永久移除计划。';
    buttons();
    $('menu-card').hidden = !data.menu;
    if (data.menu) {
      try { wheel.setData(data.menu, {jobId: job, sourceSha256: report.source_sha256, expiresAt: Date.now() + 600000}); }
      catch (_) { wheel.setError('轮盘数据不完整，不影响上方分析报告。'); }
    }
    $('step-2').classList.remove('is-active'); $('step-3').classList.add('is-active');
  }
  async function monitor(current) {
    if (current !== epoch) return;
    try {
      const status = await api('/api/analyses/' + job);
      if (current !== epoch) return;
      if (status.state === 'done') {
        const data = await api('/api/analyses/' + job + '/result');
        if (current !== epoch) return;
        render(data); finish('分析完成 · 结果保留 10 分钟');
      } else if (status.state === 'failed') throw new Error(status.error || '分析失败，可更换文件重试。');
      else { $('progress-title').textContent = stages[status.stage] || '正在启动本地分析'; poll = setTimeout(() => monitor(current), 800); }
    } catch (failure) { if (current === epoch) { error(failure.message); finish('分析未完成'); } }
  }
  function finish(title) {
    busy = false; clearInterval(timer); $('progress-title').textContent = title;
    $('progress').value = 100; buttons();
  }
  async function clear() {
    if (xhr) return;
    ++epoch; clearTimeout(poll); clearInterval(timer);
    try { if (job) await api('/api/analyses/' + job, 'DELETE'); }
    catch (failure) { error(failure.message); busy = false; buttons(); return; }
    job = ''; report = null; busy = false;
    $('result').hidden = true; $('menu-card').hidden = true; $('progress-card').hidden = true;
    $('operations').hidden = true; $('downloads').replaceChildren(); $('operation-status').textContent = '';
    removeReady = false; $('remove-confirm').checked = false;
    $('export-source').value = 'original'; $('export-source').options[1].disabled = true;
    $('report-output').textContent = ''; $('high-list').replaceChildren(); $('reference-list').replaceChildren(); $('features').replaceChildren();
    wheel.clear(); error(''); buttons();
    for (let i = 1; i <= 3; i++) $('step-' + i).classList.toggle('is-active', i === 1);
  }
  $('analysis-form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy || !ready || !selected) return;
    if (job) { await clear(); if (job) return; }
    const current = ++epoch; busy = true; started = Date.now(); error(''); buttons();
    $('progress-card').hidden = false; $('progress').value = 0; $('progress-title').textContent = '接收文件到本机临时目录';
    $('step-1').classList.remove('is-active'); $('step-2').classList.add('is-active');
    timer = setInterval(() => { const secs = Math.floor((Date.now() - started) / 1000); $('elapsed').textContent = String(Math.floor(secs / 60)).padStart(2, '0') + ':' + String(secs % 60).padStart(2, '0'); }, 1000);
    try {
      const created = await upload(selected, current);
      if (current !== epoch) return;
      job = created.id; $('progress').removeAttribute('value'); buttons(); await monitor(current);
    } catch (failure) { if (current === epoch) { error(failure.message); finish('未完成，可重新选择文件重试'); } }
  });
  $('file').addEventListener('change', () => choose($('file').files[0] || null));
  $('file-drop').addEventListener('click', event => { if (event.target !== $('file') && !busy) $('file').click(); });
  $('file-drop').addEventListener('keydown', event => { if (event.target === $('file-drop') && ['Enter', ' '].includes(event.key)) { event.preventDefault(); if (!busy) $('file').click(); } });
  $('file-drop').addEventListener('dragover', event => { event.preventDefault(); if (!busy) $('file-drop').classList.add('is-dragover'); });
  $('file-drop').addEventListener('dragleave', () => $('file-drop').classList.remove('is-dragover'));
  $('file-drop').addEventListener('drop', event => { event.preventDefault(); $('file-drop').classList.remove('is-dragover'); choose(event.dataTransfer.files[0] || null); });
  $('clear').addEventListener('click', clear);
  $('remove-confirm').addEventListener('change', buttons);
  async function operation(kind) {
    if (busy || !job) return;
    const current = ++epoch; busy = true; error(''); buttons();
    $('operation-status').textContent = '正在提交本机操作…';
    try {
      await api('/api/analyses/' + job + '/' + kind, 'POST', kind === 'remove' ? {confirmed: true} : {source: $('export-source').value});
      await operationMonitor(current);
    } catch (failure) { if (current === epoch) { error(failure.message); busy = false; buttons(); $('operation-status').textContent = '本次操作未完成。'; } }
  }
  async function operationMonitor(current) {
    if (current !== epoch) return;
    try {
      const status = await api('/api/analyses/' + job + '/operation');
      if (current !== epoch) return;
      if (status.state === 'failed') throw new Error(status.error || '本次处理失败，未生成已验证下载。');
      if (status.state !== 'done') {
        $('operation-status').textContent = stages[status.stage] || '本机正在处理，可点击“取消并清理”停止。';
        poll = setTimeout(() => operationMonitor(current), 800); return;
      }
      const data = status.result;
      if (data.kind === 'remove') {
        removeReady = false; $('remove-confirm').checked = false;
        $('export-source').options[1].disabled = false;
        $('remove-reason').textContent = '副本已生成且独立复解析通过，可下载或用于工程导出。';
        $('operation-status').textContent = '永久移除副本已通过离线结构与非目标字节核验；未做游戏实测。';
      } else {
        const c = data.counts || {};
        $('operation-status').textContent = '工程导出完成 · ' + (data.status === 'recovered_data' ? '数据恢复完成' : '仍有缺失依赖或不完整恢复') +
          '；资源 ' + (c.assets || 0) + '，缺失引用 ' + (c.missingReferences || 0) + '，近似 Shader ' + (c.approximateShaders || 0) + '。尚未在 Unity 中导入验证。';
      }
      for (const file of data.artifacts || []) {
        const link = node('a', file.key === 'model' ? '下载永久移除副本' : file.key === 'project' ? '下载 Unity 工程 ZIP' : '下载 unitypackage', 'v-btn');
        link.href = '/api/analyses/' + job + '/downloads/' + file.key; link.download = file.name;
        link.title = 'SHA256: ' + file.sha256; $('downloads').append(link);
      }
      busy = false; buttons();
    } catch (failure) { if (current === epoch) { error(failure.message); busy = false; buttons(); $('operation-status').textContent = '本次操作未完成；不提供未经验证的产物。'; } }
  }
  $('remove').addEventListener('click', () => operation('remove'));
  $('export').addEventListener('click', () => operation('export'));
  $('save').addEventListener('click', () => {
    if (!report) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'}));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'local-analysis.report.json'; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  $('quit').addEventListener('click', async () => {
    if (job && !confirm('退出会停止本地分析并清理临时文件。确定退出？')) return;
    try {
      await api('/api/shutdown', 'POST'); ++epoch; clearTimeout(poll); clearInterval(timer);
      ready = false; busy = false; report = null; job = ''; wheel.clear();
      $('result').hidden = true; $('menu-card').hidden = true; $('progress-card').hidden = true;
      $('operations').hidden = true; $('downloads').replaceChildren();
      $('report-output').textContent = ''; $('high-list').replaceChildren(); $('reference-list').replaceChildren(); $('features').replaceChildren();
      $('connection').textContent = '本地服务已退出'; $('quit').disabled = true; buttons(); $('quit').disabled = true;
    } catch (failure) { error(failure.message); }
  });
  api('/api/health').then(() => { ready = true; $('connection').textContent = '本机服务已就绪'; buttons(); })
    .catch(() => { error('无法连接本机服务，请双击启动程序后重试。'); $('connection').textContent = '本机服务未连接'; });
}());
