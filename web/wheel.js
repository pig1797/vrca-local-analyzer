(function () {
  'use strict';
  var SVG = 'http://www.w3.org/2000/svg';
  var TYPES = ['Button', 'Toggle', 'SubMenu', 'TwoAxisPuppet', 'FourAxisPuppet', 'RadialPuppet', 'Unknown'];
  var WHEEL_SIZE = 420;
  var WHEEL_CENTER = WHEEL_SIZE / 2;
  var WHEEL_OUTER = 198;
  var WHEEL_HUB = 82;
  var WHEEL_ICON_RADIUS = 146;
  var WHEEL_PAGE_SIZE = 16;
  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  }
  function svgElement(tag, attrs, text) {
    var node = document.createElementNS(SVG, tag);
    Object.keys(attrs || {}).forEach(function (key) { node.setAttribute(key, String(attrs[key])); });
    if (text !== undefined) node.textContent = String(text);
    return node;
  }
  function textValue(value, limit) { return typeof value === 'string' ? value.slice(0, limit || 512) : ''; }
  function point(radius, angle) { return [WHEEL_CENTER + radius * Math.cos(angle), WHEEL_CENTER + radius * Math.sin(angle)]; }
  function pair(value) { return value[0].toFixed(3) + ' ' + value[1].toFixed(3); }
  function sectorPath(index, count) {
    if (count <= 1) {
      // SVG treats an arc whose start and end points coincide as empty. The
      // reference emits two half-arcs for the single-item full annulus.
      return 'M ' + (WHEEL_CENTER - WHEEL_OUTER) + ' ' + WHEEL_CENTER +
        ' A ' + WHEEL_OUTER + ' ' + WHEEL_OUTER + ' 0 1 1 ' + (WHEEL_CENTER + WHEEL_OUTER) + ' ' + WHEEL_CENTER +
        ' A ' + WHEEL_OUTER + ' ' + WHEEL_OUTER + ' 0 1 1 ' + (WHEEL_CENTER - WHEEL_OUTER) + ' ' + WHEEL_CENTER +
        ' M ' + (WHEEL_CENTER - WHEEL_HUB) + ' ' + WHEEL_CENTER +
        ' A ' + WHEEL_HUB + ' ' + WHEEL_HUB + ' 0 1 0 ' + (WHEEL_CENTER + WHEEL_HUB) + ' ' + WHEEL_CENTER +
        ' A ' + WHEEL_HUB + ' ' + WHEEL_HUB + ' 0 1 1 ' + (WHEEL_CENTER - WHEEL_HUB) + ' ' + WHEEL_CENTER + ' Z';
    }
    // The reference wheel uses contiguous sectors with no angular gap.
    var start = -Math.PI / 2 - Math.PI / count + index * 2 * Math.PI / count;
    var end = start + 2 * Math.PI / count;
    var large = end - start > Math.PI ? 1 : 0;
    return 'M ' + pair(point(WHEEL_HUB, start)) + ' L ' + pair(point(WHEEL_OUTER, start)) +
      ' A ' + WHEEL_OUTER + ' ' + WHEEL_OUTER + ' 0 ' + large + ' 1 ' + pair(point(WHEEL_OUTER, end)) + ' L ' + pair(point(WHEEL_HUB, end)) +
      ' A ' + WHEEL_HUB + ' ' + WHEEL_HUB + ' 0 ' + large + ' 0 ' + pair(point(WHEEL_HUB, start)) + ' Z';
  }
  function typeGlyph(type) {
    return type === 'SubMenu' ? '☰' : type === 'Toggle' ? '●' : type === 'RadialPuppet' ? '◒' : type === 'TwoAxisPuppet' ? '✣' : type === 'FourAxisPuppet' ? '✥' : type === 'Button' ? '◆' : '?';
  }
  function normalize(dto) {
    if (!dto || dto.ok !== true || dto.schema !== 1 || !Array.isArray(dto.menus) || dto.menus.length > 4096 || !Array.isArray(dto.roots)) throw new Error('菜单数据格式不正确。');
    var menus = Object.create(null);
    var total = 0;
    dto.menus.forEach(function (menu) {
      if (!menu || typeof menu.id !== 'string' || !menu.id || menu.id.length > 128 || Object.prototype.hasOwnProperty.call(menus, menu.id) || !Array.isArray(menu.controls) || menu.controls.length > 128) throw new Error('菜单数据格式不正确。');
      total += menu.controls.length;
      if (total > 32768) throw new Error('菜单控件数量超过预览范围。');
      menus[menu.id] = { id: menu.id, name: textValue(menu.name), controls: menu.controls.map(function (control, index) {
        if (!control || typeof control.id !== 'string') throw new Error('菜单控件格式不正确。');
        return {
          id: control.id.slice(0, 256), name: textValue(control.name) || '未命名控件 ' + (index + 1),
          type: TYPES.indexOf(control.type) >= 0 ? control.type : 'Unknown',
          icon: typeof control.icon === 'string' && /^[A-Za-z0-9_-]{1,128}\.png$/.test(control.icon) ? control.icon : null,
          iconState: ['ready', 'not_provided', 'unavailable', 'not_requested'].indexOf(control.iconState) >= 0 ? control.iconState : null,
          submenu: typeof control.submenu === 'string' ? control.submenu : null,
          parameter: textValue(control.parameter), value: Number.isFinite(control.value) ? control.value : 0,
          subParameters: Array.isArray(control.subParameters) ? control.subParameters.slice(0, 4).map(function (name) { return textValue(name); }) : []
        };
      }) };
    });
    var roots = dto.roots.filter(function (root) { return root && typeof root.id === 'string' && Object.prototype.hasOwnProperty.call(menus, root.id); }).map(function (root) { return { id: root.id, evidence: textValue(root.evidence, 64) }; });
    if (dto.menus.length && (!roots.length || typeof dto.root !== 'string' || !Object.prototype.hasOwnProperty.call(menus, dto.root))) throw new Error('未能确定菜单入口。');
    // Keep the recursive tree bounded to the reference depth (12 levels).
    return { menus: menus, roots: roots, root: dto.root, maxDepth: Math.max(1, Math.min(12, Number(dto.limits && dto.limits.maxDepth) || 12)), rootEvidence: textValue(dto.rootEvidence, 64) };
  }
  function create(container) {
    var ui = {};
    var data = null;
    var jobId = '';
    var expiresAt = 0;
    var rootId = '';
    var currentId = '';
    var currentLabel = '根菜单';
    var stack = [];
    var page = 0;
    var avatarName = '';
    var avatarThumbnail = '';
    var treeOpen = Object.create(null);
    var values = Object.create(null);
    var selectedId = '';
    var sectorNodes = [];
    var renderVersion = 0;
    var searchQuery = '';
    var filterMode = 'all';
    container.textContent = '';
    ui.root = element('div', 'v-wheel');
    container.appendChild(ui.root);
    ui.message = element('p', 'v-wheel-message');
    ui.message.setAttribute('role', 'status');
    ui.message.setAttribute('aria-live', 'polite');
    ui.root.appendChild(ui.message);
    ui.body = element('div'); ui.root.appendChild(ui.body); ui.body.hidden = true;
    var toolbar = element('div', 'v-wheel-toolbar'); ui.body.appendChild(toolbar);
    ui.roots = element('select', 'v-wheel-roots'); ui.roots.setAttribute('aria-label', '选择菜单入口'); toolbar.appendChild(ui.roots);
    ui.back = element('button', 'v-wheel-nav', '← 返回'); ui.back.type = 'button'; toolbar.appendChild(ui.back);
    ui.home = element('button', 'v-wheel-nav', '根菜单'); ui.home.type = 'button'; toolbar.appendChild(ui.home);
    ui.current = element('span', 'v-wheel-current'); toolbar.appendChild(ui.current);
    ui.search = element('input', 'v-wheel-search'); ui.search.type = 'search'; ui.search.placeholder = '搜索当前菜单'; ui.search.setAttribute('aria-label', '搜索当前菜单项'); ui.search.setAttribute('autocomplete', 'off'); toolbar.appendChild(ui.search);
    ui.filter = element('select', 'v-wheel-filter'); ui.filter.setAttribute('aria-label', '筛选菜单项状态');
    [['all', '全部状态'], ['openable', '可打开子菜单'], ['unavailable', '不可预览项']].forEach(function (optionData) {
      var option = element('option', '', optionData[1]); option.value = optionData[0]; ui.filter.appendChild(option);
    });
    toolbar.appendChild(ui.filter);
    ui.legend = element('div', 'v-wheel-legend'); ui.legend.setAttribute('role', 'note'); ui.legend.textContent = '三横杠 = 可打开子菜单 · ! = 图标缺失或尚未提取'; ui.body.appendChild(ui.legend);
    ui.filterStatus = element('p', 'v-wheel-filter-status'); ui.filterStatus.setAttribute('role', 'status'); ui.filterStatus.setAttribute('aria-live', 'polite'); ui.body.appendChild(ui.filterStatus);
    var stage = element('div', 'v-wheel-stage'); ui.body.appendChild(stage);
    ui.svg = svgElement('svg', { viewBox: '0 0 ' + WHEEL_SIZE + ' ' + WHEEL_SIZE, class: 'v-wheel-svg', role: 'group', 'aria-label': '模型菜单轮盘' }); stage.appendChild(ui.svg);
    ui.tree = element('div', 'v-wheel-tree'); ui.tree.setAttribute('aria-label', '菜单树'); ui.body.appendChild(ui.tree);
    ui.iconNote = element('p', 'v-wheel-icon-note'); ui.iconNote.hidden = true; ui.iconNote.setAttribute('role', 'status'); ui.iconNote.setAttribute('aria-live', 'polite'); ui.body.appendChild(ui.iconNote);
    ui.paging = element('div', 'v-wheel-page'); ui.body.appendChild(ui.paging);
    ui.previous = element('button', 'v-wheel-nav', '上一页'); ui.previous.type = 'button'; ui.paging.appendChild(ui.previous);
    ui.page = element('span'); ui.paging.appendChild(ui.page);
    ui.next = element('button', 'v-wheel-nav', '下一页'); ui.next.type = 'button'; ui.paging.appendChild(ui.next);
    ui.body.appendChild(element('p', 'v-wheel-keyboard', '方向键选择 · Enter 确认 · Esc 返回'));
    ui.selected = element('div', 'v-wheel-selected'); ui.selected.hidden = true; ui.body.appendChild(ui.selected);
    ui.selectedTitle = element('p', 'v-wheel-selected-title'); ui.selected.appendChild(ui.selectedTitle);
    ui.selectedNote = element('p', 'v-wheel-selected-note'); ui.selectedNote.setAttribute('aria-live', 'polite'); ui.selected.appendChild(ui.selectedNote);
    ui.sliders = element('div', 'v-wheel-sliders'); ui.selected.appendChild(ui.sliders);
    function expired() { return expiresAt > 0 && Date.now() >= expiresAt; }
    function message(text) { ui.message.textContent = text; }
    function expire() {
      renderVersion += 1; data = null; ui.svg.textContent = ''; ui.body.hidden = true; sectorNodes = [];
      message('任务已过期，菜单与图标已清理，请重新上传模型。');
    }
    function ensureActive() { if (expired()) { expire(); return false; } return !!data; }
    function setFilters(query, mode) {
      searchQuery = query; filterMode = mode; ui.search.value = query; ui.filter.value = mode;
    }
    function resetFilters() { setFilters('', 'all'); }
    function showSelected(title, note) {
      ui.selected.hidden = false; ui.selectedTitle.textContent = title; ui.selectedNote.textContent = note; ui.sliders.textContent = '';
    }
    function markSelection() {
      sectorNodes.forEach(function (node) { node.classList.toggle('is-selected', node.getAttribute('data-control') === selectedId); });
    }
    function renderTree() {
      ui.tree.textContent = '';
      if (!data || !data.menus[rootId]) { ui.tree.hidden = true; return; }
      ui.tree.hidden = false;
      ui.tree.appendChild(element('div', 'v-wheel-tree-heading', '菜单结构'));
      var list = element('div', 'v-wheel-tree-list'); ui.tree.appendChild(list);
      var visited = Object.create(null);
      function addMenu(menuId, depth, host) {
        if (visited[menuId] || !data.menus[menuId] || depth > data.maxDepth) return;
        visited[menuId] = true;
        data.menus[menuId].controls.forEach(function (control) {
          var row = element('div', 'v-wheel-tree-row' + (currentId === menuId && selectedId === control.id ? ' is-selected' : ''));
          var button = element('button', 'v-wheel-tree-item'); button.type = 'button'; button.title = control.name;
          button.appendChild(element('span', 'v-wheel-tree-icon', typeGlyph(control.type)));
          button.appendChild(element('span', 'v-wheel-tree-label', control.name));
          var child = control.submenu && data.menus[control.submenu] ? element('span', 'v-wheel-tree-arrow', treeOpen[control.submenu] ? '⌄' : '›') : element('span', 'v-wheel-tree-arrow', '');
          button.appendChild(child); row.appendChild(button); host.appendChild(row);
          if (control.submenu && data.menus[control.submenu]) {
            button.classList.add('is-expandable');
            button.addEventListener('click', function () { treeOpen[control.submenu] = !treeOpen[control.submenu]; activate(control); });
            if (treeOpen[control.submenu] || currentId === control.submenu) {
              var nested = element('div', 'v-wheel-tree-children'); row.appendChild(nested); addMenu(control.submenu, depth + 1, nested);
            }
          } else button.addEventListener('click', function () { activate(control); });
        });
        delete visited[menuId];
      }
      addMenu(rootId, 0, list);
    }
    function canOpen(control) {
      return control.type === 'SubMenu' && !!control.submenu && !!data.menus[control.submenu];
    }
    function controlState(control) {
      if (canOpen(control)) return 'openable';
      if (control.type === 'Unknown' || control.type === 'SubMenu') return 'unavailable';
      return 'interactive';
    }
    function matchesControl(control) {
      var state = controlState(control);
      if (filterMode === 'openable' && state !== 'openable') return false;
      if (filterMode === 'unavailable' && state !== 'unavailable') return false;
      var query = searchQuery.trim().toLocaleLowerCase();
      if (!query) return true;
      return (control.name + ' ' + control.type + ' ' + control.parameter + ' ' + control.subParameters.join(' ')).toLocaleLowerCase().indexOf(query) >= 0;
    }
    function visibleControls(menu) { return menu.controls.filter(matchesControl); }
    function wheelItems(menu, visible) {
      var first = stack.length ? { key: '__back__', name: '返回', kind: 'back', control: null } : { key: '__avatar__', name: avatarName || '模型菜单', kind: 'avatar', control: null };
      return [first].concat(visible.map(function (control, index) { return { key: currentId + ':' + index + ':' + control.id, name: control.name, kind: 'control', control: control }; }));
    }
    function updateFilterStatus(menu, visible) {
      var openable = menu.controls.filter(function (control) { return controlState(control) === 'openable'; }).length;
      var unavailable = menu.controls.filter(function (control) { return controlState(control) === 'unavailable'; }).length;
      var suffix = searchQuery.trim() ? ' · 搜索“' + searchQuery.trim().slice(0, 32) + '”' : '';
      ui.filterStatus.textContent = '当前分支 ' + visible.length + '/' + menu.controls.length + ' 项 · 可打开 ' + openable + ' · 不可预览 ' + unavailable + suffix + '。图标仅在当前分支页面加载。';
    }
    function iconStateBadge(g, pos, state, hidden) {
      var marker = svgElement('g', { class: 'v-wheel-icon-state', transform: 'translate(' + (pos[0] + 21) + ' ' + (pos[1] - 33) + ')', 'aria-hidden': 'true' });
      if (hidden) marker.setAttribute('visibility', 'hidden');
      marker.appendChild(svgElement('circle', { cx: '0', cy: '0', r: '9', class: 'v-wheel-icon-state-bg' }));
      marker.appendChild(svgElement('text', { x: '0', y: '4', class: 'v-wheel-icon-state-text' }, '!'));
      marker.appendChild(svgElement('title', {}, state === 'not_requested' ? '图标尚未提取' : '图标不可用，已使用控件符号'));
      g.appendChild(marker);
      return marker;
    }
    function activate(control) {
      if (!ensureActive()) return;
      if (control.type === 'SubMenu') {
        if (!control.submenu || !data.menus[control.submenu]) { showSelected(control.name, '此子菜单未能解析，未模拟任何效果。'); return; }
        if (stack.length >= data.maxDepth) { showSelected(control.name, '菜单层级达到预览上限，请回到根菜单继续浏览。'); return; }
        stack.push({ id: currentId, page: page, label: currentLabel, searchQuery: searchQuery, filterMode: filterMode }); currentId = control.submenu; currentLabel = control.name; page = 0; selectedId = ''; resetFilters(); render(); return;
      }
      selectedId = control.id; markSelection();
      if (control.type === 'Unknown') { showSelected(control.name, '此控件类型暂不支持交互预览。'); return; }
      var parameter = control.parameter || '(无参数名)';
      if (control.type === 'Button' || control.type === 'Toggle') {
        var key = control.parameter || control.id;
        values[key] = control.type === 'Toggle' && values[key] === control.value ? 0 : control.value;
        showSelected(control.name, '网页模拟：' + parameter + ' = ' + values[key] + (control.type === 'Button' ? '（按钮按下预览）' : '（开关预览）'));
        return;
      }
      showSelected(control.name, '仅模拟下列参数，不执行模型动画或网络同步。');
      var count = control.type === 'RadialPuppet' ? 1 : (control.type === 'TwoAxisPuppet' ? 2 : 4);
      for (var i = 0; i < count; i += 1) {
        (function (axis) {
          var name = control.subParameters[axis] || (count === 1 ? control.parameter : '') || '参数 ' + (axis + 1);
          var row = element('label', 'v-wheel-slider'); row.appendChild(element('span', '', name));
          var range = element('input'); range.type = 'range'; range.min = control.type === 'TwoAxisPuppet' ? '-1' : '0'; range.max = '1'; range.step = '.01'; range.value = '0'; range.setAttribute('aria-label', name + '，仅网页模拟'); row.appendChild(range);
          var output = element('output', '', '0.00'); row.appendChild(output);
          range.addEventListener('input', function () { if (!ensureActive()) return; var n = Number(range.value); output.textContent = Number.isFinite(n) ? n.toFixed(2) : '0.00'; });
          ui.sliders.appendChild(row);
        })(i);
      }
    }
    function goBack() {
      if (!ensureActive() || !stack.length) return;
      var previous = stack.pop(); currentId = previous.id; currentLabel = previous.label; page = previous.page; selectedId = ''; setFilters(previous.searchQuery, previous.filterMode); render();
    }
    function goHome() { if (!ensureActive()) return; currentId = rootId; currentLabel = '根菜单'; stack = []; page = 0; selectedId = ''; resetFilters(); render(); }
    function render() {
      if (!ensureActive()) return;
      var menu = data.menus[currentId];
      if (!menu) return;
      ui.body.hidden = false; ui.svg.textContent = ''; ui.selected.hidden = true;
      var defs = svgElement('defs', {});
      var wheelGradient = svgElement('radialGradient', { id: 'v-wheel-gradient', cx: '50%', cy: '50%', r: '50%' });
      wheelGradient.appendChild(svgElement('stop', { offset: '35%', 'stop-color': '#0c3236' }));
      wheelGradient.appendChild(svgElement('stop', { offset: '75%', 'stop-color': '#092529' }));
      wheelGradient.appendChild(svgElement('stop', { offset: '100%', 'stop-color': '#06181a' }));
      var hubGradient = svgElement('radialGradient', { id: 'v-hub-gradient', cx: '50%', cy: '50%', r: '50%' });
      hubGradient.appendChild(svgElement('stop', { offset: '0%', 'stop-color': '#0c2c30' }));
      hubGradient.appendChild(svgElement('stop', { offset: '100%', 'stop-color': '#06181a' }));
      defs.appendChild(wheelGradient); defs.appendChild(hubGradient); ui.svg.appendChild(defs);
      ui.svg.appendChild(svgElement('circle', { class: 'v-wheel-outer-ring', cx: WHEEL_CENTER, cy: WHEEL_CENTER, r: WHEEL_OUTER, fill: 'url(#v-wheel-gradient)' }));
      ui.svg.appendChild(svgElement('circle', { class: 'v-wheel-inner-ring', cx: WHEEL_CENTER, cy: WHEEL_CENTER, r: WHEEL_OUTER - 1.5 }));
      ui.current.textContent = menu.name || currentLabel || '未命名菜单'; ui.back.disabled = stack.length === 0;
      ui.home.disabled = currentId === rootId && stack.length === 0;
      var visible = visibleControls(menu);
      updateFilterStatus(menu, visible);
      var allItems = wheelItems(menu, visible);
      var pages = Math.max(1, Math.ceil(allItems.length / WHEEL_PAGE_SIZE)); page = Math.min(page, pages - 1);
      ui.paging.hidden = pages === 1; ui.previous.disabled = page === 0; ui.next.disabled = page >= pages - 1; ui.page.textContent = (page + 1) + ' / ' + pages;
      var controls = allItems.slice(page * WHEEL_PAGE_SIZE, page * WHEEL_PAGE_SIZE + WHEEL_PAGE_SIZE); sectorNodes = [];
      var version = ++renderVersion;
      var iconFailures = Object.create(null);
      function showIconStatus() {
        if (version !== renderVersion) return;
        var count = Object.keys(iconFailures).length;
        ui.iconNote.hidden = count === 0;
        ui.iconNote.textContent = count ? count + ' 个图标暂时不可用，已显示控件符号；菜单仍可操作。' : '';
      }
      message(!menu.controls.length ? '此菜单没有控件；这不代表模型无锁。' : (!visible.length ? '当前筛选没有匹配项，请调整搜索或状态筛选。' : (data.rootEvidence === 'avatar_descriptor' ? '' : '菜单入口依据实际菜单引用关系推定。')));
      controls.forEach(function (item, index) {
        var control = item.control;
        var hasSubmenu = item.kind === 'back' || (control && canOpen(control));
        var status = control ? controlState(control) : 'synthetic';
        var labelText = item.name || '';
        var g = svgElement('g', { class: 'v-wheel-sector is-' + status + (item.kind !== 'control' ? ' is-' + item.kind : ''), role: 'button', tabindex: '0', 'aria-label': labelText + '，' + (item.kind === 'back' ? '返回上级菜单' : (item.kind === 'avatar' ? '模型菜单入口' : (hasSubmenu ? '可打开子菜单' : (status === 'unavailable' ? '不可预览项' : control.type)))), 'data-control': control ? control.id : '', 'data-kind': item.kind, 'data-openable': hasSubmenu ? 'true' : 'false', 'data-control-state': status });
        g.appendChild(svgElement('title', {}, labelText));
        g.appendChild(svgElement('path', { class: 'v-wheel-sector-shape', d: sectorPath(index, controls.length), 'stroke-width': controls.length > 1 ? '2' : '0' }));
        var pos = point(WHEEL_ICON_RADIUS, -Math.PI / 2 + index * 2 * Math.PI / controls.length);
        var visuals = svgElement('g', { class: 'v-wheel-item-visual' });
        g.appendChild(visuals);
        function setItemScale(scale) {
          visuals.setAttribute('transform', 'translate(' + pos[0].toFixed(3) + ' ' + pos[1].toFixed(3) + ') scale(' + scale + ') translate(' + (-pos[0]).toFixed(3) + ' ' + (-pos[1]).toFixed(3) + ')');
        }
        setItemScale(1);
        var fallbackTile = svgElement('rect', { class: 'v-wheel-fallback-tile', x: pos[0] - 25, y: pos[1] - 40, width: '50', height: '50', rx: '10' });
        visuals.appendChild(fallbackTile);
        var fallback = svgElement('text', { class: 'v-wheel-symbol', x: pos[0], y: pos[1] - 8 }, item.kind === 'back' ? '↩' : (item.kind === 'avatar' ? '◉' : (control.type === 'SubMenu' ? '▦' : (control.type === 'Toggle' ? '◉' : '◇'))));
        visuals.appendChild(fallback);
        var missingIconMarker = null;
        if (item.kind === 'avatar' && avatarThumbnail && /^(data:image\/|\/)/.test(avatarThumbnail)) {
          var avatarIcon = svgElement('image', { class: 'v-wheel-icon', x: pos[0] - 25, y: pos[1] - 40, width: '52', height: '52', preserveAspectRatio: 'xMidYMid slice', href: avatarThumbnail });
          avatarIcon.addEventListener('load', function () { if (version !== renderVersion) return; fallback.setAttribute('visibility', 'hidden'); });
          avatarIcon.addEventListener('error', function () { if (version !== renderVersion) return; avatarIcon.removeAttribute('href'); fallback.removeAttribute('visibility'); });
          visuals.appendChild(avatarIcon);
        } else if (control && control.icon) {
          g.setAttribute('data-icon-status', 'loading');
          var icon = svgElement('image', { class: 'v-wheel-icon', x: pos[0] - 25, y: pos[1] - 40, width: '52', height: '52', preserveAspectRatio: 'xMidYMid meet', href: '/api/jobs/' + encodeURIComponent(jobId) + '/icons/' + encodeURIComponent(control.icon) });
          missingIconMarker = iconStateBadge(visuals, pos, 'loading', true);
          icon.addEventListener('load', function () { if (version !== renderVersion) return; fallback.setAttribute('visibility', 'hidden'); g.setAttribute('data-icon-status', 'ready'); });
          icon.addEventListener('error', function () { if (version !== renderVersion) return; icon.removeAttribute('href'); fallback.removeAttribute('visibility'); g.setAttribute('data-icon-status', 'unavailable'); if (missingIconMarker) missingIconMarker.setAttribute('visibility', 'visible'); iconFailures[control.id] = true; showIconStatus(); });
          visuals.appendChild(icon);
        } else if (control && (control.iconState === 'unavailable' || control.iconState === 'not_requested')) {
          g.setAttribute('data-icon-status', control.iconState); iconFailures[control.id] = true; iconStateBadge(visuals, pos, control.iconState, false);
        }
        var labelChars = Array.from(labelText);
        var label = labelChars.slice(0, 18);
        if (labelChars.length > 18) label[17] = label[17] + '…';
        var labelNode = svgElement('text', { class: 'v-wheel-label', x: pos[0], y: pos[1] + 24 });
        labelNode.appendChild(svgElement('tspan', { x: pos[0], dy: '0' }, label.slice(0, 9).join('')));
        if (label.length > 9) labelNode.appendChild(svgElement('tspan', { x: pos[0], dy: '14' }, label.slice(9).join('')));
        visuals.appendChild(labelNode);
        if (control && hasSubmenu) {
          // The reference uses a clean list glyph: three dots and three
          // short lines, without a surrounding badge.
          var marker = svgElement('g', { class: 'v-wheel-submenu-marker', transform: 'translate(' + (pos[0] + 17) + ' ' + (pos[1] - 8) + ')', 'aria-hidden': 'true' });
          marker.appendChild(svgElement('path', { d: 'M6 3H18 M6 9H18 M6 15H18', class: 'v-wheel-submenu-marker-lines' }));
          [3, 9, 15].forEach(function (y) { marker.appendChild(svgElement('circle', { cx: '2', cy: y, r: '1.8', class: 'v-wheel-submenu-marker-dot' })); });
          marker.appendChild(svgElement('title', {}, '列表标记：可打开子菜单'));
          visuals.appendChild(marker);
        } else if (control && item.kind === 'control' && status !== 'unavailable') {
          // Supported leaf controls get the hollow right-facing triangle
          // used by the reference for a non-expandable action.
          var leafMarker = svgElement('g', { class: 'v-wheel-non-submenu-marker', transform: 'translate(' + (pos[0] + 18) + ' ' + (pos[1] - 7) + ')', 'aria-hidden': 'true' });
          leafMarker.appendChild(svgElement('path', { d: 'M1 1 L1 17 L14 9 Z', class: 'v-wheel-non-submenu-marker-shape' }));
          leafMarker.appendChild(svgElement('title', {}, '三角标记：不可打开子菜单'));
          visuals.appendChild(leafMarker);
        }
        if (status === 'unavailable') g.classList.add('is-unavailable');
        g.addEventListener('mouseenter', function () { setItemScale(1.08); });
        g.addEventListener('mouseleave', function () { setItemScale(1); });
        g.addEventListener('focus', function () { setItemScale(1.08); });
        g.addEventListener('blur', function () { setItemScale(1); });
        g.addEventListener('click', function () { if (item.kind === 'back') goBack(); else if (control) activate(control); });
        g.addEventListener('keydown', function (event) {
          if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); if (item.kind === 'back') goBack(); else if (control) activate(control); }
          else if (event.key === 'Escape' || event.key === 'Backspace') { event.preventDefault(); goBack(); }
          else if (['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].indexOf(event.key) >= 0) {
            event.preventDefault(); var delta = event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 1; var next = sectorNodes[(index + delta + sectorNodes.length) % sectorNodes.length]; if (next) next.focus();
          }
        });
        sectorNodes.push(g); ui.svg.appendChild(g);
      });
      showIconStatus();
      ui.svg.appendChild(svgElement('circle', { class: 'v-wheel-hub', cx: WHEEL_CENTER, cy: WHEEL_CENTER, r: WHEEL_HUB, fill: 'url(#v-hub-gradient)' }));
      // Match the reference's nested center rings (82, 70, 56, 42).
      [WHEEL_HUB - 12, WHEEL_HUB - 26, WHEEL_HUB - 40, WHEEL_HUB - 52].forEach(function (radius, index) {
        ui.svg.appendChild(svgElement('circle', { class: 'v-wheel-hub-ring v-wheel-hub-ring-' + index, cx: WHEEL_CENTER, cy: WHEEL_CENTER, r: radius }));
      });
      renderTree();
      markSelection();
    }
    ui.back.addEventListener('click', goBack); ui.home.addEventListener('click', goHome);
    ui.previous.addEventListener('click', function () { if (!ensureActive() || page <= 0) return; page -= 1; render(); });
    ui.next.addEventListener('click', function () { if (!ensureActive() || (page + 1) * WHEEL_PAGE_SIZE >= wheelItems(data.menus[currentId], visibleControls(data.menus[currentId])).length) return; page += 1; render(); });
    ui.roots.addEventListener('change', function () { if (!ensureActive() || !data.menus[ui.roots.value]) return; rootId = ui.roots.value; currentId = rootId; currentLabel = '根菜单'; stack = []; page = 0; selectedId = ''; resetFilters(); render(); });
    ui.search.addEventListener('input', function () { if (!ensureActive()) return; searchQuery = String(ui.search.value || '').slice(0, 80); page = 0; selectedId = ''; render(); });
    ui.filter.addEventListener('change', function () { if (!ensureActive()) return; filterMode = ['all', 'openable', 'unavailable'].indexOf(ui.filter.value) >= 0 ? ui.filter.value : 'all'; ui.filter.value = filterMode; page = 0; selectedId = ''; render(); });
    return {
      clear: function () { renderVersion += 1; data = null; jobId = ''; expiresAt = 0; avatarName = ''; avatarThumbnail = ''; treeOpen = Object.create(null); values = Object.create(null); resetFilters(); ui.body.hidden = true; ui.svg.textContent = ''; ui.tree.textContent = ''; message(''); },
      setLoading: function () { renderVersion += 1; data = null; ui.body.hidden = true; message('正在读取模型菜单与图标……'); },
      setError: function (text) { renderVersion += 1; data = null; ui.body.hidden = true; ui.svg.textContent = ''; message(text || '菜单预览暂时不可用，不影响已有分析结果。'); },
      expire: expire,
      setExpiry: function (value) { if (Number.isFinite(value)) expiresAt = value; },
      setData: function (dto, options) {
        options = options || {};
        if (typeof options.jobId !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(options.jobId)) throw new Error('任务编号无效。');
        if (options.sourceSha256 && dto.source_sha256 !== options.sourceSha256) throw new Error('菜单与当前模型不匹配。');
        data = normalize(dto); jobId = options.jobId; expiresAt = Number(options.expiresAt) || 0; avatarName = textValue(options.avatarName, 96); avatarThumbnail = typeof options.avatarThumbnail === 'string' ? options.avatarThumbnail.slice(0, 2048) : ''; rootId = data.root; currentId = rootId; currentLabel = '根菜单'; stack = []; page = 0; selectedId = ''; treeOpen = Object.create(null); treeOpen[rootId] = true; values = Object.create(null); resetFilters();
        ui.roots.textContent = '';
        data.roots.forEach(function (root, index) { var option = element('option', '', data.menus[root.id].name || '菜单入口 ' + (index + 1)); option.value = root.id; ui.roots.appendChild(option); });
        ui.roots.hidden = data.roots.length <= 1; ui.roots.value = rootId || '';
        if (!Object.keys(data.menus).length) { ui.body.hidden = true; message('未发现可预览菜单；这不代表模型无锁。'); return; }
        render();
      }
    };
  }
  window.VRCA_WHEEL = { create: create };
}());
