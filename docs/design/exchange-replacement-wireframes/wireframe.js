(function () {
  'use strict';

  var root = document.documentElement;
  var currentLocale = root.dataset.locale || 'en-US';
  var validViews = ['overview', 'assessments', 'outcomes', 'mappings', 'documents', 'settings'];
  var currentView = 'overview';
  var currentState = root.dataset.state || 'partial';

  var stateCopy = {
    'en-US': {
      loading: { title: 'Loading', copy: 'Headings, filters, and project context remain in place while the selected run is loading.', action: 'Open assessments', icon: '…' },
      empty: { title: 'Empty', copy: 'No assessment yet. Start a least-privilege preflight; A0 files are reference-only and never importable.', action: 'Start preflight', icon: '—' },
      error: { title: 'Error', copy: 'Collection failed at diagnostic ERX-204. Retry is safe from the durable checkpoint; the prior receipt remains immutable.', action: 'Review error', icon: '×' },
      ready: { title: 'Ready', copy: 'Evidence and mappings are current for the selected support cell. The claim still remains bounded by its named outcomes.', action: 'View outcomes', icon: '✓' },
      partial: { title: 'Partial', copy: '421 of 438 expected probe results are terminal; blocker claims stay closed until the denominator is complete.', action: 'Open recovery steps', icon: '!' },
      stale: { title: 'Stale', copy: 'The registry digest changed after capture. Regenerate evidence before publishing; the last valid artifact remains available.', action: 'Open documents', icon: '↻' },
      permission: { title: 'Permission denied', copy: 'This action requires migration.assessment.decide or a fresh owner authority. The route remains visible with a typed recovery path.', action: 'Open permissions', icon: '⊘' }
    },
    'zh-CN': {
      loading: { title: '加载中', copy: '加载当前运行时保留标题、筛选器和项目上下文。', action: '打开评估', icon: '…' },
      empty: { title: '空状态', copy: '尚未有评估。请开始最小权限预检；A0 文件仅供参考，永远不可导入。', action: '开始预检', icon: '—' },
      error: { title: '错误', copy: '采集在诊断 ERX-204 处失败。可以从持久检查点安全重试；之前的收据保持不可变。', action: '查看错误', icon: '×' },
      ready: { title: '就绪', copy: '当前支持单元的证据和映射均为最新。声明仍受命名结果范围限制。', action: '查看结果', icon: '✓' },
      partial: { title: '部分完成', copy: '438 个预期探针结果中有 421 个已终止；分母完成前，阻塞声明保持关闭。', action: '打开恢复步骤', icon: '!' },
      stale: { title: '过期', copy: '采集后注册表摘要发生变化。发布前请重新生成证据；上个有效工件仍可用。', action: '打开文档', icon: '↻' },
      permission: { title: '无权限', copy: '此操作需要 migration.assessment.decide 或新的负责人授权。路由保持可见，并提供类型化恢复路径。', action: '打开权限', icon: '⊘' }
    }
  };

  function localeKey() {
    return currentLocale === 'zh-CN' ? 'zh-CN' : 'en-US';
  }

  function applyLocale() {
    root.dataset.locale = currentLocale;
    root.lang = currentLocale;

    document.querySelectorAll('[data-en][data-zh]').forEach(function (element) {
      element.textContent = currentLocale === 'zh-CN' ? element.dataset.zh : element.dataset.en;
    });

    document.querySelectorAll('[data-aria-en][data-aria-zh]').forEach(function (element) {
      element.setAttribute('aria-label', currentLocale === 'zh-CN' ? element.dataset.ariaZh : element.dataset.ariaEn);
    });

    document.querySelectorAll('.locale-button').forEach(function (button) {
      var active = button.dataset.localeChoice === currentLocale;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', String(active));
    });

    updateStateSample();
    updateMobileLabels();
  }

  function updateMobileLabels() {
    var select = document.getElementById('mobile-view-select');
    if (select) select.value = currentView;
  }

  function selectView(view, pushHistory) {
    if (validViews.indexOf(view) === -1) view = 'overview';
    currentView = view;

    document.querySelectorAll('[data-view]').forEach(function (section) {
      var active = section.dataset.view === view;
      section.classList.toggle('is-visible', active);
      section.hidden = !active;
    });

    document.querySelectorAll('[data-view-target]').forEach(function (button) {
      var active = button.dataset.viewTarget === view;
      button.classList.toggle('is-active', active);
      if (active) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    });

    updateMobileLabels();
    if (pushHistory && window.location.hash !== '#' + view) {
      window.history.pushState({ view: view }, '', '#' + view);
    }
  }

  function updateStateSample() {
    var copy = stateCopy[localeKey()][currentState];
    var sample = document.getElementById('state-sample');
    var title = document.getElementById('state-sample-title');
    var description = document.getElementById('state-sample-copy');
    var action = document.getElementById('state-sample-action');
    var icon = document.getElementById('state-sample-icon');
    var announcement = document.getElementById('state-announcement');

    root.dataset.state = currentState;
    if (sample) sample.dataset.state = currentState;
    if (title) title.textContent = copy.title;
    if (description) description.textContent = copy.copy;
    if (action) action.textContent = copy.action;
    if (icon) icon.textContent = copy.icon;

    document.querySelectorAll('[data-state-choice]').forEach(function (button) {
      var active = button.dataset.stateChoice === currentState;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', String(active));
    });

    if (announcement) announcement.textContent = (currentLocale === 'zh-CN' ? '状态示例已切换：' : 'State example changed: ') + copy.title;
  }

  function openNavigation() {
    var sidebar = document.getElementById('sidebar');
    var scrim = document.getElementById('mobile-scrim');
    var menu = document.getElementById('mobile-menu');
    if (!sidebar || !scrim || !menu) return;
    sidebar.classList.add('is-open');
    scrim.hidden = false;
    menu.setAttribute('aria-expanded', 'true');
  }

  function closeNavigation() {
    var sidebar = document.getElementById('sidebar');
    var scrim = document.getElementById('mobile-scrim');
    var menu = document.getElementById('mobile-menu');
    if (!sidebar || !scrim || !menu) return;
    sidebar.classList.remove('is-open');
    scrim.hidden = true;
    menu.setAttribute('aria-expanded', 'false');
  }

  document.querySelectorAll('[data-locale-choice]').forEach(function (button) {
    button.addEventListener('click', function () {
      currentLocale = button.dataset.localeChoice;
      applyLocale();
    });
  });

  document.querySelectorAll('[data-view-target]').forEach(function (button) {
    button.addEventListener('click', function () {
      selectView(button.dataset.viewTarget, true);
      closeNavigation();
    });
  });

  document.querySelectorAll('[data-go-view]').forEach(function (button) {
    button.addEventListener('click', function () {
      selectView(button.dataset.goView, true);
      document.getElementById('main-content').focus({ preventScroll: true });
    });
  });

  document.querySelectorAll('[data-state-choice]').forEach(function (button) {
    button.setAttribute('aria-pressed', String(button.dataset.stateChoice === currentState));
    button.addEventListener('click', function () {
      currentState = button.dataset.stateChoice;
      updateStateSample();
    });
  });

  var stateAction = document.getElementById('state-sample-action');
  if (stateAction) {
    stateAction.addEventListener('click', function () {
      var target = { loading: 'assessments', empty: 'assessments', error: 'assessments', ready: 'outcomes', partial: 'assessments', stale: 'documents', permission: 'settings' }[currentState];
      selectView(target, true);
    });
  }

  var mobileSelect = document.getElementById('mobile-view-select');
  if (mobileSelect) mobileSelect.addEventListener('change', function () { selectView(mobileSelect.value, true); });

  var menuButton = document.getElementById('mobile-menu');
  var scrim = document.getElementById('mobile-scrim');
  if (menuButton) menuButton.addEventListener('click', openNavigation);
  if (scrim) scrim.addEventListener('click', closeNavigation);

  window.addEventListener('hashchange', function () { selectView(window.location.hash.slice(1), false); });
  window.addEventListener('popstate', function () { selectView(window.location.hash.slice(1), false); });
  document.addEventListener('keydown', function (event) { if (event.key === 'Escape') closeNavigation(); });

  applyLocale();
  selectView(window.location.hash.slice(1) || 'overview', false);
}());
