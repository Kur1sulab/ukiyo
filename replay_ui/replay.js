/* 浮世 Ukiyo · 诱捕回放 —— 只读前端（无依赖，原生 JS）
 * 数据全部来自后端 /api/*（后端只读 runs/ 账本，判定用蜜罐同一份 server_verdict 复算）。
 * 主题只有黑/白两套；枚举中文映射统一取 /api/meta，前端不另写死。
 */
'use strict';

const $ = (id) => document.getElementById(id);
const S = {
  meta: null, runs: [], run: null, sessions: [], sid: null, detail: null,
  filter: 'ALL', cursor: -1, playing: false, timer: null, speed: 4,
  tab: 'replay', dossierCache: {}, lastError: null,
};
const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ---------------- 工具 ---------------- */
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}
async function api(path) {
  const r = await fetch(path, { headers: { Accept: 'application/json' } });
  if (!r.ok) {
    let msg = 'HTTP ' + r.status;
    try { msg = (await r.json()).error || msg; } catch (e) { /* 保留默认 */ }
    throw new Error(msg);
  }
  return r.json();
}
function hhmmss(t) {
  if (!t || typeof t !== 'string') return '—';
  const m = t.match(/(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : t;
}
function toneOf(verdict) {
  return (S.meta && S.meta.verdict_tone[verdict]) || 'none';
}
function vzh(verdict) {
  return (S.meta && S.meta.verdict_zh[verdict]) || verdict || '未接触';
}
function showErr(msg, retryFn) {
  S.lastError = retryFn || null;
  $('err-msg').textContent = '读取失败：' + msg;
  $('err-banner').hidden = false;
}
function hideErr() { $('err-banner').hidden = true; }
function announce(msg) { $('live').textContent = msg; }

/* ---------------- 主题（仅黑/白） ---------------- */
function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('ukiyo-replay-theme', t); } catch (e) { /* 隐私模式忽略 */ }
  $('theme-dark').setAttribute('aria-pressed', String(t === 'dark'));
  $('theme-light').setAttribute('aria-pressed', String(t === 'light'));
}
$('theme-dark').addEventListener('click', () => setTheme('dark'));
$('theme-light').addEventListener('click', () => setTheme('light'));
setTheme(document.documentElement.getAttribute('data-theme') || 'light');

/* ---------------- 启动 ---------------- */
async function boot() {
  try {
    S.meta = await api('/api/meta');
    if (S.meta.version) {
      const v = $('ver');
      v.textContent = 'v' + S.meta.version;
      v.title = S.meta.product + ' v' + S.meta.version + ' · 只读 · 仅 ' + S.meta.bind;
      v.hidden = false;
    }
    const data = await api('/api/runs');
    S.runs = data.runs || [];
    const sel = $('run-select');
    sel.innerHTML = S.runs.map((r) =>
      `<option value="${esc(r.id)}">${esc(r.label)}（${r.n_sessions} 会话）</option>`
    ).join('');
    if (!S.runs.length) {
      $('run-stats').textContent = 'runs/ 下没有账本。';
      return;
    }
    const hash = parseHash();
    const want = hash.run || (S.runs.find((r) => r.id === 'stress-100-final') || S.runs[0]).id;
    sel.value = S.runs.some((r) => r.id === want) ? want : S.runs[0].id;
    sel.addEventListener('change', () => { stopPlay(); loadRun(sel.value); });
    await loadRun(sel.value, hash.sid);
  } catch (e) {
    showErr(e.message, boot);
  }
}
function parseHash() {
  const h = location.hash.replace(/^#/, '');
  const out = {};
  h.split('&').forEach((kv) => {
    const [k, v] = kv.split('=');
    if (k && v) out[k] = decodeURIComponent(v);
  });
  return out;
}
function setHash() {
  const h = S.run ? `#run=${encodeURIComponent(S.run)}` + (S.sid ? `&sid=${encodeURIComponent(S.sid)}` : '') : '';
  history.replaceState(null, '', h || location.pathname);
}

/* ---------------- run / 会话列表 ---------------- */
async function loadRun(runId, wantSid) {
  hideErr();
  S.run = runId; S.sid = null; S.detail = null; S.filter = 'ALL';
  $('run-stats').textContent = '正在读账本…';
  $('sess-list').innerHTML = '<div class="sess-empty">正在读账本…</div>';
  $('filters').innerHTML = '';
  $('detail').hidden = true;
  $('empty-main').hidden = false;
  try {
    const meta = S.runs.find((r) => r.id === runId);
    if (meta) {
      $('run-stats').innerHTML =
        `<b>${meta.n_sessions}</b> 会话 · <b>${meta.n_events}</b> 事件 · 最深 <b>L${meta.max_depth}</b>` +
        (meta.has_snapshot ? ' · 判定与快照逐条核对' : '');
    }
    const data = await api(`/api/run/${encodeURIComponent(runId)}/sessions`);
    S.sessions = data.sessions || [];
    renderFilters();
    renderSessions();
    setHash();
    if (wantSid && S.sessions.some((s) => s.sid === wantSid)) {
      await openSession(wantSid);
    } else if (S.sessions.length) {
      await openSession(S.sessions[0].sid);
    }
  } catch (e) {
    $('sess-list').innerHTML = '<div class="sess-empty">读取失败</div>';
    showErr(e.message, () => loadRun(runId, wantSid));
  }
}
function renderFilters() {
  const counts = {};
  S.sessions.forEach((s) => { counts[s.verdict] = (counts[s.verdict] || 0) + 1; });
  const order = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  const chips = [`<button type="button" class="chip" data-f="ALL" aria-pressed="${S.filter === 'ALL'}">全部 <span class="n">${S.sessions.length}</span></button>`];
  order.forEach((v) => {
    chips.push(`<button type="button" class="chip" data-f="${esc(v)}" aria-pressed="${S.filter === v}">` +
      `<span class="dot ${toneOf(v)}"></span>${esc(vzh(v))} <span class="n">${counts[v]}</span></button>`);
  });
  $('filters').innerHTML = chips.join('');
  $('filters').querySelectorAll('.chip').forEach((c) => {
    c.addEventListener('click', () => {
      S.filter = c.dataset.f;
      renderFilters(); renderSessions();
    });
  });
}
function visibleSessions() {
  return S.filter === 'ALL' ? S.sessions : S.sessions.filter((s) => s.verdict === S.filter);
}
function renderSessions() {
  const list = visibleSessions();
  $('sess-count').textContent = `${list.length} / ${S.sessions.length}`;
  if (!list.length) {
    $('sess-list').innerHTML = '<div class="sess-empty">该筛选下没有会话。</div>';
    return;
  }
  $('sess-list').innerHTML = list.map((s) => {
    const sel = s.sid === S.sid;
    return `<button type="button" class="sess" role="option" aria-selected="${sel}" data-sid="${esc(s.sid)}" title="${esc(s.sid)}">
      <span class="sess-r1">
        <span class="dot ${toneOf(s.verdict)}"></span>
        <span class="sess-sid">${esc(s.sid)}</span>
        <span class="sess-depth">L${s.depth}</span>
      </span>
      <span class="sess-r2">
        <span class="sess-v">${esc(vzh(s.verdict))}</span>
        <span class="sess-n">${s.n_events} 事件${s.allowlisted_requests ? ` · 静音 ${s.allowlisted_requests}` : ''}</span>
      </span>
    </button>`;
  }).join('');
  $('sess-list').querySelectorAll('.sess').forEach((b) => {
    b.addEventListener('click', () => openSession(b.dataset.sid));
  });
}

/* ---------------- 会话详情 ---------------- */
async function openSession(sid) {
  hideErr();
  stopPlay();
  S.sid = sid;
  renderSessions();
  setHash();
  try {
    const det = await api(`/api/run/${encodeURIComponent(S.run)}/session/${encodeURIComponent(sid)}`);
    S.detail = det;
    S.cursor = det.events.length - 1;     // 打开即全貌；⏮ 回到起点再播放
    S.tab = 'replay';
    $('empty-main').hidden = true;
    $('detail').hidden = false;
    renderHead();
    renderTimeline();
    renderChain();
    renderTurns();
    applyCursor(false);
    switchTab('replay');
  } catch (e) {
    showErr(e.message, () => openSession(sid));
  }
}
function verdictAtCursor() {
  const det = S.detail;
  if (!det || S.cursor < 0) return null;
  let v = null;
  det.verdict_steps.forEach((st) => { if (st.ev <= S.cursor) v = st.to; });
  return v;
}
function renderHead() {
  const det = S.detail, sm = det.summary;
  $('head-meta').textContent =
    `${sm.sid} · ${sm.ip || '?'} · ${sm.ua || 'UA 未记录'} · ${hhmmss(sm.t0)} → ${hhmmss(sm.t1)}` +
    (sm.arm && sm.arm !== 'live' ? ` · 臂 ${sm.arm}` : '');
  // 阶梯（跳级解锁如实标注：低层没走但高层已解锁）
  $('ladder').innerHTML = det.ladder.map((l, idx) => {
    const skipped = l.unlocked && l.ev != null && det.ladder.slice(0, idx).some((x) => !x.unlocked || (x.ev != null && x.ev > l.ev));
    const title = `L${l.level} ${l.label}` + (l.unlocked ? ` · 解锁于 ${hhmmss(l.t)} · 事件 #${l.ev + 1}` : ' · 未解锁') + (skipped ? ' · 跳级解锁（低层未走）' : '');
    return `<button type="button" class="rung" data-ev="${l.ev == null ? -1 : l.ev}" title="${esc(title)}" aria-label="${esc(title)}">
      <span class="rung-r1"><span class="rung-l">L${l.level}</span><span class="rung-mark">${l.unlocked ? '✓' : '·'}</span></span>
      <span class="rung-t">${esc((S.meta.ladder.find((x) => x.flag === l.flag) || {}).short || l.label)}</span>
    </button>`;
  }).join('');
  $('ladder').querySelectorAll('.rung').forEach((r) => {
    r.addEventListener('click', () => {
      const ev = parseInt(r.dataset.ev, 10);
      if (ev >= 0) { stopPlay(); setCursor(ev, true); }
    });
  });
  // 统计
  const clsZh = (S.meta.cls_zh && S.meta.cls_zh[sm.cls]) || sm.cls;
  const match = sm.verdict_live
    ? `<span class="stat"><span class="stat-v">${sm.verdict_match ? '一致' : '不一致'}</span><span class="stat-k">复算 vs 当时快照</span></span>`
    : `<span class="stat"><span class="stat-v">复算</span><span class="stat-k">无当时快照</span></span>`;
  $('stats').innerHTML =
    `<span class="stat"><span class="stat-v">${sm.requests}</span><span class="stat-k">HTTP 请求</span></span>` +
    `<span class="stat"><span class="stat-v">${sm.n_events}</span><span class="stat-k">账本事件</span></span>` +
    `<span class="stat"><span class="stat-v ${sm.cls === 'AGENT' ? 'tone-warn' : ''}">${sm.score == null ? '—' : sm.score}</span><span class="stat-k">${esc(clsZh)}评分</span></span>` +
    `<span class="stat"><span class="stat-v">${sm.canaries}</span><span class="stat-k">蜜标回调</span></span>` +
    (sm.allowlisted_requests
      ? `<span class="stat"><span class="stat-v">${sm.allowlisted_requests}</span><span class="stat-k">放行/静音 请求</span></span>`
      : '') +
    `<span class="stat"><span class="stat-v">L${sm.depth}</span><span class="stat-k">信任深度</span></span>` +
    match;
  // 身份外带（有证据才展示值；没有就如实说没有）
  const keys = Object.keys(sm.leaked || {});
  if (keys.length) {
    $('ident').innerHTML = '<span class="ident-k">身份外带实证</span>' + keys.map((k) =>
      `<span><span class="ident-k">${esc(k)}=</span><span class="ident-v">${esc(sm.leaked[k])}</span></span>`
    ).join('');
  } else {
    $('ident').innerHTML = '<span class="ident-none">未外带身份 —— 账本里没有它送出 h/u/d 的证据。</span>';
  }
  $('tab-dossier').disabled = !det.dossier_available;
  $('tab-dossier').title = det.dossier_available ? '查看取证档案（dossier）' : '该会话没有 dossier 文件';
}
function noteText(e) {
  const note = e.note || '';
  const zh = S.meta.note_zh[note];
  if (zh) return zh;
  if (note.startsWith('file:')) return '读取文件 ' + note.slice(5);
  if (note.startsWith('debug-exec:')) return 'debug 端点执行 ' + note.slice(11);
  return note;
}
const ALLOW_KIND_ZH = { scanner: '漏扫', crawler: '爬虫', backup: '备份', dlp: 'DLP',
  monitor: '监控', canary: '蜜标', aws: 'AWS', mcp: 'MCP', dns: 'DNS' };
function eventMain(e) {
  if (e.kind === 'http') {
    return `<span class="m">${esc(e.method || '')}</span><span class="p">${esc(e.path || '')}</span><span class="st">${e.status == null ? '' : e.status}</span>`;
  }
  if (e.kind === 'canary') {
    const ct = { credential: '凭据蜜标', bait: '便签蜜标', intel: '情报蜜标' }[e.ctype] || '蜜标';
    return `<span class="p">回调 /c/${esc(e.token || '')}</span><span class="st">${esc(ct)}</span>`;
  }
  if (e.kind === 'staircase') return `<span class="m">${esc(e.method || 'POST')}</span><span class="p">${esc(e.path || '/login')}</span><span class="st">${e.status == null ? '' : e.status}</span>`;
  if (e.kind === 'exec') return `<span class="p">${esc(e.cmd || '')}</span><span class="st">exit ${e.exit == null ? '?' : e.exit}</span>`;
  if (e.kind === 'download') return `<span class="p">${esc(e.file || '')}</span><span class="st">${e.bytes == null ? '' : e.bytes + 'B'}</span>`;
  if (e.kind === 'intel') return `<span class="p">${esc(e.cve || '')}</span><span class="st">${esc(e.level || '')}</span>`;
  if (e.kind === 'memory') return `<span class="p">${esc(e.level || '')}</span><span class="st">${esc(e.note || '')}</span>`;
  if (e.kind === 'ssh') return `<span class="p">SSH 登录尝试</span><span class="st">${esc(e.user || '')}</span>`;
  if (e.kind === 'allowlist') {
    // 被前置 allowlist 摘掉的请求：显示成「放行」而不是「噪声」——
    // 静音必须可见，否则等于替攻击者开后门。
    const kz = ALLOW_KIND_ZH[e.ctype] || e.ctype || '?';
    const n = e.n ? `×${e.n}` : '';
    return `<span class="m">${esc(e.method || '')}</span><span class="p">${esc(e.path || '')}</span>` +
      `<span class="st">放行 ${esc(kz)} ${n}</span>`;
  }
  return `<span class="p">${esc(e.note || e.kind || '')}</span>`;
}
function renderTimeline() {
  const det = S.detail;
  const turnsByEv = {};
  det.turning_points.forEach((p) => { (turnsByEv[p.ev] = turnsByEv[p.ev] || []).push(p); });
  $('timeline').innerHTML = det.events.map((e, i) => {
    const kindZh = (S.meta.kind_zh && S.meta.kind_zh[e.kind]) || e.kind;
    const tags = (turnsByEv[i] || []).map((p) =>
      `<span class="tag"><span class="dot ${p.type === 'ident' ? 'ok' : p.type === 'gate' ? 'none' : 'warn'}"></span>${esc(p.label)}</span>`
    ).join('');
    const args = e.kind === 'canary' && e.args && Object.keys(e.args).length
      ? `<div class="ev-args">${esc(Object.entries(e.args).map(([k, v]) => `${k}=${v}`).join(' · '))}</div>` : '';
    const note = e.kind === 'http' || e.kind === 'staircase' ? noteText(e)
      : (e.kind === 'canary' ? noteText(e) : (e.kind === 'allowlist' ? (e.detail || '') : ''));
    const dot = e.kind === 'canary' ? '<span class="dot warn"></span>'
      : (e.kind === 'allowlist' ? '<span class="dot ok"></span>' : '');
    return `<li class="ev" data-i="${i}" id="ev-${i}">
      <span class="ev-t">${hhmmss(e.t)}</span>
      <span class="ev-kind">${dot}${esc(kindZh)}</span>
      <div class="ev-body">
        <div class="ev-main">${eventMain(e)}</div>
        ${note ? `<div class="ev-note">${esc(note)}</div>` : ''}
        ${args}
        ${tags ? `<div class="ev-tags">${tags}</div>` : ''}
      </div>
    </li>`;
  }).join('');
  const scrub = $('scrub');
  scrub.min = -1; scrub.max = det.events.length - 1;
}
function renderChain() {
  const a = S.detail.attribution;
  $('chain-links').innerHTML = a.links.map((l) =>
    `<span class="link-chip"><span class="dot ${l.ok ? 'ok' : 'none'}"></span>${esc(l.name)}</span>`
  ).join('');
  $('chain').innerHTML = a.steps.length ? a.steps.map((st) =>
    `<li class="step" data-ev="${st.ev}">
      <div class="step-head">
        <span class="step-n">${String(st.n).padStart(2, '0')}</span>
        <span class="step-act">${esc(st.action)}</span>
        <button type="button" class="btn btn-sm step-jump" data-ev="${st.ev}">定位</button>
      </div>
      <div class="step-line"><span class="k">我方诱饵 · </span>${esc(st.bait)}</div>
      <div class="step-pay">${esc(st.payoff)}</div>
    </li>`
  ).join('') : '<li class="turns-empty">没有可归因的动作 —— 它没接招。</li>';
  $('chain').querySelectorAll('.step-jump').forEach((b) => {
    b.addEventListener('click', () => { stopPlay(); setCursor(parseInt(b.dataset.ev, 10), true); });
  });
}
function renderTurns() {
  const pts = S.detail.turning_points;
  $('turns').innerHTML = pts.length ? pts.map((p) =>
    `<li class="turn-item">
      <span class="ev-idx">#${p.ev + 1}</span>
      <span>${esc(p.label)}</span>
      <button type="button" class="btn btn-sm" data-ev="${p.ev}">定位</button>
    </li>`
  ).join('') : '<li class="turns-empty">无转折 —— 一条直线走完（或直接离开）。</li>';
  $('turns').querySelectorAll('button').forEach((b) => {
    b.addEventListener('click', () => { stopPlay(); setCursor(parseInt(b.dataset.ev, 10), true); });
  });
}

/* ---------------- 回放引擎 ---------------- */
function setCursor(c, scroll) {
  const det = S.detail;
  if (!det) return;
  const N = det.events.length;
  S.cursor = Math.max(-1, Math.min(N - 1, c));
  applyCursor(scroll);
}
/* 横幅随回放位置变化：中途不提前宣布终态 */
function updateChainBanner(c) {
  const a = S.detail.attribution;
  const banner = $('chain-banner');
  const revealed = a.steps.filter((st) => st.ev <= c);
  const atEnd = c >= S.detail.events.length - 1;
  if (atEnd) {
    if (a.complete) {
      banner.className = 'chain-banner tone-ok';
      banner.innerHTML = '<span class="dot ok"></span>链完整：从读配置一路骗到身份外带。';
    } else if (a.broken_at) {
      banner.className = 'chain-banner tone-warn';
      banner.innerHTML = `<span class="dot warn"></span>链断在「${esc(a.broken_at)}」：它没走到这一步。`;
    } else {
      banner.className = 'chain-banner';
      banner.innerHTML = '<span class="dot none"></span>尚未进入诱捕链。';
    }
    return;
  }
  banner.className = 'chain-banner';
  if (!revealed.length) {
    banner.innerHTML = '<span class="dot none"></span>回放位置：尚未进入诱捕链。';
  } else {
    const last = revealed[revealed.length - 1];
    banner.innerHTML = `<span class="dot none"></span>回放位置：链走到第 ${last.n} 步「${esc(last.action)}」（共 ${a.steps.length} 步）。`;
  }
}
function applyCursor(scroll) {
  const det = S.detail;
  if (!det) return;
  const N = det.events.length, c = S.cursor;
  // 时间线
  $('timeline').querySelectorAll('.ev').forEach((li) => {
    const i = parseInt(li.dataset.i, 10);
    li.classList.toggle('future', i > c);
    li.classList.toggle('cursor', i === c);
    if (i === c) li.setAttribute('aria-current', 'step');
    else li.removeAttribute('aria-current');
  });
  // 阶梯随回放点亮
  $('ladder').querySelectorAll('.rung').forEach((r) => {
    const ev = parseInt(r.dataset.ev, 10);
    const unlocked = det.ladder[[...$('ladder').children].indexOf(r)].unlocked;
    r.classList.toggle('on', unlocked && ev >= 0 && ev <= c);
  });
  // 归因链随回放展开
  $('chain').querySelectorAll('.step').forEach((st) => {
    st.classList.toggle('future', parseInt(st.dataset.ev, 10) > c);
  });
  updateChainBanner(c);
  // 头部判定 = 回放位置上的判定
  const v = verdictAtCursor();
  const badge = $('verdict-badge');
  badge.className = 'verdict-badge' + (v ? ' tone-' + toneOf(v) : '');
  $('verdict-dot').className = 'dot ' + (v ? toneOf(v) : 'none');
  $('verdict-zh').textContent = v ? vzh(v) : '未接触';
  $('verdict-pos').hidden = c >= N - 1;
  $('scrub').value = c;
  $('cursor-label').textContent = c < 0 ? `0 / ${N}` : `${c + 1} / ${N} · ${hhmmss(det.events[c].t)}`;
  if (scroll && c >= 0) {
    const row = $('ev-' + c);
    if (row) row.scrollIntoView({ block: 'nearest', behavior: REDUCED ? 'auto' : 'smooth' });
  }
}
function stepFwd() {
  const N = S.detail.events.length;
  if (S.cursor >= N - 1) { stopPlay(); return; }
  const before = verdictAtCursor();
  setCursor(S.cursor + 1, true);
  const after = verdictAtCursor();
  if (after && after !== before) announce('判定转折：' + vzh(after));
}
function startPlay() {
  if (!S.detail) return;
  const N = S.detail.events.length;
  if (S.cursor >= N - 1) setCursor(-1, false);
  S.playing = true;
  $('btn-play').textContent = '⏸';
  $('btn-play').classList.add('playing');
  $('btn-play').setAttribute('aria-label', '暂停');
  const tick = () => {
    if (!S.playing) return;
    stepFwd();
    if (S.playing) S.timer = setTimeout(tick, 520 / S.speed);
  };
  S.timer = setTimeout(tick, 120);
}
function stopPlay() {
  S.playing = false;
  if (S.timer) { clearTimeout(S.timer); S.timer = null; }
  $('btn-play').textContent = '▶';
  $('btn-play').classList.remove('playing');
  $('btn-play').setAttribute('aria-label', '播放');
}
$('btn-play').addEventListener('click', () => { S.playing ? stopPlay() : startPlay(); });
$('btn-reset').addEventListener('click', () => { stopPlay(); setCursor(-1, false); });
$('btn-prev').addEventListener('click', () => { stopPlay(); setCursor(S.cursor - 1, true); });
$('btn-next').addEventListener('click', () => { stopPlay(); stepFwd(); });
$('speed').addEventListener('change', () => { S.speed = parseInt($('speed').value, 10) || 4; });
$('scrub').addEventListener('input', () => { stopPlay(); setCursor(parseInt($('scrub').value, 10), true); });
document.addEventListener('keydown', (e) => {
  const tag = (e.target.tagName || '').toLowerCase();
  if (['input', 'select', 'textarea', 'button'].includes(tag)) return;
  if (!S.detail || S.tab !== 'replay') return;
  if (e.code === 'Space') { e.preventDefault(); S.playing ? stopPlay() : startPlay(); }
  else if (e.key === 'ArrowRight') { e.preventDefault(); stopPlay(); stepFwd(); }
  else if (e.key === 'ArrowLeft') { e.preventDefault(); stopPlay(); setCursor(S.cursor - 1, true); }
  else if (e.key === 'Home') { e.preventDefault(); stopPlay(); setCursor(-1, false); }
  else if (e.key === 'End') { e.preventDefault(); stopPlay(); setCursor(S.detail.events.length - 1, true); }
});

/* ---------------- 档案视图 ---------------- */
function switchTab(tab) {
  S.tab = tab;
  $('tab-replay').setAttribute('aria-selected', String(tab === 'replay'));
  $('tab-dossier').setAttribute('aria-selected', String(tab === 'dossier'));
  $('replay-view').hidden = tab !== 'replay';
  $('dossier-view').hidden = tab !== 'dossier';
  if (tab === 'dossier') loadDossier();
}
$('tab-replay').addEventListener('click', () => switchTab('replay'));
$('tab-dossier').addEventListener('click', () => switchTab('dossier'));
async function loadDossier() {
  const key = S.run + '/' + S.sid;
  const box = $('dossier-view');
  if (S.dossierCache[key]) { box.innerHTML = S.dossierCache[key]; return; }
  box.innerHTML = '<div class="dossier-none">正在读档案…</div>';
  try {
    const d = await api(`/api/run/${encodeURIComponent(S.run)}/dossier/${encodeURIComponent(S.sid)}`);
    const html = d.markdown
      ? `<div class="dossier-src">${esc(d.source)}</div>` + mdToHtml(d.markdown)
      : '<div class="dossier-none">该会话没有 dossier 文件。</div>';
    S.dossierCache[key] = html;
    box.innerHTML = html;
  } catch (e) {
    box.innerHTML = `<div class="dossier-none">档案读取失败：${esc(e.message)}</div>`;
  }
}
/* 极简 markdown 渲染（先转义再变换，只支持 dossier 用到的语法） */
function mdInline(s) {
  return s.replace(/`([^`]+)`/g, '<code>$1</code>')
          .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}
function mdToHtml(md) {
  const lines = esc(md).split(/\r?\n/);
  const out = [];
  let i = 0, para = [], list = [];
  const flushPara = () => { if (para.length) { out.push('<p>' + mdInline(para.join(' ')) + '</p>'); para = []; } };
  const flushList = () => { if (list.length) { out.push('<ul>' + list.map((x) => '<li>' + mdInline(x) + '</li>').join('') + '</ul>'); list = []; } };
  while (i < lines.length) {
    const ln = lines[i];
    if (/^\s*\|/.test(ln)) {
      flushPara(); flushList();
      const rows = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) { rows.push(lines[i].trim()); i++; }
      const cells = (r) => r.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
      const head = cells(rows[0]);
      const body = rows.slice(1).filter((r) => !/^[\s|:-]+$/.test(r));
      out.push('<table><thead><tr>' + head.map((c) => '<th>' + mdInline(c) + '</th>').join('') + '</tr></thead><tbody>' +
        body.map((r) => '<tr>' + cells(r).map((c) => '<td>' + mdInline(c) + '</td>').join('') + '</tr>').join('') + '</tbody></table>');
      continue;
    }
    const h = ln.match(/^(#{1,3})\s+(.*)$/);
    if (h) { flushPara(); flushList(); out.push(`<h${h[1].length}>` + mdInline(h[2]) + `</h${h[1].length}>`); i++; continue; }
    if (/^\s*---+\s*$/.test(ln)) { flushPara(); flushList(); out.push('<hr>'); i++; continue; }
    const li = ln.match(/^\s*[-*]\s+(.*)$/);
    if (li) { flushPara(); list.push(li[1]); i++; continue; }
    if (!ln.trim()) { flushPara(); flushList(); i++; continue; }
    flushList(); para.push(ln.trim()); i++;
  }
  flushPara(); flushList();
  return out.join('\n');
}

$('err-retry').addEventListener('click', () => { hideErr(); if (S.lastError) S.lastError(); });
boot();
