(() => {
  'use strict';
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';

  document.addEventListener('submit', async (e) => {
    const form = e.target;
    if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) {
      e.preventDefault();
      return;
    }
    if (!form.matches('form[data-vote]')) return;

    // Upvote ohne Seitenneuladen; ohne JS funktioniert das Formular normal.
    e.preventDefault();
    const btn = form.querySelector('.up');
    const score = form.querySelector('.n');
    const label = btn.querySelector('span');
    btn.disabled = true;
    try {
      const res = await fetch(form.action, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json', 'X-CSRF-Token': csrf },
        body: new FormData(form),
      });
      if (res.status === 401) {
        location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search);
        return;
      }
      if (!res.ok) throw new Error(res.status);
      const data = await res.json();
      score.textContent = data.score;
      btn.classList.toggle('is-on', data.voted);
      if (label) label.textContent = data.voted ? 'Unterstützt' : 'Unterstützen';
      btn.setAttribute('aria-pressed', String(data.voted));
    } catch {
      form.submit();
    } finally {
      btn.disabled = false;
    }
  });

  document.querySelectorAll('[data-autosubmit]').forEach((el) =>
    el.addEventListener('change', () => el.form.submit()));

  // Hinweis bei Sicherheitsmeldungen
  const note = document.getElementById('security-note');
  if (note) {
    const update = () => {
      note.hidden = document.querySelector('input[name="art"]:checked')?.value !== 'security';
    };
    document.querySelectorAll('input[name="art"]').forEach((i) => i.addEventListener('change', update));
    update();
  }

  // Dateiliste mit Größenprüfung
  const fmt = (n) => n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.ceil(n / 1024) + ' KB';
  document.querySelectorAll('input[type=file][data-filelist]').forEach((input) => {
    const out = document.getElementById(input.dataset.filelist);
    const max = Number(input.dataset.max) || 0;
    const maxBytes = Number(input.dataset.maxBytes) || 0;
    input.addEventListener('change', () => {
      out.replaceChildren();
      let err = '';
      if (max && input.files.length > max) err = `Maximal ${max} Dateien erlaubt.`;
      for (const f of input.files) {
        const li = document.createElement('li');
        li.textContent = `${f.name} (${fmt(f.size)})`;
        if (maxBytes && f.size > maxBytes) {
          li.className = 'too-big';
          err = `${f.name} ist größer als ${fmt(maxBytes)}.`;
        }
        out.append(li);
      }
      if (err) {
        const li = document.createElement('li');
        li.className = 'too-big';
        li.textContent = err;
        out.append(li);
      }
      input.setCustomValidity(err);
    });
  });
})();

// Verweist die Adresse auf einen Eintrag im eingeklappten Änderungsverlauf, diesen öffnen.
(() => {
  const open = () => {
    const el = location.hash && document.getElementById(location.hash.slice(1));
    const d = el && el.closest('details');
    if (d) { d.open = true; el.scrollIntoView(); }
  };
  window.addEventListener('hashchange', open);
  open();
})();

// Duplikatsfinder im Meldeformular
(() => {
  const box = document.getElementById('dupes');
  if (!box) return;
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const title = document.getElementById('f-titel');
  const software = document.getElementById('f-software');
  const list = box.querySelector('.dupes-list');
  let timer, ctrl, last = '';

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const kind = () => document.querySelector('input[name="art"]:checked')?.value;

  const render = (hits) => {
    list.replaceChildren();
    for (const h of hits) {
      const li = el('li', `dupe k-${h.kind}${h.done ? ' is-done' : ''}`);
      const main = el('div', 'dupe-main');
      const a = el('a', 'dupe-title', h.title);
      a.href = `/r/${h.id}`;
      a.target = '_blank';
      a.rel = 'noopener';
      const meta = el('p', 'dupe-meta');
      meta.append(el('span', 'kind', h.kindLabel));
      const st = el('span', `status st-${h.status}`);
      st.append(el('i'), document.createTextNode(h.statusLabel));
      meta.append(st, el('span', null, `#${h.id}`));
      if (h.answers) meta.append(el('span', null, `${h.answers} ${h.answers === 1 ? 'Antwort' : 'Antworten'}`));
      main.append(a, meta);
      if (h.excerpt) main.append(el('p', 'dupe-excerpt', h.excerpt));
      if (h.done) main.append(el('p', 'dupe-note', h.status === 'fixed'
        ? 'Bereits behoben. Tritt der Fehler weiterhin auf, schreib dort eine Antwort mit deiner Version.'
        : 'Diese Meldung ist abgeschlossen.'));

      const side = el('div', 'dupe-vote');
      const count = el('span', 'n', String(h.score));
      const btn = el('button', `btn${h.voted ? ' is-on' : ''}`, h.voted ? 'Unterstützt' : 'Unterstützen');
      btn.type = 'button';
      btn.setAttribute('aria-pressed', String(h.voted));
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        try {
          const res = await fetch(`/r/${h.id}/vote`, {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Accept': 'application/json', 'X-CSRF-Token': csrf, 'Content-Type': 'application/x-www-form-urlencoded' },
            body: '',
          });
          if (!res.ok) throw new Error(res.status);
          const d = await res.json();
          count.textContent = d.score;
          btn.textContent = d.voted ? 'Unterstützt' : 'Unterstützen';
          btn.classList.toggle('is-on', d.voted);
          btn.setAttribute('aria-pressed', String(d.voted));
          li.classList.toggle('is-voted', d.voted);
          box.querySelector('.dupes-thanks').hidden = !d.voted;
        } catch {
          btn.textContent = 'Fehler, bitte erneut versuchen';
        } finally {
          btn.disabled = false;
        }
      });
      side.append(count, btn);
      li.append(main, side);
      if (h.voted) li.classList.add('is-voted');
      list.append(li);
    }
    box.hidden = hits.length === 0;
  };

  const search = async () => {
    const q = title.value.trim();
    const sw = software.value;
    const key = `${sw}|${q}|${kind()}`;
    if (key === last) return;
    last = key;
    if (!sw || q.length < 4 || kind() === 'security') { render([]); return; }
    ctrl?.abort();
    ctrl = new AbortController();
    try {
      const res = await fetch(`/api/aehnlich?software=${encodeURIComponent(sw)}&q=${encodeURIComponent(q)}`,
        { headers: { 'Accept': 'application/json' }, signal: ctrl.signal, credentials: 'same-origin' });
      if (res.ok) render(await res.json());
    } catch { /* abgebrochen oder offline: einfach keine Vorschläge */ }
  };
  const schedule = () => { clearTimeout(timer); timer = setTimeout(search, 300); };
  title.addEventListener('input', schedule);
  software.addEventListener('change', search);
  document.querySelectorAll('input[name="art"]').forEach((i) => i.addEventListener('change', search));
  search();
})();

// Sicherheitsabfragen für einzelne Buttons (formaction) und Links
document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-confirm-btn], [data-confirm-link]');
  if (!el) return;
  const msg = el.dataset.confirmBtn || el.dataset.confirmLink;
  if (!window.confirm(msg)) e.preventDefault();
});

// Markdown-Editor: Schreiben / Vorschau
(() => {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  let n = 0;
  document.querySelectorAll('textarea[data-md]').forEach((ta) => {
    n++;
    const wrap = document.createElement('div');
    wrap.className = 'md-editor';
    const bar = document.createElement('div');
    bar.className = 'md-tabs';
    bar.setAttribute('role', 'tablist');
    const mk = (label, sel) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'md-tab';
      b.textContent = label;
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-selected', String(sel));
      return b;
    };
    const tWrite = mk('Schreiben', true);
    const tPrev = mk('Vorschau', false);
    const help = document.createElement('details');
    help.className = 'md-help';
    help.innerHTML = '<summary>Formatierung</summary><table><tbody>' +
      '<tr><td><code>**fett**</code></td><td><strong>fett</strong></td></tr>' +
      '<tr><td><code>_kursiv_</code></td><td><em>kursiv</em></td></tr>' +
      '<tr><td><code>`code`</code></td><td><code>code</code></td></tr>' +
      '<tr><td><code>```</code> … <code>```</code></td><td>Codeblock für Logs und Stacktraces</td></tr>' +
      '<tr><td><code>- Punkt</code> / <code>1. Schritt</code></td><td>Listen</td></tr>' +
      '<tr><td><code>[Text](https://…)</code></td><td>Link</td></tr>' +
      '<tr><td><code>&gt; Zitat</code></td><td>Zitat</td></tr></tbody></table>';
    bar.append(tWrite, tPrev, help);
    const prev = document.createElement('div');
    prev.className = 'md-preview prose md';
    prev.hidden = true;
    prev.id = 'md-prev-' + n;
    ta.parentNode.insertBefore(wrap, ta);
    wrap.append(bar, ta, prev);

    const show = (preview) => {
      tWrite.setAttribute('aria-selected', String(!preview));
      tPrev.setAttribute('aria-selected', String(preview));
      ta.hidden = preview;
      prev.hidden = !preview;
    };
    tWrite.addEventListener('click', () => { show(false); ta.focus(); });
    tPrev.addEventListener('click', async () => {
      prev.style.minHeight = ta.offsetHeight + 'px';
      show(true);
      if (!ta.value.trim()) { prev.innerHTML = '<p class="hint">Nichts zum Anzeigen.</p>'; return; }
      prev.innerHTML = '<p class="hint">Vorschau wird geladen …</p>';
      try {
        const body = new URLSearchParams({ text: ta.value });
        const res = await fetch('/api/vorschau', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Accept': 'application/json', 'X-CSRF-Token': csrf },
          body,
        });
        if (!res.ok) throw new Error(res.status);
        prev.innerHTML = (await res.json()).html; // serverseitig sicher gerendert (kein Roh-HTML)
      } catch {
        prev.innerHTML = '<p class="hint">Vorschau nicht verfügbar.</p>';
      }
    });
  });
})();

// Folgen ohne Neuladen
document.addEventListener('submit', async (e) => {
  const form = e.target;
  if (!form.matches('form[data-follow]')) return;
  e.preventDefault();
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const btn = form.querySelector('button');
  btn.disabled = true;
  try {
    const res = await fetch(form.action, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Accept': 'application/json', 'X-CSRF-Token': csrf }, body: new FormData(form),
    });
    if (!res.ok) throw new Error(res.status);
    const { following } = await res.json();
    btn.classList.toggle('is-on', following);
    btn.setAttribute('aria-pressed', String(following));
    btn.querySelector('span').textContent = following ? 'Du folgst' : 'Folgen';
    form.querySelector('.follow-hint').textContent = following
      ? 'Du wirst über Antworten und Änderungen informiert.'
      : 'Bei Antworten und Änderungen benachrichtigt werden.';
  } catch {
    form.submit();
  } finally {
    btn.disabled = false;
  }
});

// Bearbeiten-Panel: Duplikat-Feld und Vorschläge
(() => {
  const form = document.querySelector('form[data-triage]');
  if (!form) return;
  const status = form.querySelector('select[name="status"]');
  const field = form.querySelector('.dup-field');
  const input = field.querySelector('input');
  const list = field.querySelector('.dup-suggest');
  let loaded = false;
  const load = async () => {
    if (loaded) return;
    loaded = true;
    const q = new URLSearchParams({ software: form.dataset.software, q: form.dataset.title, ohne: form.dataset.report });
    try {
      const res = await fetch('/api/aehnlich?' + q, { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' });
      const hits = res.ok ? await res.json() : [];
      list.replaceChildren(...hits.map((h) => {
        const li = document.createElement('li');
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'dup-pick';
        const ref = document.createElement('span');
        ref.className = 'ref';
        ref.textContent = '#' + h.id;
        b.append(ref, document.createTextNode(' ' + h.title));
        b.addEventListener('click', () => { input.value = '#' + h.id; input.focus(); });
        li.append(b);
        return li;
      }));
    } catch { /* keine Vorschläge */ }
  };
  const update = () => {
    const dup = status.value === 'duplicate';
    field.hidden = !dup;
    input.required = dup;
    if (dup) load();
  };
  status.addEventListener('change', update);
  update();
})();
