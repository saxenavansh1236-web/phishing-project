// app_pro.js -- small behaviours shared by the user pages: drop zones, busy buttons, copy buttons, history filter.
(function () {
  document.querySelectorAll('.drop').forEach(function (zone) {
    var input = zone.querySelector('input[type=file]'), label = zone.querySelector('.drop-name'), img = zone.querySelector('.drop-prev');
    function show(file) {
      if (!file) return;
      label.textContent = file.name + ' (' + Math.max(1, Math.round(file.size / 1024)) + ' KB)'; zone.classList.add('has-file');
      if (img && file.type.indexOf('image/') === 0) { img.src = URL.createObjectURL(file); img.hidden = false; }
    }
    input.addEventListener('change', function () { show(input.files[0]); });
    ['dragenter', 'dragover'].forEach(function (ev) { zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add('over'); }); });
    ['dragleave', 'drop'].forEach(function (ev) { zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove('over'); }); });
    zone.addEventListener('drop', function (e) { if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; show(input.files[0]); } });
  });

  document.querySelectorAll('form[data-busy]').forEach(function (form) {
    var btn = form.querySelector('button[type=submit]'), lbl = btn && btn.querySelector('.lbl'), original = lbl && lbl.textContent;
    form.addEventListener('submit', function () { btn.classList.add('busy'); btn.disabled = true; if (lbl) lbl.textContent = form.dataset.busy; });
    window.addEventListener('pageshow', function (e) { if (e.persisted && btn) { btn.classList.remove('busy'); btn.disabled = false; if (lbl) lbl.textContent = original; } });
  });

  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var text = document.querySelector(btn.dataset.copy).textContent.trim(), old = btn.textContent;
      (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(
        function () { btn.textContent = 'Copied'; setTimeout(function () { btn.textContent = old; }, 1600); },
        function () { window.prompt('Copy this:', text); });
    });
  });

  var search = document.getElementById('h-search'), chips = document.querySelectorAll('[data-filter]'), rows = document.querySelectorAll('#h-body tr[data-v]'), mode = 'all';
  function apply() {
    var q = search ? search.value.toLowerCase() : '', shown = 0;
    rows.forEach(function (r) {
      var ok = (mode === 'all' || r.dataset.v === mode) && r.dataset.t.indexOf(q) !== -1;
      r.style.display = ok ? '' : 'none'; if (ok) shown++;
    });
    var none = document.getElementById('h-none'); if (none) none.style.display = shown ? 'none' : '';
  }
  if (search) search.addEventListener('input', apply);
  chips.forEach(function (c) { c.addEventListener('click', function () {
    chips.forEach(function (x) { x.classList.remove('on'); }); c.classList.add('on'); mode = c.dataset.filter; apply(); }); });
})();