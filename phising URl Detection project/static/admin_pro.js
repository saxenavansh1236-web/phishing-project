// admin_pro.js -- small polish on top of admin.html: no emoji in the UI, status dots, avatar, "View all" links.
(function () {
  const EMOJI = /[\p{Extended_Pictographic}\uFE0F\u200D]/gu;
  const SELECTORS = '.topbar-title,.topbar-badge,.sidebar-brand h2,.section-header h3,.card h4,#section-settings h4,' +
                    '.pill,.activity-text,.flash,.btn-del,.btn-ok,.logout-link,.empty,.nav-item span:not(.icon)';

  function clean(root) {
    root.querySelectorAll(SELECTORS).forEach(el => {
      const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        const t = n.nodeValue.replace(EMOJI, '').replace(/ {2,}/g, ' ');
        if (t !== n.nodeValue) n.nodeValue = t;
      }
    });
  }

  function init() {
    // coloured status dots instead of emoji in the activity feeds
    document.querySelectorAll('.activity-item').forEach(item => {
      const icon = item.querySelector('.activity-icon');
      if (!icon) return;
      const text = item.textContent;
      const kind = /PHISHING/.test(text) ? 'dot-bad' : /SAFE/.test(text) ? 'dot-ok' : 'dot-info';
      icon.innerHTML = '<span class="dot ' + kind + '"></span>';
    });

    // "View all" links on the two dashboard feeds
    document.querySelectorAll('#section-dashboard .section-header').forEach((header, i) => {
      const target = i === 0 ? 'scans' : 'logins';
      const link = document.createElement('a');
      link.href = '#' + target; link.className = 'link-btn'; link.textContent = 'View all';
      link.addEventListener('click', e => { e.preventDefault(); showSection(target); });
      header.appendChild(link);
    });

    // avatar with the admin's initial
    const name = document.querySelector('.sidebar-footer .admin-name');
    if (name) {
      const avatar = document.createElement('div');
      avatar.className = 'avatar';
      avatar.textContent = (name.textContent.trim()[0] || 'A').toUpperCase();
      name.parentElement.prepend(avatar);
    }

    clean(document);

    // keep the top-bar title emoji-free when the section changes
    if (typeof showSection === 'function') {
      const original = showSection;
      showSection = function (name) { original(name); clean(document.querySelector('.topbar')); };
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();