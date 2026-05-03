/* shared.js — Thème + taille de police — exécuté en premier dans <head> */
(function () {
  var mq = window.matchMedia('(prefers-color-scheme: dark)');

  function _currentTheme() {
    var mode = localStorage.getItem('mednews-theme') || 'auto';
    if (mode === 'light') return 'light';
    if (mode === 'dark') return 'dark';
    return mq.matches ? 'dark' : 'light';
  }

  function applyTheme() {
    var theme = _currentTheme();
    document.documentElement.setAttribute('data-theme', theme);
    // Prévention du flash : couleur de fond immédiate
    document.documentElement.style.backgroundColor =
      theme === 'dark' ? '#0f1117' : '#f6f5f2';
  }

  function setTheme(mode) {
    localStorage.setItem('mednews-theme', mode);
    applyTheme();
  }

  function applyFontSize() {
    var fs = localStorage.getItem('mednews-fontsize') || 'normal';
    // compact=20px, normal=23px, large=26px
    var sizes = { compact: 20, normal: 23, large: 26 };
    var px = sizes[fs] || 23;
    var scale = px / 14;
    // Injecter un <style> garanti — plus fiable que les CSS custom props inline
    var el = document.getElementById('_mednews_fs');
    if (!el) { el = document.createElement('style'); el.id = '_mednews_fs'; document.head.appendChild(el); }
    el.textContent = 'html{font-size:' + px + 'px!important}body{font-size:' + px + 'px!important;--font-scale:' + scale + '}';
  }

  function setFontSize(mode) {
    localStorage.setItem('mednews-fontsize', mode);
    applyFontSize();
  }

  // Init synchrone (avant tout rendu)
  applyTheme();
  applyFontSize();

  // Réagir aux changements OS en mode Auto
  mq.addEventListener('change', applyTheme);

  // Détecte si l'utilisateur connecté est admin (depuis le JWT)
  function isAdmin() {
    try {
      var token = sessionStorage.getItem('access_token');
      if (!token) return false;
      var payload = JSON.parse(atob(token.split('.')[1]));
      return !!payload.adm;
    } catch (e) { return false; }
  }

  // Retourne l'URL "home" selon le rôle : /review pour admin, /portal pour user
  function homeUrl() {
    return isAdmin() ? '/review' : '/portal';
  }

  function goHome() {
    window.location.href = homeUrl();
  }

  // Formate une date ISO (YYYY-MM-DD) en jj - mm - yyyy
  function formatDate(raw) {
    if (!raw) return '';
    try {
      var parts = raw.substring(0, 10).split('-');
      if (parts.length !== 3) return raw;
      return parts[2] + '/' + parts[1] + '/' + parts[0];
    } catch (e) { return raw; }
  }

  // Bandeau "site en développement" — injecté en haut de toutes les pages
  function injectDevBanner() {
    if (sessionStorage.getItem('mednews-devbanner-closed')) return;
    var banner = document.createElement('div');
    banner.id = 'mednews-dev-banner';
    banner.setAttribute('style', [
      'position:fixed',
      'top:0',
      'left:0',
      'right:0',
      'width:100%',
      'box-sizing:border-box',
      'z-index:99999',
      'background:#fffbeb',
      'border-bottom:1px solid #f5d87a',
      'color:#78450a',
      'font-family:inherit',
      'font-size:0.78rem',
      'line-height:1.4',
      'padding:8px 48px 8px 16px',
      'text-align:center',
      'letter-spacing:0.1px',
    ].join(';'));
    banner.innerHTML =
      '🚧 <strong>Site en cours de développement</strong> — ' +
      'l’accès est <strong>gratuit pendant toute la phase de développement</strong>. ' +
      'MedNews deviendra payant à l’issue du développement complet, ' +
      'prévu <strong>dans environ 2 mois</strong>.' +
      '<button onclick="(function(){sessionStorage.setItem(\'mednews-devbanner-closed\',\'1\');' +
      'document.getElementById(\'mednews-dev-banner\').remove();})()" ' +
      'style="position:absolute;right:12px;top:50%;transform:translateY(-50%);' +
      'background:none;border:none;cursor:pointer;font-size:1rem;color:#78450a;' +
      'line-height:1;padding:2px 4px;" aria-label="Fermer">×</button>';
    if (document.body.firstChild) {
      document.body.insertBefore(banner, document.body.firstChild);
    } else {
      document.body.appendChild(banner);
    }
  }

  document.addEventListener('DOMContentLoaded', injectDevBanner);

  // Export global
  window.MedNews = {
    setTheme: setTheme,
    setFontSize: setFontSize,
    applyTheme: applyTheme,
    isAdmin: isAdmin,
    homeUrl: homeUrl,
    goHome: goHome,
    formatDate: formatDate,
  };
})();
