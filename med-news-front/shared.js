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
      theme === 'dark' ? '#0f1117' : '#f8fafc';
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


  // Bandeau cookies RGPD
  function initCookieBanner() {
    if (localStorage.getItem('mednews-cookie-consent')) return;
    var banner = document.createElement('div');
    banner.id = 'mednews-cookie-banner';
    banner.setAttribute('role', 'region');
    banner.setAttribute('aria-label', 'Information cookies');
    banner.innerHTML =
      '<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;justify-content:space-between;">' +
        '<p style="margin:0;font-size:0.8rem;line-height:1.55;color:var(--text2,#3E3A34);flex:1;min-width:200px;">' +
          'Ce site utilise uniquement des cookies fonctionnels nécessaires à votre connexion sécurisée. ' +
          'Aucun cookie publicitaire ni de tracking. ' +
          '<a href="/politique-confidentialite" style="color:var(--accent,#9B2335);text-decoration:underline;white-space:nowrap;">En savoir plus</a>' +
        '</p>' +
        '<button id="mednews-cookie-accept" ' +
          'style="flex-shrink:0;background:var(--accent,#9B2335);color:#fff;border:none;border-radius:4px;' +
          'padding:8px 20px;font-size:0.8rem;font-weight:500;cursor:pointer;font-family:inherit;white-space:nowrap;">' +
          'J\'ai compris' +
        '</button>' +
      '</div>';
    Object.assign(banner.style, {
      position: 'fixed', bottom: '0', left: '0', right: '0',
      background: 'var(--surface, #FDFCF9)',
      borderTop: '1px solid var(--border, #D6D2C8)',
      padding: '14px 32px', zIndex: '9999',
      boxShadow: '0 -2px 12px rgba(0,0,0,0.06)',
    });
    document.body.appendChild(banner);
    document.getElementById('mednews-cookie-accept').addEventListener('click', function () {
      localStorage.setItem('mednews-cookie-consent', '1');
      banner.style.transition = 'opacity 0.2s';
      banner.style.opacity = '0';
      setTimeout(function () { banner.remove(); }, 220);
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initCookieBanner);
  } else {
    initCookieBanner();
  }

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
