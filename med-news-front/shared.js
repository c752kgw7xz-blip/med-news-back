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

  // Export global
  window.MedNews = {
    setTheme: setTheme,
    setFontSize: setFontSize,
    applyTheme: applyTheme,
    isAdmin: isAdmin,
    homeUrl: homeUrl,
    goHome: goHome,
  };
})();
