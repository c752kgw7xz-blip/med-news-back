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
    // compact=15px, normal=17px, large=20px — base 14px (calc(14px * --font-scale))
    var sizes = { compact: 15, normal: 17, large: 20 };
    var px = sizes[fs] || 17;
    document.documentElement.style.setProperty('--font-scale', String(px / 14));
    // Définir html font-size → 1rem = px (utilisé par les CSS rem)
    document.documentElement.style.fontSize = px + 'px';
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

  // Export global
  window.MedNews = {
    setTheme: setTheme,
    setFontSize: setFontSize,
    applyTheme: applyTheme,
  };
})();
