/* cookie-banner.js — Bandeau information cookies RGPD */
(function () {
  if (localStorage.getItem('mednews-cookie-consent')) return;

  document.addEventListener('DOMContentLoaded', function () {
    var banner = document.createElement('div');
    banner.id = 'mednews-cookie-banner';
    banner.setAttribute('role', 'region');
    banner.setAttribute('aria-label', 'Information cookies');
    banner.innerHTML =
      '<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;justify-content:space-between;">' +
        '<p style="margin:0;font-size:0.8rem;line-height:1.55;color:#3E3A34;flex:1;min-width:200px;">' +
          'Ce site utilise uniquement des cookies fonctionnels nécessaires à votre connexion sécurisée. ' +
          'Aucun cookie publicitaire ni de tracking. ' +
          '<a href="/politique-confidentialite" style="color:#9B2335;text-decoration:underline;white-space:nowrap;">En savoir plus</a>' +
        '</p>' +
        '<button id="mednews-cookie-accept" ' +
          'style="flex-shrink:0;background:#9B2335;color:#fff;border:none;border-radius:4px;' +
          'padding:8px 20px;font-size:0.8rem;font-weight:500;cursor:pointer;font-family:inherit;white-space:nowrap;">' +
          'J\'ai compris' +
        '</button>' +
      '</div>';

    Object.assign(banner.style, {
      position: 'fixed',
      bottom: '0',
      left: '0',
      right: '0',
      background: '#FDFCF9',
      borderTop: '1px solid #D6D2C8',
      padding: '14px 32px',
      zIndex: '9999',
      boxShadow: '0 -2px 12px rgba(0,0,0,0.06)',
    });

    document.body.appendChild(banner);

    document.getElementById('mednews-cookie-accept').addEventListener('click', function () {
      localStorage.setItem('mednews-cookie-consent', '1');
      banner.style.transition = 'opacity 0.2s';
      banner.style.opacity = '0';
      setTimeout(function () { banner.remove(); }, 220);
    });
  });
})();
