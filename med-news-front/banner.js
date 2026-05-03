(function () {
  var KEY = 'mednews-devbanner-v2';
  if (sessionStorage.getItem(KEY)) return;

  var banner = document.createElement('div');
  banner.id = 'mednews-dev-banner';
  banner.style.cssText = [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'width:100%',
    'box-sizing:border-box', 'z-index:99999', 'background:#fffbeb',
    'border-bottom:1px solid #f5d87a', 'color:#78450a',
    'font-family:inherit', 'font-size:0.78rem', 'line-height:1.4',
    'padding:8px 48px 8px 16px', 'text-align:center', 'letter-spacing:0.1px'
  ].join(';');

  var btn = document.createElement('button');
  btn.setAttribute('aria-label', 'Fermer');
  btn.style.cssText = [
    'position:absolute', 'right:12px', 'top:50%', 'transform:translateY(-50%)',
    'background:none', 'border:none', 'cursor:pointer',
    'font-size:1rem', 'color:#78450a', 'line-height:1', 'padding:2px 4px'
  ].join(';');
  btn.textContent = '×';
  btn.addEventListener('click', function () {
    sessionStorage.setItem(KEY, '1');
    banner.remove();
    document.body.style.paddingTop = '';
    var hdr = document.querySelector('header');
    if (hdr) hdr.style.top = '';
    var sb = document.querySelector('.sidebar');
    if (sb) { sb.style.top = ''; sb.style.height = ''; }
  });

  var txt = document.createElement('span');
  txt.innerHTML = "Version bêta — accès gratuit jusqu'au lancement officiel (<strong>dans ~ 2 mois</strong>).";

  banner.appendChild(txt);
  banner.appendChild(btn);

  function inject() {
    if (document.getElementById('mednews-dev-banner')) return;
    if (document.body) {
      document.body.insertBefore(banner, document.body.firstChild);
      var h = banner.offsetHeight;
      document.body.style.paddingTop = h + 'px';
      var hdr = document.querySelector('header');
      if (hdr) hdr.style.top = h + 'px';
      var sb = document.querySelector('.sidebar');
      if (sb) { sb.style.top = (52 + h) + 'px'; sb.style.height = 'calc(100vh - ' + (52 + h) + 'px)'; }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }
})();
