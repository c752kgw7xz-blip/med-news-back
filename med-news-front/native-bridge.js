/**
 * native-bridge.js — MedNews Capacitor bridge
 * Pas de bundler : utilise window.Capacitor injecté par le runtime natif.
 * Chargé en dernier dans <body> sur toutes les pages HTML.
 */
(function () {
  const cap = window.Capacitor;
  const isNative = cap && cap.isNativePlatform();

  // ── Push notifications ─────────────────────────────────────────
  const PUSH_TOKEN_KEY = 'mednews_push_token';
  const platform = isNative ? cap.getPlatform() : 'web';

  function sendPushToken(token) {
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken || !token) return;
    fetch('/me/push-token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
      credentials: 'include',
      body: JSON.stringify({ token, platform }),
    }).catch(() => {});
  }

  // Appelé après login pour envoyer un token push déjà obtenu
  function flushPushToken() {
    const token = localStorage.getItem(PUSH_TOKEN_KEY);
    if (token) sendPushToken(token);
  }

  async function registerPush() {
    if (!isNative) return;
    const { PushNotifications } = cap.Plugins;

    let perm = await PushNotifications.checkPermissions();
    if (perm.receive === 'prompt') {
      perm = await PushNotifications.requestPermissions();
    }
    if (perm.receive !== 'granted') return;

    // Sur iOS, Firebase SDK envoie le vrai token FCM via l'événement natif ci-dessous.
    // Sur Android, le plugin retourne directement le token FCM dans 'registration'.
    if (platform === 'ios') {
      function handleFcmToken(token) {
        if (!token) return;
        localStorage.setItem(PUSH_TOKEN_KEY, token);
        sendPushToken(token);
      }

      // Écouter l'événement injecté par AppDelegate via evaluateJavaScript
      window.addEventListener('mednews_fcm_token', (e) => {
        handleFcmToken(e.detail && e.detail.token);
      }, { once: false });

      // Polling : vérifie window.__mednews_pending_fcm_token toutes les 500ms
      // Capture le token quelle que soit la chronologie d'arrivée
      const _pollFcm = setInterval(() => {
        const t = window.__mednews_pending_fcm_token;
        if (t) {
          clearInterval(_pollFcm);
          window.__mednews_pending_fcm_token = null;
          handleFcmToken(t);
        }
      }, 500);
      // Arrêt du polling après 60 secondes
      setTimeout(() => clearInterval(_pollFcm), 60000);

      // Vérification immédiate (token déjà là au démarrage)
      const _pending = window.__mednews_pending_fcm_token;
      if (_pending) {
        clearInterval(_pollFcm);
        window.__mednews_pending_fcm_token = null;
        handleFcmToken(_pending);
      }
    }

    // Attacher les listeners AVANT register() pour éviter la race condition
    PushNotifications.addListener('registration', ({ value: token }) => {
      if (platform === 'android') {
        // Android : token FCM direct
        localStorage.setItem(PUSH_TOKEN_KEY, token);
        sendPushToken(token);
      }
      // iOS : token APNs brut ignoré ici — on attend l'événement mednews_fcm_token de Firebase
    });

    PushNotifications.addListener('pushNotificationActionPerformed', ({ notification }) => {
      const d = notification.data || {};
      if (d.item_id) {
        window.location.href = '/portal?item=' + encodeURIComponent(d.item_id);
      } else if (d.specialty_slug) {
        window.location.href = '/portal?spec=' + encodeURIComponent(d.specialty_slug);
      } else if (!window.location.pathname.startsWith('/portal')) {
        window.location.href = '/portal';
      }
    });

    await PushNotifications.register();
  }

  // ── Biométrie ──────────────────────────────────────────────────
  async function isBiometricAvailable() {
    if (!isNative) return false;
    try {
      const { NativeBiometric } = cap.Plugins;
      const { isAvailable } = await NativeBiometric.isAvailable();
      return isAvailable;
    } catch { return false; }
  }

  async function saveCredentials(email, password) {
    if (!isNative) return;
    const { NativeBiometric } = cap.Plugins;
    await NativeBiometric.setCredentials({
      username: email,
      password,
      server: 'fr.mednews.app',
    });
  }

  async function getCredentials() {
    if (!isNative) return null;
    try {
      const { NativeBiometric } = cap.Plugins;
      return await NativeBiometric.getCredentials({ server: 'fr.mednews.app' });
    } catch { return null; }
  }

  async function deleteCredentials() {
    if (!isNative) return;
    try {
      const { NativeBiometric } = cap.Plugins;
      await NativeBiometric.deleteCredentials({ server: 'fr.mednews.app' });
    } catch {}
  }

  async function authenticateWithBiometric() {
    if (!isNative) return false;
    try {
      const { NativeBiometric } = cap.Plugins;
      await NativeBiometric.verifyIdentity({
        reason: 'Connectez-vous à MedNews',
        title: 'MedNews',
        subtitle: 'Utilisez Face ID ou Touch ID',
        description: 'Accès sécurisé à votre portail médical',
      });
      return true;
    } catch { return false; }
  }

  // ── Export global ──────────────────────────────────────────────
  window.MedNewsNative = {
    isNative: !!isNative,
    platform,
    registerPush,
    flushPushToken,
    isBiometricAvailable,
    saveCredentials,
    getCredentials,
    deleteCredentials,
    authenticateWithBiometric,
  };

  // Init push au chargement si natif
  if (isNative) {
    registerPush();
  }
})();
