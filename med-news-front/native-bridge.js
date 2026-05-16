/**
 * native-bridge.js — MedNews Capacitor bridge
 * Pas de bundler : utilise window.Capacitor injecté par le runtime natif.
 * Chargé en dernier dans <body> sur toutes les pages HTML.
 */
(function () {
  const cap = window.Capacitor;
  const isNative = cap && cap.isNativePlatform();

  // ── Push notifications ─────────────────────────────────────────
  async function registerPush() {
    if (!isNative) return;
    const { PushNotifications } = cap.Plugins;

    let perm = await PushNotifications.checkPermissions();
    if (perm.receive === 'prompt') {
      perm = await PushNotifications.requestPermissions();
    }
    if (perm.receive !== 'granted') return;

    // Attacher les listeners AVANT register() pour éviter la race condition
    PushNotifications.addListener('registration', ({ value: token }) => {
      const accessToken = localStorage.getItem('access_token');
      if (!accessToken) return;
      fetch('/me/push-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        credentials: 'include',
        body: JSON.stringify({ token, platform: cap.getPlatform() }),
      }).catch(() => {});
    });

    PushNotifications.addListener('pushNotificationActionPerformed', ({ notification }) => {
      if (notification.data?.specialty_slug) {
        window.location.href = `/portal?spec=${notification.data.specialty_slug}`;
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
    platform: isNative ? cap.getPlatform() : 'web',
    registerPush,
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
