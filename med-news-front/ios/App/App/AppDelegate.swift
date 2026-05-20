import UIKit
import WebKit
import UserNotifications
import Capacitor
import FirebaseCore
import FirebaseMessaging

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?
    /// Token FCM en attente d'être livré au WebView
    var pendingFcmToken: String?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        FirebaseApp.configure()
        Messaging.messaging().delegate = self
        // Gérer les notifications en foreground (bannière même app ouverte)
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func applicationWillResignActive(_ application: UIApplication) {}
    func applicationDidEnterBackground(_ application: UIApplication) {}
    func applicationWillEnterForeground(_ application: UIApplication) {}
    func applicationDidBecomeActive(_ application: UIApplication) {}
    func applicationWillTerminate(_ application: UIApplication) {}

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        return ApplicationDelegateProxy.shared.application(app, open: url, options: options)
    }

    func application(_ application: UIApplication, continue userActivity: NSUserActivity, restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
        return ApplicationDelegateProxy.shared.application(application, continue: userActivity, restorationHandler: restorationHandler)
    }

    // Pont APNs → Firebase
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Messaging.messaging().apnsToken = deviceToken
        NotificationCenter.default.post(name: .capacitorDidRegisterForRemoteNotifications, object: deviceToken)
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        NotificationCenter.default.post(name: .capacitorDidFailToRegisterForRemoteNotifications, object: error)
    }
}

// MARK: - Firebase Messaging Delegate
extension AppDelegate: MessagingDelegate {
    func messaging(_ messaging: Messaging, didReceiveRegistrationToken fcmToken: String?) {
        print("[MedNews] *** FCM token received: \(fcmToken ?? "NIL")")
        guard let token = fcmToken else {
            print("[MedNews] *** FCM token is NIL — check APNs setup")
            return
        }
        pendingFcmToken = token
        // 1. Injecter un WKUserScript qui se déclenche à chaque page
        injectUserScript(token: token)
        // 2. Essayer aussi un evaluateJavaScript immédiat (si la page est déjà chargée)
        tryEvaluateJavaScript(token: token)
    }
}

// MARK: - Token injection helpers
extension AppDelegate {

    /// Script inline injecté dans la page au chargement — fiable même si le token arrive tôt
    func injectUserScript(token: String) {
        DispatchQueue.main.async {
            guard let vc = self.window?.rootViewController as? CAPBridgeViewController,
                  let wv = vc.bridge?.webView else { return }

            let safeToken = token.replacingOccurrences(of: "\\", with: "\\\\")
                                  .replacingOccurrences(of: "'", with: "\\'")

            let source = """
                window.__mednews_pending_fcm_token = '\(safeToken)';
                window.dispatchEvent(new CustomEvent('mednews_fcm_token',
                    { detail: { token: '\(safeToken)' } }));
            """
            // Supprimer l'ancien script s'il existe
            let controller = wv.configuration.userContentController
            let existing = controller.userScripts.filter { $0.source.contains("__mednews_pending_fcm_token") }
            if !existing.isEmpty {
                controller.removeAllUserScripts()
            }
            let script = WKUserScript(source: source,
                                      injectionTime: .atDocumentEnd,
                                      forMainFrameOnly: true)
            controller.addUserScript(script)
        }
    }

    /// Tentative directe d'evaluateJavaScript (fonctionne si la page est déjà chargée)
    func tryEvaluateJavaScript(token: String) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            guard let vc = self.window?.rootViewController as? CAPBridgeViewController,
                  let wv = vc.bridge?.webView,
                  self.pendingFcmToken != nil else { return }

            let safeToken = token.replacingOccurrences(of: "\\", with: "\\\\")
                                  .replacingOccurrences(of: "'", with: "\\'")
            let js = """
                window.__mednews_pending_fcm_token = '\(safeToken)';
                window.dispatchEvent(new CustomEvent('mednews_fcm_token',
                    { detail: { token: '\(safeToken)' } }));
            """
            wv.evaluateJavaScript(js) { _, error in
                if error == nil { self.pendingFcmToken = nil }
            }
        }
    }
}

// MARK: - Foreground notification display
extension AppDelegate: UNUserNotificationCenterDelegate {
    /// Appelé quand une notification arrive alors que l'app est en foreground
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        // Afficher bannière + son + badge même app ouverte
        if #available(iOS 14.0, *) {
            completionHandler([.banner, .sound, .badge])
        } else {
            completionHandler([.alert, .sound, .badge])
        }
    }

    /// Appelé quand l'utilisateur tape sur la notification
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        // Laisser Capacitor gérer le tap (deeplink, etc.)
        NotificationCenter.default.post(
            name: Notification.Name("CAPNotificationsPluginDidReceiveResponse"),
            object: response
        )
        completionHandler()
    }
}
