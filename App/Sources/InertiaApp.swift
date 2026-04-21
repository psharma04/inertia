import SwiftUI
import BackgroundTasks

@main
struct InertiaApp: App {
    @State private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(model)
                .task {
                    // Keep transport connectivity independent of onboarding/lock UI
                    // so announces and routing stay alive across app states.
                    model.connectAll()
                }
                .onOpenURL { url in
                    model.handleDeepLink(url)
                }
        }
        .onChange(of: scenePhase) { _, phase in
            defer {
                model.appSceneDidChange(isActive: phase == .active)
            }
            if phase == .active {
                // Re-establish any dropped connections on foreground return.
                for server in model.servers
                where model.serverStatuses[server.id] != true {
                    model.connect(serverId: server.id)
                }
                model.clearBadge()
                Task { await model.processRetryQueue() }
            }
        }
        // BGAppRefreshTask fires periodically even when the app is terminated,
        // giving ~30s to sync the propagation inbox and post local notifications.
        .backgroundTask(.appRefresh(AppModel.backgroundRefreshTaskID)) {
            await model.performBackgroundRefresh()
        }
    }
}
