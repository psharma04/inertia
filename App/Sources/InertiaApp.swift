import SwiftUI

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
        }
        .onChange(of: scenePhase) { _, phase in
            defer {
                model.appSceneDidChange(isActive: phase == .active)
            }
            if phase == .active {
                // Re-establish any dropped connections on foreground return.
                // Skips servers that are already connected (serverStatuses == true)
                // OR currently connecting (connectionTasks != nil via idempotent guard).
                for server in model.servers
                where model.serverStatuses[server.id] != true {
                    model.connect(serverId: server.id)
                }
            }
        }
    }
}
