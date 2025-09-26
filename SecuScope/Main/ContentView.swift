import SwiftUI

struct ContentView: View {
    @State private var selectedTab = 0

    var body: some View {
        HomePageView()
            .tabItem {
                Image(systemName: "house")
                Text("首页")
            }
    }
}

#Preview {
    ContentView()
}
