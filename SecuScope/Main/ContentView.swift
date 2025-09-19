import SwiftUI

struct ContentView: View {
    @State private var selectedTab = 0

    var body: some View {
        TabView(selection: $selectedTab) {
            // 首页内容
            HomePageView()
                .tabItem {
                    Image(systemName: "house")
                    Text("首页")
                }
                .tag(0)
            
            // 更多页面
            MoreView()
                .tabItem {
                    Image(systemName: "ellipsis.circle")
                    Text("更多")
                }
                .tag(1)
        }
    }
}

#Preview {
    ContentView()
}
