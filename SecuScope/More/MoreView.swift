import SwiftUI

struct MoreView: View {
    var body: some View {
        NavigationStack {
            VStack {
                Text("更多功能")
                    .font(.title)
                    .padding()
                
                // 这里可以添加更多功能的界面内容
                
                Spacer()
            }
            .navigationTitle("更多")
        }
    }
}

#Preview {
    MoreView()
}
