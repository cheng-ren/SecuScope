import SwiftUI

struct ModuleDetailView: View {
    let module: SecurityModule
    
    var body: some View {
        VStack {
            if module.name == "加解密" {
                EncryptionView()
            } else {
                defaultView
            }
        }
        .navigationTitle(module.name)
        .padding()
    }
    
    // MARK: - Default View for other modules
    private var defaultView: some View {
        VStack {
            Text("\(module.name) 详细内容")
                .font(.title)
                .padding()
            
            Text("这里是 \(module.name) 模块的具体实现和检测逻辑。")
                .padding()
            
            Spacer()
        }
    }
}

#Preview {
    NavigationStack {
        ModuleDetailView(module: modules[0])
    }
}
