import SwiftUI

struct MoreView: View {
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    // 项目介绍部分
                    SectionView(title: "简介") {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("SecuScope")
                                .font(.headline)
                            
                            Text("这是一个 逆向的桩 项目, ")
                            
                            Text("功能特色：")
                                .font(.headline)
                                .padding(.top)
                            
                            VStack(alignment: .leading, spacing: 5) {
                                Text("• 安全检测")
                                Text("• 安全防护")
                                Text("• 为自动化脚本支持打桩服务")
                            }
                        }
                    }
                    
                    // 作者信息部分
                    SectionView(title: "作者") {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("任成")
                                .font(.headline)
                            
                            Text("一位热爱 iOS 开发的独立开发者")
                            
                            Text("联系方式：")
                                .font(.headline)
                                .padding(.top)
                            
                            VStack(alignment: .leading, spacing: 5) {
                                Text("• 邮箱: rencheng11@icloud.com")
                                Text("• GitHub: github.com/cheng-ren")
                            }
                        }
                    }
                    
                    Spacer()
                }
                .padding()
            }
            .navigationTitle("关于")
        }
    }
}

// 自定义 Section 视图组件
struct SectionView<Content: View>: View {
    let title: String
    let content: Content
    
    init(title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.title2)
                .fontWeight(.semibold)
            
            content
            
            Divider()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

#Preview {
    MoreView()
}
