import SwiftUI

struct HomePageView: View {
    @State private var isDetecting = false
    @State private var detectionResult: DetectionResult = .none
    @State private var showDetails = false
    // 添加越狱检测详细结果的状态
    @State private var jailbreakDetectionResult: JailbreakDetectionResult?
    
    var body: some View {
        NavigationStack {
            GeometryReader { geometry in
                ScrollView(.vertical, showsIndicators: false) {
                    VStack(spacing: 0) {
                        // 安全检测按钮 - 美化圆形大按钮
                        ZStack {
                            // 背景按钮，用于重新检测
                            Button(action: startDetection) {
                                Circle()
                                    .fill(
                                        LinearGradient(
                                            gradient: Gradient(colors: [Color.blue.opacity(0.8), Color.purple]),
                                            startPoint: .topLeading,
                                            endPoint: .bottomTrailing
                                        )
                                    )
                                    .frame(width: geometry.size.width * 0.7, height: geometry.size.width * 0.7)
                                    .shadow(color: Color.black.opacity(0.3), radius: 10, x: 0, y: 5)
                            }
                            .buttonStyle(PlainButtonStyle())
                            
                            if isDetecting {
                                
                                VStack(spacing: 10) {
                                    ProgressView()
                                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                        .scaleEffect(1.5)
                                    Text("检测中")
                                        .font(.title2)
                                        .fontWeight(.bold)
                                        .foregroundColor(.white)
                                }
                            } else {
                                // 检测结果显示内容
                                Button(action: {
                                    if detectionResult != .none {
                                        showDetails = true
                                    } else {
                                        startDetection()
                                    }
                                }) {
                                    VStack(spacing: 10) {
                                        if detectionResult == .success {
                                            Image(systemName: "checkmark.shield.fill")
                                                .font(.system(size: 48))
                                                .foregroundColor(.green)
                                            Text("设备安全")
                                                .font(.title2)
                                                .fontWeight(.bold)
                                                .foregroundColor(.white)
                                        } else if detectionResult == .failure {
                                            Image(systemName: "exclamationmark.triangle.fill")
                                                .font(.system(size: 48))
                                                .foregroundColor(.red)
                                            Text("设备已越狱")
                                                .font(.title2)
                                                .fontWeight(.bold)
                                                .foregroundColor(.red)
                                        } else {
                                            Image(systemName: "shield.checkerboard")
                                                .font(.system(size: 48))
                                            Text("越狱检测")
                                                .font(.title2)
                                                .fontWeight(.bold)
                                                .foregroundColor(.white)
                                        }
                                    }
                                    .foregroundColor(.white)
                                    .frame(width: geometry.size.width * 0.7, height: geometry.size.width * 0.7)
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal)
                        .padding(.top)
                        .disabled(isDetecting)
                        
                        Spacer().frame(height: 30)
                        
                        // 美化后的网格视图
                        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 16), count: 2), spacing: 16) {
                            ForEach(modules) { module in
                                if module.name == "加密算法" {
                                    NavigationLink(destination: EncryptionView()) {
                                        ModuleItemView(module: module)
                                    }
                                } else {
                                    NavigationLink(destination: ModuleDetailView(module: module)) {
                                        ModuleItemView(module: module)
                                    }
                                }
                            }
                        }
                        .padding()
                        
                        Spacer()
                    }
                }
            }
            .navigationTitle("逆向安全")
            .navigationBarTitleDisplayMode(.large)
            // 传递越狱检测结果到详情视图
            .navigationDestination(isPresented: $showDetails) {
                DetectionDetailsView(jailbreakDetectionResult: jailbreakDetectionResult)
                    .navigationBarTitleDisplayMode(.inline)
            }
        }
    }
    
    func startDetection() {
        isDetecting = true
        
        // 执行真实的越狱检测
        DispatchQueue.global(qos: .userInitiated).async {
            let result = SecurityDetector.shared.detailedJailbreakDetection()
            
            DispatchQueue.main.async {
                isDetecting = false
                jailbreakDetectionResult = result
                
                // 根据越狱检测结果设置显示状态
                detectionResult = result.isJailbroken ? .failure : .success
            }
        }
    }
}

// 美化的模块项视图
struct ModuleItemView: View {
    let module: SecurityModule
    
    var body: some View {
        VStack(spacing: 5) {
            Spacer()
            Image(systemName: module.icon)
                .font(.title)
                .foregroundColor(.blue)
                .frame(width: 60, height: 60)
            
            // 模块名称
            Text(module.name)
                .font(.headline)
                .fontWeight(.medium)
                .foregroundColor(.primary)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Material.regular)
                .shadow(color: Color.black.opacity(0.1), radius: 8, x: 0, y: 4)
        )
        .buttonStyle(ModuleItemButtonStyle())
    }
}

// 自定义按钮样式以支持按下动画
struct ModuleItemButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.95 : 1.0)
            .animation(.easeInOut(duration: 0.2), value: configuration.isPressed)
    }
}

#Preview {
    HomePageView()
}
