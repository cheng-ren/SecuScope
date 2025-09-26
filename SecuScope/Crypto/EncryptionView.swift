import SwiftUI

struct EncryptionAlgorithm: Identifiable, Equatable {
    let id = UUID()
    let name: String
    let color: Color
}

struct EncryptionStep: Identifiable, Equatable {
    let id = UUID()
    var algorithm: EncryptionAlgorithm
    var order: Int
}

struct EncryptionView: View {
    @State private var inputText = ""
    @State private var outputText = ""
    @State private var encryptionSteps: [EncryptionStep] = []
    @State private var availableAlgorithms: [EncryptionAlgorithm] = [
        EncryptionAlgorithm(name: "Base64", color: .blue),
        EncryptionAlgorithm(name: "MD5", color: .green),
        EncryptionAlgorithm(name: "AES", color: .purple),
        EncryptionAlgorithm(name: "SHA256", color: .orange),
        EncryptionAlgorithm(name: "DES", color: .cyan),
        EncryptionAlgorithm(name: "RSA", color: .red),
    ]
    @State private var isProcessing = false
    @FocusState private var isTextEditorFocused: Bool
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    // 输入区域
                    VStack(alignment: .leading, spacing: 10) {
                        Text("输入文本")
                            .font(.headline)
                        TextEditor(text: $inputText)
                            .frame(height: 80)
                            .padding(5)
                            .overlay(
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                            )
                            .focused($isTextEditorFocused)
                    }
                    
                    // 算法选择区域
                    VStack(alignment: .leading, spacing: 10) {
                        Text("可用算法")
                            .font(.headline)
                        
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack {
                                ForEach(availableAlgorithms) { algorithm in
                                    AlgorithmChip(algorithm: algorithm)
                                        .onTapGesture {
                                            addAlgorithmToFlow(algorithm)
                                        }
                                }
                            }
                           
                        }
                    }
                    
                    // 加密流程区域
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("加密流程")
                                .font(.headline)
                            Spacer()
                            Button(action: clearFlow) {
                                Image(systemName: "trash")
                                    .foregroundColor(.red)
                            }
                        }
                        
                        if encryptionSteps.isEmpty {
                            Text("请从上方添加算法来构建加密流程")
                                .foregroundColor(.gray)
                                .frame(maxWidth: .infinity, minHeight: 100)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 8)
                                        .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                                )
                        } else {
                            List {
                                ForEach($encryptionSteps) { $step in
                                    EncryptionStepRowView(
                                        step: $step,
                                        totalSteps: encryptionSteps.count
                                    )
                                    .listRowInsets(EdgeInsets(top: 0, leading: 0, bottom: 5, trailing: 0))
                                }
                                .onMove(perform: moveStep)
                                .onDelete(perform: deleteStep)
                            }
                            .frame(height: CGFloat(encryptionSteps.count) * 60)
                            .listStyle(InsetListStyle())
                            .listRowSeparator(.hidden)
                        }
                    }
                    
                    // 控制按钮
                    HStack {
                        Button(action: runEncryption) {
                            HStack {
                                if isProcessing {
                                    ProgressView()
                                        .tint(.white)
                                }
                                Image(systemName: "play.fill")
                                    .font(.headline)
                                    .foregroundColor(.red)
                            }
                            .foregroundColor(.white)
                            .frame(width: 40, height: 40, alignment: .center)
                            .padding()
                            .background(isProcessing ? Color.gray : Color.blue)
                            .cornerRadius(40)
                            .disabled(isProcessing)
                        }
                    }
                    
                    // 输出结果
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("输出结果")
                                .font(.headline)
                            Spacer()
                            Button(action: {
                                UIPasteboard.general.string = outputText
                            }) {
                                Image(systemName: "doc.on.doc")
                            }
                        }
                        Text(outputText)
                            .frame(height: 80, alignment: .topLeading)
                            .padding(5)
                            .overlay(
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                            )
                            .textSelection(.enabled)
                            .multilineTextAlignment(.leading) // 确保文本左对齐
                    }.frame(maxWidth: .infinity)
                    
                    Spacer()
                }
                .padding(.vertical)
                .padding(.horizontal)
            }
            .navigationTitle("加密流程")
            .navigationBarTitleDisplayMode(.large)
            .scrollDismissesKeyboard(.interactively)
            .onTapGesture {
                isTextEditorFocused = false
            }
            .toolbar(.hidden, for: .tabBar)
        }
    }
    
    // MARK: - Helper Functions
    private func addAlgorithmToFlow(_ algorithm: EncryptionAlgorithm) {
        let newStep = EncryptionStep(algorithm: algorithm, order: encryptionSteps.count)
        encryptionSteps.append(newStep)
    }
    
    private func moveStep(source: IndexSet, destination: Int) {
        encryptionSteps.move(fromOffsets: source, toOffset: destination)
        reorderSteps()
    }
    
    private func deleteStep(offsets: IndexSet) {
        encryptionSteps.remove(atOffsets: offsets)
        reorderSteps()
    }
    
    private func reorderSteps() {
        for i in 0..<encryptionSteps.count {
            encryptionSteps[i].order = i
            print("\(encryptionSteps[i].algorithm.name) order: \(encryptionSteps[i].order)")
        }
    }
    
    private func clearFlow() {
        encryptionSteps = []
    }
    
    private func runEncryption() {
        isProcessing = true
        outputText = "处理中..."
        
        DispatchQueue.global(qos: .userInitiated).async {
            var result = inputText
            
            // 按顺序执行加密步骤
            for step in encryptionSteps.sorted(by: { $0.order < $1.order }) {
                switch step.algorithm.name {
                case "Base64":
                    if let data = result.data(using: .utf8) {
                        result = data.base64EncodedString()
                    }
                case "MD5":
                    result = EncryptionUtils.md5(result)
                case "AES":
                    // 这里需要一个密钥，为简化示例我们使用固定密钥
                    if let encryptedData = EncryptionUtils.aesEncrypt(result, key: "defaultKey12345") {
                        result = encryptedData.base64EncodedString()
                    }
                case "SHA256":
                    result = EncryptionUtils.sha256(result)
                default:
                    break
                }
            }
            
            DispatchQueue.main.async {
                self.outputText = result
                self.isProcessing = false
            }
        }
    }
}

// MARK: - AlgorithmChip View
struct AlgorithmChip: View {
    let algorithm: EncryptionAlgorithm
    
    var body: some View {
        Text(algorithm.name)
        .foregroundColor(.white)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(algorithm.color)
        .cornerRadius(20)
    }
}

// MARK: - EncryptionStepRowView
struct EncryptionStepRowView: View {
    @Binding var step: EncryptionStep
    var totalSteps: Int
    
    var body: some View {
        HStack {
            
            Text(step.algorithm.name)
            .foregroundColor(.white)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(step.algorithm.color)
            .cornerRadius(20)
            
            Spacer()
            
            // 添加拖动指示图标
            Image(systemName: "line.horizontal.3")
                .foregroundColor(.gray)
                .padding(.trailing, 8)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background()
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.gray.opacity(0.3), lineWidth: 1)
        )
    }
}

#Preview {
    EncryptionView()
}
