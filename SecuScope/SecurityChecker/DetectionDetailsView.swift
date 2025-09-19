import SwiftUI

struct DetectionDetailsView: View {
    // 接收越狱检测详细结果
    let jailbreakDetectionResult: JailbreakDetectionResult?
    
    var body: some View {
        List {
            // 显示越狱检测结果（如果有的话）
            if let result = jailbreakDetectionResult {
                ForEach(result.details, id: \.checkType) { detail in
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(detail.checkType.description)
                                .font(.headline)
                                .fontWeight(.medium)
                                .foregroundColor(.primary)
                            if !detail.description.isEmpty {
                                Text(detail.description)
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                            }
                        }
                        Spacer()
                        Image(systemName: detail.isDetected ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                            .foregroundColor(detail.isDetected ? .orange : .green)
                            .font(.title2)
//                            .symbolRenderingMode(.multicolor)
                    }
                    .padding(.vertical, 8)
                    .padding(.horizontal, 4)
                }
//                .listRowSeparator(.hidden)
            }
        }
        .listStyle(PlainListStyle())
        .navigationTitle("检测详情")
        .navigationBarTitleDisplayMode(.inline)
    }
}

#Preview {
    NavigationStack {
        DetectionDetailsView(jailbreakDetectionResult: nil)
    }
}
