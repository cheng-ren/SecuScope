import Foundation
import SwiftUI

// 检测结果枚举
enum DetectionResult {
    case none, success, failure
}

// 模块数据结构
struct SecurityModule: Identifiable, Hashable {
    let id = UUID()
    let name: String
    let icon: String
}

let modules: [SecurityModule] = [
    SecurityModule(name: "加密算法", icon: "lock.fill"),
    SecurityModule(name: "网络请求", icon: "network"),
    SecurityModule(name: "UI页面", icon: "iphone"),
    SecurityModule(name: "文件操作", icon: "doc.fill")
]
