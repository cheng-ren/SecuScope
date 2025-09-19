# SecuScope
iOS 逆向安全桩App - iOS Security Analysis Framework

## 概述

SecuScope 是一个全面的 iOS 安全分析框架，用于检测和分析 iOS 应用程序中的各种安全漏洞。该框架提供了多层次的安全检测功能，包括加密算法分析、网络安全监控、UI控件安全检查和文件操作安全审计。

## 功能特性

### 🔒 安全检测模块 (SecurityDetector)
- **越狱检测**: 检测设备是否已越狱
- **调试器检测**: 检测调试器和动态分析工具
- **运行时保护**: 检测代码注入和 Hook 框架
- **反调试机制**: 实施多层反调试保护

### 🔐 加密算法分析 (EncryptionAnalyzer)
- **算法强度评估**: 分析使用的加密算法强度
- **密钥管理检查**: 检测硬编码密钥和不安全的密钥存储
- **加密实现审计**: 识别加密实现中的安全弱点
- **性能测试**: 测试加密算法的性能和正确性

### 🌐 网络安全监控 (NetworkMonitor)
- **TLS/SSL 分析**: 检查证书有效性和 TLS 配置
- **流量安全检测**: 监控未加密的网络流量
- **DNS 安全**: 检查 DNS 配置和 DNS over HTTPS 支持
- **网络代理检测**: 识别可能的中间人攻击

### 🖥️ UI 安全检查 (UISecurityChecker)
- **敏感数据泄露**: 检测 UI 中的敏感信息暴露
- **屏幕保护**: 检查屏幕截图和录制防护
- **输入安全**: 分析键盘输入和自动完成安全性
- **WebView 安全**: 检查 WebView 配置和 URL 处理

### 📁 文件操作监控 (FileOperationMonitor)
- **文件权限审计**: 检查文件和目录权限配置
- **敏感文件检测**: 识别可能包含敏感数据的文件
- **数据库安全**: 分析 SQLite 数据库加密状态
- **备份安全**: 检查文件备份配置

## 系统要求

- iOS 13.0 或更高版本
- Xcode 14.0 或更高版本
- Swift 5.0 或更高版本

## 项目结构

```
SecuScope/
├── SecuScope/
│   ├── AppDelegate.swift
│   ├── SceneDelegate.swift
│   ├── ViewController.swift
│   ├── Security/
│   │   ├── SecurityDetector.swift      # 主安全检测器
│   │   ├── EncryptionAnalyzer.swift    # 加密算法分析器
│   │   ├── NetworkMonitor.swift        # 网络安全监控器
│   │   ├── UISecurityChecker.swift     # UI安全检查器
│   │   └── FileOperationMonitor.swift  # 文件操作监控器
│   ├── Base.lproj/
│   │   ├── Main.storyboard
│   │   └── LaunchScreen.storyboard
│   ├── Assets.xcassets/
│   └── Info.plist
├── SecuScope.xcodeproj/
└── README.md
```

## 快速开始

1. **克隆项目**
   ```bash
   git clone https://github.com/cheng-ren/SecuScope.git
   cd SecuScope
   ```

2. **打开项目**
   ```bash
   open SecuScope.xcodeproj
   ```

3. **运行应用**
   - 选择目标设备或模拟器
   - 按 Cmd+R 运行应用

## 使用方法

### 基本用法

1. **启动安全监控**
   ```swift
   SecurityDetector.shared.startMonitoring()
   ```

2. **执行全面安全扫描**
   ```swift
   let securityReport = SecurityDetector.shared.performComprehensiveSecurityCheck()
   print(securityReport)
   ```

3. **分析特定安全域**
   ```swift
   // 加密分析
   let encryptionAnalyzer = EncryptionAnalyzer()
   let encryptionReport = encryptionAnalyzer.analyzeEncryption()
   
   // 网络安全分析
   let networkMonitor = NetworkMonitor()
   networkMonitor.startMonitoring { result in
       print("网络安全状态: \(result)")
   }
   
   // UI安全检查
   let uiChecker = UISecurityChecker()
   let uiReport = uiChecker.analyzeUIComponents()
   
   // 文件操作审计
   let fileMonitor = FileOperationMonitor()
   let fileReport = fileMonitor.analyzeFileOperations()
   ```

### 高级功能

#### 自定义安全检测规则
```swift
// 添加自定义威胁检测
extension SecurityDetector {
    func detectCustomThreat() {
        // 实现自定义检测逻辑
    }
}
```

#### 集成到现有应用
```swift
class MyAppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        
        // 启动 SecuScope 监控
        SecurityDetector.shared.startMonitoring()
        
        return true
    }
}
```

## API 文档

### SecurityDetector
- `startMonitoring()`: 启动安全监控
- `stopMonitoring()`: 停止安全监控
- `isSecure() -> Bool`: 检查整体安全状态
- `performComprehensiveSecurityCheck() -> String`: 执行全面安全检查

### EncryptionAnalyzer
- `analyzeEncryption() -> String`: 分析加密算法使用情况
- `testAESEncryption() -> String`: 测试 AES 加密功能

### NetworkMonitor
- `startMonitoring(completion:)`: 启动网络监控
- `analyzeNetworkSecurity() -> String`: 分析网络安全状态
- `performNetworkSecurityTest() -> String`: 执行网络安全测试

### UISecurityChecker
- `startMonitoring(completion:)`: 启动 UI 安全检查
- `analyzeUIComponents() -> String`: 分析 UI 组件安全性
- `performLiveUISecurityTest() -> String`: 执行实时 UI 安全测试

### FileOperationMonitor
- `startMonitoring(completion:)`: 启动文件操作监控
- `analyzeFileOperations() -> String`: 分析文件操作安全性
- `performFileSystemSecurityTest() -> String`: 执行文件系统安全测试

## 安全建议

### 通用安全最佳实践
1. **数据保护**
   - 使用 Keychain 存储敏感数据
   - 对数据库文件启用加密
   - 避免在代码中硬编码密钥

2. **网络安全**
   - 始终使用 HTTPS
   - 实施证书固定
   - 验证服务器证书

3. **代码保护**
   - 启用代码混淆
   - 实施反调试机制
   - 使用应用程序完整性检查

4. **UI安全**
   - 对敏感输入启用安全文本输入
   - 实施屏幕截图保护
   - 避免在UI中显示敏感信息

## 贡献指南

欢迎贡献代码！请遵循以下步骤：

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 许可证

本项目采用 MIT 许可证。详细信息请参阅 [LICENSE](LICENSE) 文件。

## 联系方式

- 项目维护者: [cheng-ren](https://github.com/cheng-ren)
- 问题反馈: [Issues](https://github.com/cheng-ren/SecuScope/issues)

## 更新日志

### v1.0.0 (2024-09-19)
- ✨ 初始版本发布
- 🔒 实现基础安全检测功能
- 🔐 添加加密算法分析器
- 🌐 实现网络安全监控
- 🖥️ 添加UI安全检查器
- 📁 实现文件操作监控器
- 📱 创建用户界面和报告系统

---

**免责声明**: SecuScope 仅用于安全研究和教育目的。请确保在使用本工具时遵守相关法律法规。
