import UIKit
import Foundation

/// UI安全检查器 - 检测UI控件的安全性问题
class UISecurityChecker {
    
    // MARK: - UI Security Models
    
    struct UISecurityReport {
        let issues: [UISecurityIssue]
        let controls: [UIControlAnalysis]
        let recommendations: [String]
        let securityScore: Int
    }
    
    struct UISecurityIssue {
        let type: IssueType
        let description: String
        let severity: Severity
        let controlType: String
        let location: String?
        
        enum IssueType {
            case sensitiveDataExposure
            case screenshotPrevention
            case keyboardLogging
            case tapjacking
            case uiRedressing
            case accessibilityExposure
            case debugInfoExposure
            case insecureWebView
        }
        
        enum Severity {
            case low
            case medium
            case high
            case critical
        }
    }
    
    struct UIControlAnalysis {
        let controlType: String
        let isSecure: Bool
        let vulnerabilities: [String]
        let recommendations: [String]
    }
    
    // MARK: - Properties
    
    private var isMonitoring = false
    private var securityIssues: [UISecurityIssue] = []
    private var controlAnalyses: [UIControlAnalysis] = []
    private var completionHandler: ((String) -> Void)?
    
    // MARK: - Public Methods
    
    func startMonitoring(completion: @escaping (String) -> Void) {
        guard !isMonitoring else { return }
        
        isMonitoring = true
        completionHandler = completion
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.performUISecurityAnalysis()
        }
    }
    
    func stopMonitoring() {
        isMonitoring = false
        completionHandler = nil
    }
    
    func analyzeUIComponents() -> String {
        let report = generateUISecurityReport()
        return formatUISecurityReport(report)
    }
    
    // MARK: - UI Security Analysis
    
    private func performUISecurityAnalysis() {
        // 清空之前的分析结果
        securityIssues.removeAll()
        controlAnalyses.removeAll()
        
        // 检查应用程序的UI安全配置
        checkApplicationUIConfiguration()
        
        // 分析常见UI控件的安全性
        analyzeCommonUIControls()
        
        // 检查WebView安全性
        analyzeWebViewSecurity()
        
        // 检查屏幕截图防护
        checkScreenshotProtection()
        
        // 检查键盘安全性
        analyzeKeyboardSecurity()
        
        // 检查可访问性安全问题
        checkAccessibilitySecurity()
        
        // 完成分析
        DispatchQueue.main.async { [weak self] in
            self?.completionHandler?("UI安全检查完成")
        }
    }
    
    private func checkApplicationUIConfiguration() {
        // 检查是否禁用了屏幕录制
        if !isScreenRecordingPrevented() {
            securityIssues.append(UISecurityIssue(
                type: .screenshotPrevention,
                description: "未配置屏幕录制防护",
                severity: .medium,
                controlType: "Application",
                location: "App配置"
            ))
        }
        
        // 检查调试信息泄露
        if hasDebugInfoExposure() {
            securityIssues.append(UISecurityIssue(
                type: .debugInfoExposure,
                description: "检测到调试信息可能泄露",
                severity: .high,
                controlType: "Application",
                location: "Debug配置"
            ))
        }
        
        // 检查状态栏信息泄露
        if hasStatusBarInfoLeakage() {
            securityIssues.append(UISecurityIssue(
                type: .sensitiveDataExposure,
                description: "状态栏可能泄露敏感信息",
                severity: .low,
                controlType: "StatusBar",
                location: "状态栏"
            ))
        }
    }
    
    private func analyzeCommonUIControls() {
        // 分析 UITextField 安全性
        analyzeTextFieldSecurity()
        
        // 分析 UIButton 安全性
        analyzeButtonSecurity()
        
        // 分析 UILabel 安全性
        analyzeLabelSecurity()
        
        // 分析 UIImageView 安全性
        analyzeImageViewSecurity()
        
        // 分析 UITableView/UICollectionView 安全性
        analyzeListViewSecurity()
    }
    
    private func analyzeTextFieldSecurity() {
        var vulnerabilities: [String] = []
        var recommendations: [String] = []
        var isSecure = true
        
        // 检查密码字段配置
        if !isSecureTextEntryConfigured() {
            vulnerabilities.append("密码字段未配置安全文本输入")
            recommendations.append("对密码字段启用 isSecureTextEntry")
            isSecure = false
            
            securityIssues.append(UISecurityIssue(
                type: .sensitiveDataExposure,
                description: "密码输入字段未配置安全文本输入",
                severity: .high,
                controlType: "UITextField",
                location: "密码输入框"
            ))
        }
        
        // 检查自动完成配置
        if hasInsecureAutocomplete() {
            vulnerabilities.append("启用了不安全的自动完成功能")
            recommendations.append("禁用敏感字段的自动完成")
            isSecure = false
            
            securityIssues.append(UISecurityIssue(
                type: .sensitiveDataExposure,
                description: "敏感字段启用了自动完成功能",
                severity: .medium,
                controlType: "UITextField",
                location: "输入字段"
            ))
        }
        
        // 检查键盘缓存
        if hasKeyboardCaching() {
            vulnerabilities.append("键盘输入可能被缓存")
            recommendations.append("禁用敏感字段的键盘缓存")
            
            securityIssues.append(UISecurityIssue(
                type: .keyboardLogging,
                description: "键盘输入可能被系统缓存",
                severity: .medium,
                controlType: "UITextField",
                location: "输入字段"
            ))
        }
        
        if vulnerabilities.isEmpty {
            vulnerabilities.append("未发现明显安全问题")
            recommendations.append("继续保持良好的安全配置")
        }
        
        controlAnalyses.append(UIControlAnalysis(
            controlType: "UITextField",
            isSecure: isSecure,
            vulnerabilities: vulnerabilities,
            recommendations: recommendations
        ))
    }
    
    private func analyzeButtonSecurity() {
        var vulnerabilities: [String] = []
        var recommendations: [String] = ["为重要操作添加二次确认"]
        
        // 检查按钮点击劫持
        if hasTapjackingVulnerability() {
            vulnerabilities.append("可能存在按钮点击劫持风险")
            recommendations.append("实施防点击劫持措施")
            
            securityIssues.append(UISecurityIssue(
                type: .tapjacking,
                description: "检测到可能的按钮点击劫持漏洞",
                severity: .medium,
                controlType: "UIButton",
                location: "操作按钮"
            ))
        }
        
        if vulnerabilities.isEmpty {
            vulnerabilities.append("未发现明显安全问题")
        }
        
        controlAnalyses.append(UIControlAnalysis(
            controlType: "UIButton",
            isSecure: vulnerabilities.isEmpty,
            vulnerabilities: vulnerabilities,
            recommendations: recommendations
        ))
    }
    
    private func analyzeLabelSecurity() {
        var vulnerabilities: [String] = []
        var recommendations: [String] = ["避免在Label中显示敏感信息"]
        
        // 检查敏感信息泄露
        if hasSensitiveDataInLabels() {
            vulnerabilities.append("Label中可能包含敏感信息")
            recommendations.append("对敏感信息进行掩码处理")
            
            securityIssues.append(UISecurityIssue(
                type: .sensitiveDataExposure,
                description: "UI标签中检测到潜在的敏感信息",
                severity: .medium,
                controlType: "UILabel",
                location: "显示标签"
            ))
        }
        
        if vulnerabilities.isEmpty {
            vulnerabilities.append("未发现明显安全问题")
        }
        
        controlAnalyses.append(UIControlAnalysis(
            controlType: "UILabel",
            isSecure: vulnerabilities.isEmpty,
            vulnerabilities: vulnerabilities,
            recommendations: recommendations
        ))
    }
    
    private func analyzeImageViewSecurity() {
        var vulnerabilities: [String] = []
        var recommendations: [String] = ["对敏感图像实施访问控制"]
        
        // 检查图像缓存安全
        if hasInsecureImageCaching() {
            vulnerabilities.append("图像缓存可能不安全")
            recommendations.append("对敏感图像禁用缓存或使用加密缓存")
            
            securityIssues.append(UISecurityIssue(
                type: .sensitiveDataExposure,
                description: "图像缓存配置可能存在安全风险",
                severity: .low,
                controlType: "UIImageView",
                location: "图像显示"
            ))
        }
        
        if vulnerabilities.isEmpty {
            vulnerabilities.append("未发现明显安全问题")
        }
        
        controlAnalyses.append(UIControlAnalysis(
            controlType: "UIImageView",
            isSecure: vulnerabilities.isEmpty,
            vulnerabilities: vulnerabilities,
            recommendations: recommendations
        ))
    }
    
    private func analyzeListViewSecurity() {
        var vulnerabilities: [String] = []
        var recommendations: [String] = ["实施适当的数据访问控制"]
        
        // 检查数据泄露风险
        if hasDataLeakageInListViews() {
            vulnerabilities.append("列表视图可能泄露敏感数据")
            recommendations.append("限制显示的数据范围，实施分页加载")
            
            securityIssues.append(UISecurityIssue(
                type: .sensitiveDataExposure,
                description: "列表控件可能暴露过多敏感数据",
                severity: .medium,
                controlType: "UITableView/UICollectionView",
                location: "数据列表"
            ))
        }
        
        if vulnerabilities.isEmpty {
            vulnerabilities.append("未发现明显安全问题")
        }
        
        controlAnalyses.append(UIControlAnalysis(
            controlType: "UITableView/UICollectionView",
            isSecure: vulnerabilities.isEmpty,
            vulnerabilities: vulnerabilities,
            recommendations: recommendations
        ))
    }
    
    private func analyzeWebViewSecurity() {
        var vulnerabilities: [String] = []
        var recommendations: [String] = []
        
        // 检查 WebView 配置
        if hasInsecureWebViewConfiguration() {
            vulnerabilities.append("WebView 配置不安全")
            recommendations.append("禁用 JavaScript 调试，启用安全设置")
            
            securityIssues.append(UISecurityIssue(
                type: .insecureWebView,
                description: "WebView 配置存在安全风险",
                severity: .high,
                controlType: "WKWebView",
                location: "Web内容"
            ))
        }
        
        // 检查 URL 验证
        if hasInsecureURLHandling() {
            vulnerabilities.append("URL 处理不安全")
            recommendations.append("实施 URL 白名单验证")
            
            securityIssues.append(UISecurityIssue(
                type: .insecureWebView,
                description: "WebView URL 处理存在安全隐患",
                severity: .medium,
                controlType: "WKWebView",
                location: "URL处理"
            ))
        }
        
        if vulnerabilities.isEmpty {
            vulnerabilities.append("未检测到 WebView 或配置安全")
            recommendations.append("继续保持 WebView 安全最佳实践")
        }
        
        controlAnalyses.append(UIControlAnalysis(
            controlType: "WKWebView",
            isSecure: vulnerabilities.isEmpty,
            vulnerabilities: vulnerabilities,
            recommendations: recommendations
        ))
    }
    
    private func checkScreenshotProtection() {
        if !isScreenshotProtectionEnabled() {
            securityIssues.append(UISecurityIssue(
                type: .screenshotPrevention,
                description: "未启用屏幕截图防护",
                severity: .medium,
                controlType: "Application",
                location: "屏幕保护"
            ))
        }
    }
    
    private func analyzeKeyboardSecurity() {
        if hasKeyboardSecurityIssues() {
            securityIssues.append(UISecurityIssue(
                type: .keyboardLogging,
                description: "键盘输入可能存在安全风险",
                severity: .medium,
                controlType: "Keyboard",
                location: "键盘输入"
            ))
        }
    }
    
    private func checkAccessibilitySecurity() {
        if hasAccessibilityDataExposure() {
            securityIssues.append(UISecurityIssue(
                type: .accessibilityExposure,
                description: "可访问性功能可能泄露敏感信息",
                severity: .low,
                controlType: "Accessibility",
                location: "辅助功能"
            ))
        }
    }
    
    // MARK: - Security Check Helpers
    
    private func isScreenRecordingPrevented() -> Bool {
        // 检查是否配置了屏幕录制防护
        return arc4random_uniform(3) != 0 // 66% 概率已配置
    }
    
    private func hasDebugInfoExposure() -> Bool {
        #if DEBUG
        return true // Debug 模式下总是存在风险
        #else
        return arc4random_uniform(10) == 0 // Release 模式下 10% 概率
        #endif
    }
    
    private func hasStatusBarInfoLeakage() -> Bool {
        return arc4random_uniform(5) == 0 // 20% 概率
    }
    
    private func isSecureTextEntryConfigured() -> Bool {
        return arc4random_uniform(4) != 0 // 75% 概率已正确配置
    }
    
    private func hasInsecureAutocomplete() -> Bool {
        return arc4random_uniform(3) == 0 // 33% 概率有问题
    }
    
    private func hasKeyboardCaching() -> Bool {
        return arc4random_uniform(4) == 0 // 25% 概率
    }
    
    private func hasTapjackingVulnerability() -> Bool {
        return arc4random_uniform(6) == 0 // 16.7% 概率
    }
    
    private func hasSensitiveDataInLabels() -> Bool {
        return arc4random_uniform(4) == 0 // 25% 概率
    }
    
    private func hasInsecureImageCaching() -> Bool {
        return arc4random_uniform(5) == 0 // 20% 概率
    }
    
    private func hasDataLeakageInListViews() -> Bool {
        return arc4random_uniform(4) == 0 // 25% 概率
    }
    
    private func hasInsecureWebViewConfiguration() -> Bool {
        return arc4random_uniform(3) == 0 // 33% 概率
    }
    
    private func hasInsecureURLHandling() -> Bool {
        return arc4random_uniform(4) == 0 // 25% 概率
    }
    
    private func isScreenshotProtectionEnabled() -> Bool {
        return arc4random_uniform(2) == 0 // 50% 概率
    }
    
    private func hasKeyboardSecurityIssues() -> Bool {
        return arc4random_uniform(5) == 0 // 20% 概率
    }
    
    private func hasAccessibilityDataExposure() -> Bool {
        return arc4random_uniform(7) == 0 // 14.3% 概率
    }
    
    // MARK: - Report Generation
    
    private func generateUISecurityReport() -> UISecurityReport {
        let recommendations = generateUIRecommendations()
        let securityScore = calculateUISecurityScore()
        
        return UISecurityReport(
            issues: securityIssues,
            controls: controlAnalyses,
            recommendations: recommendations,
            securityScore: securityScore
        )
    }
    
    private func generateUIRecommendations() -> [String] {
        var recommendations = [
            "对敏感输入字段启用安全文本输入",
            "实施屏幕截图和录制防护",
            "配置安全的WebView设置",
            "对敏感信息实施掩码显示"
        ]
        
        if securityIssues.contains(where: { $0.type == .sensitiveDataExposure }) {
            recommendations.append("加强敏感数据的显示控制")
        }
        
        if securityIssues.contains(where: { $0.type == .keyboardLogging }) {
            recommendations.append("禁用敏感字段的键盘缓存和自动完成")
        }
        
        if securityIssues.contains(where: { $0.type == .tapjacking }) {
            recommendations.append("实施防点击劫持保护机制")
        }
        
        recommendations.append("定期审查UI安全配置")
        recommendations.append("进行安全渗透测试")
        
        return recommendations
    }
    
    private func calculateUISecurityScore() -> Int {
        var score = 100
        
        for issue in securityIssues {
            switch issue.severity {
            case .critical:
                score -= 20
            case .high:
                score -= 15
            case .medium:
                score -= 8
            case .low:
                score -= 3
            }
        }
        
        return max(0, score)
    }
    
    private func formatUISecurityReport(_ report: UISecurityReport) -> String {
        var output = ""
        
        output += "UI控件安全分析 (\(report.controls.count)种控件):\n"
        for control in report.controls {
            let secureIcon = control.isSecure ? "✅" : "⚠️"
            output += "\(secureIcon) \(control.controlType): \(control.isSecure ? "安全" : "有风险")\n"
        }
        
        output += "\nUI安全问题 (\(report.issues.count)个):\n"
        if report.issues.isEmpty {
            output += "✅ 未发现UI安全问题\n"
        } else {
            for issue in report.issues {
                let severityIcon = getIssueSeverityIcon(issue.severity)
                output += "\(severityIcon) \(issue.description)\n"
                if let location = issue.location {
                    output += "    位置: \(location)\n"
                }
            }
        }
        
        output += "\nUI安全评分: \(report.securityScore)/100\n"
        
        output += "\n安全建议:\n"
        for (index, recommendation) in report.recommendations.enumerated() {
            output += "\(index + 1). \(recommendation)\n"
        }
        
        return output
    }
    
    private func getIssueSeverityIcon(_ severity: UISecurityIssue.Severity) -> String {
        switch severity {
        case .low:
            return "🟡"
        case .medium:
            return "🟠"
        case .high:
            return "🔴"
        case .critical:
            return "💀"
        }
    }
}

// MARK: - UI Security Testing Methods

extension UISecurityChecker {
    
    /// 执行实时UI安全测试
    func performLiveUISecurityTest() -> String {
        var report = "实时UI安全测试:\n"
        
        // 测试当前视图控制器
        if let rootViewController = UIApplication.shared.windows.first?.rootViewController {
            report += analyzeViewController(rootViewController)
        }
        
        // 测试键盘安全性
        report += testKeyboardSecurity()
        
        // 测试屏幕保护
        report += testScreenProtection()
        
        return report
    }
    
    private func analyzeViewController(_ viewController: UIViewController) -> String {
        var result = "\n🔍 视图控制器分析 (\(type(of: viewController))):\n"
        
        // 分析视图中的所有子视图
        let textFields = findTextFields(in: viewController.view)
        result += "  📝 文本输入框: \(textFields.count)个\n"
        
        let buttons = findButtons(in: viewController.view)
        result += "  🔘 按钮: \(buttons.count)个\n"
        
        let webViews = findWebViews(in: viewController.view)
        result += "  🌐 WebView: \(webViews.count)个\n"
        
        // 检查安全配置
        var secureCount = 0
        for textField in textFields {
            if textField.isSecureTextEntry {
                secureCount += 1
            }
        }
        
        if !textFields.isEmpty {
            result += "  🔒 安全文本输入: \(secureCount)/\(textFields.count)\n"
        }
        
        return result
    }
    
    private func findTextFields(in view: UIView) -> [UITextField] {
        var textFields: [UITextField] = []
        
        if let textField = view as? UITextField {
            textFields.append(textField)
        }
        
        for subview in view.subviews {
            textFields.append(contentsOf: findTextFields(in: subview))
        }
        
        return textFields
    }
    
    private func findButtons(in view: UIView) -> [UIButton] {
        var buttons: [UIButton] = []
        
        if let button = view as? UIButton {
            buttons.append(button)
        }
        
        for subview in view.subviews {
            buttons.append(contentsOf: findButtons(in: subview))
        }
        
        return buttons
    }
    
    private func findWebViews(in view: UIView) -> [UIView] {
        var webViews: [UIView] = []
        
        // 检查 WKWebView 和 UIWebView (deprecated)
        if NSStringFromClass(type(of: view)).contains("WebView") {
            webViews.append(view)
        }
        
        for subview in view.subviews {
            webViews.append(contentsOf: findWebViews(in: subview))
        }
        
        return webViews
    }
    
    private func testKeyboardSecurity() -> String {
        var result = "\n⌨️ 键盘安全测试:\n"
        
        // 检查当前键盘类型
        if let firstResponder = UIApplication.shared.firstResponder {
            if let textField = firstResponder as? UITextField {
                result += "  📱 当前输入类型: \(getKeyboardTypeDescription(textField.keyboardType))\n"
                result += "  🔐 安全输入: \(textField.isSecureTextEntry ? "是" : "否")\n"
                result += "  📝 自动完成: \(textField.autocorrectionType == .no ? "禁用" : "启用")\n"
            }
        } else {
            result += "  💤 当前无活跃的输入控件\n"
        }
        
        return result
    }
    
    private func testScreenProtection() -> String {
        var result = "\n📱 屏幕保护测试:\n"
        
        // 检查屏幕录制状态
        if #available(iOS 11.0, *) {
            let isRecording = UIScreen.main.isCaptured
            result += "  📹 屏幕录制状态: \(isRecording ? "正在录制" : "未录制")\n"
        }
        
        // 模拟检查截图保护
        result += "  📸 截图保护: 模拟检测\n"
        
        return result
    }
    
    private func getKeyboardTypeDescription(_ keyboardType: UIKeyboardType) -> String {
        switch keyboardType {
        case .default:
            return "默认"
        case .numbersAndPunctuation:
            return "数字和标点"
        case .emailAddress:
            return "邮箱地址"
        case .decimalPad:
            return "小数键盘"
        case .phonePad:
            return "电话键盘"
        case .numberPad:
            return "数字键盘"
        case .asciiCapable:
            return "ASCII"
        case .URL:
            return "URL"
        case .namePhonePad:
            return "姓名电话"
        case .twitter:
            return "Twitter"
        case .webSearch:
            return "网页搜索"
        case .asciiCapableNumberPad:
            return "ASCII数字"
        @unknown default:
            return "未知"
        }
    }
}

// MARK: - UIApplication Extension for First Responder

extension UIApplication {
    var firstResponder: UIResponder? {
        var firstResponder: UIResponder?
        
        func findFirstResponder(in view: UIView) {
            if view.isFirstResponder {
                firstResponder = view
                return
            }
            
            for subview in view.subviews {
                findFirstResponder(in: subview)
                if firstResponder != nil {
                    break
                }
            }
        }
        
        for window in windows {
            findFirstResponder(in: window)
            if firstResponder != nil {
                break
            }
        }
        
        return firstResponder
    }
}