import Foundation
import UIKit
import Security

/// 主安全检测器 - 协调各种安全检测模块
class SecurityDetector {
    
    static let shared = SecurityDetector()
    
    private var isMonitoring = false
    private var securityThreats: [SecurityThreat] = []
    
    private init() {}
    
    // MARK: - Security Threat Model
    
    struct SecurityThreat {
        let type: ThreatType
        let severity: Severity
        let description: String
        let timestamp: Date
        
        enum ThreatType {
            case encryption
            case network
            case ui
            case fileOperation
            case general
        }
        
        enum Severity {
            case low
            case medium
            case high
            case critical
        }
    }
    
    // MARK: - Public Methods
    
    func startMonitoring() {
        guard !isMonitoring else { return }
        
        isMonitoring = true
        print("🔒 SecuScope 安全监控已启动")
        
        // 检测越狱状态
        detectJailbreak()
        
        // 检测调试器
        detectDebugger()
        
        // 检测模拟器
        detectSimulator()
        
        // 检测 Hook 框架
        detectHookingFrameworks()
    }
    
    func stopMonitoring() {
        isMonitoring = false
        print("🔓 SecuScope 安全监控已停止")
    }
    
    func isSecure() -> Bool {
        return securityThreats.filter { $0.severity == .high || $0.severity == .critical }.isEmpty
    }
    
    func getOverallSecurityStatus() -> String {
        let criticalCount = securityThreats.filter { $0.severity == .critical }.count
        let highCount = securityThreats.filter { $0.severity == .high }.count
        let mediumCount = securityThreats.filter { $0.severity == .medium }.count
        
        if criticalCount > 0 {
            return "严重威胁 (\(criticalCount)个)"
        } else if highCount > 0 {
            return "高风险 (\(highCount)个)"
        } else if mediumCount > 0 {
            return "中等风险 (\(mediumCount)个)"
        } else {
            return "安全"
        }
    }
    
    func performComprehensiveSecurityCheck() -> String {
        var report = ""
        
        // 清空之前的威胁记录
        securityThreats.removeAll()
        
        // 重新检测所有安全威胁
        detectJailbreak()
        detectDebugger()
        detectSimulator()
        detectHookingFrameworks()
        detectRuntimeManipulation()
        detectCodeInjection()
        
        // 生成报告
        report += "检测到的安全威胁:\n"
        
        if securityThreats.isEmpty {
            report += "✅ 未发现安全威胁\n"
        } else {
            for threat in securityThreats.sorted(by: { $0.severity.rawValue > $1.severity.rawValue }) {
                let severityIcon = getSeverityIcon(threat.severity)
                report += "\(severityIcon) \(threat.description)\n"
            }
        }
        
        report += "\n安全建议:\n"
        report += "• 避免在越狱设备上运行敏感应用\n"
        report += "• 使用代码混淆技术保护重要逻辑\n"
        report += "• 实施运行时应用程序自我保护 (RASP)\n"
        report += "• 定期更新安全检测规则\n"
        
        return report
    }
    
    // MARK: - Private Detection Methods
    
    private func detectJailbreak() {
        var isJailbroken = false
        
        // 检查常见的越狱文件路径
        let jailbreakPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/",
            "/Applications/RockApp.app",
            "/Applications/Icy.app",
            "/usr/sbin/frida-server",
            "/usr/bin/cycript",
            "/usr/local/bin/cycript",
            "/usr/lib/libcycript.dylib",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist"
        ]
        
        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                isJailbroken = true
                break
            }
        }
        
        // 检查是否可以写入受保护的目录
        if !isJailbroken {
            let testPath = "/private/test_jailbreak.txt"
            do {
                try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
                try FileManager.default.removeItem(atPath: testPath)
                isJailbroken = true
            } catch {
                // 无法写入，这是正常的
            }
        }
        
        // 检查URL Scheme
        if !isJailbroken {
            if let url = URL(string: "cydia://package/com.example.package") {
                if UIApplication.shared.canOpenURL(url) {
                    isJailbroken = true
                }
            }
        }
        
        if isJailbroken {
            let threat = SecurityThreat(
                type: .general,
                severity: .critical,
                description: "检测到设备已越狱",
                timestamp: Date()
            )
            securityThreats.append(threat)
        }
    }
    
    private func detectDebugger() {
        var isDebugged = false
        
        // 检查 ptrace
        if isDebuggerAttached() {
            isDebugged = true
        }
        
        // 检查异常端口
        if isDebuggedViaExceptionPort() {
            isDebugged = true
        }
        
        if isDebugged {
            let threat = SecurityThreat(
                type: .general,
                severity: .high,
                description: "检测到调试器连接",
                timestamp: Date()
            )
            securityThreats.append(threat)
        }
    }
    
    private func detectSimulator() {
        #if targetEnvironment(simulator)
        let threat = SecurityThreat(
            type: .general,
            severity: .medium,
            description: "应用运行在模拟器环境",
            timestamp: Date()
        )
        securityThreats.append(threat)
        #endif
    }
    
    private func detectHookingFrameworks() {
        let hookingLibraries = [
            "MobileSubstrate",
            "libcycript",
            "frida",
            "Substrate",
            "FridaGadget"
        ]
        
        for library in hookingLibraries {
            if dlopen(library, RTLD_NOW) != nil {
                let threat = SecurityThreat(
                    type: .general,
                    severity: .high,
                    description: "检测到Hook框架: \(library)",
                    timestamp: Date()
                )
                securityThreats.append(threat)
            }
        }
    }
    
    private func detectRuntimeManipulation() {
        // 检查是否有方法被 swizzled
        let originalMethodCount = class_getInstanceMethodList(UIViewController.self, nil)
        if let methods = originalMethodCount {
            // 简单检查方法数量是否异常
            // 在实际应用中，这里应该有更精确的检测逻辑
            let methodCount = Int(methods.pointee.count)
            if methodCount > 50 { // 假设正常情况下不应该超过50个方法
                let threat = SecurityThreat(
                    type: .general,
                    severity: .medium,
                    description: "检测到可能的运行时操作",
                    timestamp: Date()
                )
                securityThreats.append(threat)
            }
        }
    }
    
    private func detectCodeInjection() {
        // 检查动态库注入
        var imageCount: UInt32 = 0
        let images = _dyld_image_count()
        
        for i in 0..<images {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                
                // 检查可疑的动态库
                let suspiciousLibraries = [
                    "cycript",
                    "substrate",
                    "frida",
                    "mobilehookery"
                ]
                
                for suspicious in suspiciousLibraries {
                    if name.lowercased().contains(suspicious) {
                        let threat = SecurityThreat(
                            type: .general,
                            severity: .high,
                            description: "检测到可疑动态库: \(name)",
                            timestamp: Date()
                        )
                        securityThreats.append(threat)
                    }
                }
            }
        }
    }
    
    // MARK: - Helper Methods
    
    private func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        
        return result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    private func isDebuggedViaExceptionPort() -> Bool {
        var exceptionPort: mach_port_t = 0
        var exceptionPortCount: mach_msg_type_number_t = 0
        var exceptionPorts: exception_port_array_t = nil
        var exceptionBehaviors: exception_behavior_array_t = nil
        var exceptionFlavors: exception_flavor_array_t = nil
        
        let result = task_get_exception_ports(
            mach_task_self_,
            EXC_MASK_ALL,
            &exceptionPorts,
            &exceptionPortCount,
            &exceptionBehaviors,
            &exceptionFlavors
        )
        
        return result == KERN_SUCCESS && exceptionPortCount > 0
    }
    
    private func getSeverityIcon(_ severity: SecurityThreat.Severity) -> String {
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

// MARK: - C Extensions for Low-level System Calls

extension SecurityDetector.SecurityThreat.Severity: Comparable {
    static func < (lhs: SecurityDetector.SecurityThreat.Severity, rhs: SecurityDetector.SecurityThreat.Severity) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }
    
    var rawValue: Int {
        switch self {
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }
}