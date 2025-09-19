import Foundation
import UIKit

// 越狱检测结果结构
struct JailbreakDetectionResult {
    let isJailbroken: Bool
    let details: [JailbreakCheckDetail]
    
    struct JailbreakCheckDetail {
        let checkType: JailbreakCheckType
        let isDetected: Bool
        let description: String
    }
    
    enum JailbreakCheckType: String, CaseIterable {
        case emulator = "模拟器"
        case urlSchemes = "URL Scheme"
        case existenceOfSuspiciousFiles = "可疑文件是否存在"
        case suspiciousFilesCanBeOpened = "可疑文件是否能打开"
        case suspiciousObjCClasses = "可疑OC类"
        case dyld = "可疑动态库"
        case restrictedDirectoriesWriteable = "受限目录是否可写"
        case environmentVariables = "可疑环境变量"
        case symbolicLinks = "系统文件转符号链接"
        case fork = "可疑创建新进程"
        case openedPorts = "可疑端口被开放"
        case fileIntegrity = "文件完整性检测"
        case debugged = "异常动态调试"
        case pSelectFlag = "进程的 p_flag 字段是否包含 P_SELECT 标记"
        case proxy = "代理/VPN"
        case lockdown = "锁定模式"
        
        var description: String {
            return self.rawValue
        }
    }
}

class SecurityDetector {
    // 越狱检测相关方法将在这里实现
    static let shared = SecurityDetector()
    
    private init() {}
    
    // 原有的简单越狱检测方法
    func isDeviceJailbroken() -> Bool {
        let result = detailedJailbreakDetection()
        return result.isJailbroken
    }
    
    // 详细的越狱检测方法，返回详细的检测结果
    func detailedJailbreakDetection() -> JailbreakDetectionResult {
        var details: [JailbreakDetectionResult.JailbreakCheckDetail] = []
        
        let emulatorCheckResult = EmulatorChecker.amIRunInEmulator()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .emulator,
            isDetected: emulatorCheckResult,
            description: emulatorCheckResult ? "设备运行在模拟器中" : ""
        ))
        
        let schemeCheckResult = JailbreakChecker.checkURLSchemes()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .urlSchemes,
            isDetected: !schemeCheckResult.passed,
            description: schemeCheckResult.failMessage
        ))
        
        let existenceOfSuspiciousFilesCheckResult = JailbreakChecker.checkExistenceOfSuspiciousFiles()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .existenceOfSuspiciousFiles,
            isDetected: !existenceOfSuspiciousFilesCheckResult.passed,
            description: existenceOfSuspiciousFilesCheckResult.failMessage
        ))
        
        let suspiciousFilesCanBeOpenedCheckResult = JailbreakChecker.checkSuspiciousFilesCanBeOpened()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .suspiciousFilesCanBeOpened,
            isDetected: !suspiciousFilesCanBeOpenedCheckResult.passed,
            description: suspiciousFilesCanBeOpenedCheckResult.failMessage
        ))
        
        let suspiciousObjCClassesCheckResult = JailbreakChecker.checkSuspiciousObjCClasses()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .suspiciousObjCClasses,
            isDetected: !suspiciousObjCClassesCheckResult.passed,
            description: suspiciousObjCClassesCheckResult.failMessage
        ))
        
        let dyldCheckResult = JailbreakChecker.checkDYLD()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .dyld,
            isDetected: !dyldCheckResult.passed,
            description: dyldCheckResult.failMessage
        ))
        
        let restrictedDirectoriesWriteableCheckResult = JailbreakChecker.checkRestrictedDirectoriesWriteable()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .restrictedDirectoriesWriteable,
            isDetected: !restrictedDirectoriesWriteableCheckResult.passed,
            description: restrictedDirectoriesWriteableCheckResult.failMessage
        ))
        
        let environmentVariablesCheckResult = checkEnvironmentVariables()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .environmentVariables,
            isDetected: !environmentVariablesCheckResult.passed,
            description: environmentVariablesCheckResult.failMessage
        ))
        
        let symbolicLinksCheckResult = JailbreakChecker.checkSymbolicLinks()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .symbolicLinks,
            isDetected: !symbolicLinksCheckResult.passed,
            description: symbolicLinksCheckResult.failMessage
        ))
        
        let forkCheckResult = JailbreakChecker.checkFork()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .fork,
            isDetected: !forkCheckResult.passed,
            description: forkCheckResult.failMessage
        ))
        
        let openedPortsCheckResult = ReverseEngineeringToolsChecker.checkOpenedPorts()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .openedPorts,
            isDetected: !openedPortsCheckResult.passed,
            description: openedPortsCheckResult.failMessage
        ))
        
        let fileIntegrityCheckResult = IntegrityChecker.getMachOFileHashValue() == "041f2fc14f8375c0962e8f4783c5200b37f899b2a671852f3f8446852ae13cfa"
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .fileIntegrity,
            isDetected: fileIntegrityCheckResult,
            description: fileIntegrityCheckResult ? "应用文件被篡改" : ""
        ))
        
        let debuggedCheckResult = DebuggerChecker.amIDebugged()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .debugged,
            isDetected: debuggedCheckResult,
            description: debuggedCheckResult ? "应用正在被调试" : ""
        ))
        
        let pSelectFlagCheckResult = ReverseEngineeringToolsChecker.checkPSelectFlag()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .pSelectFlag,
            isDetected: !pSelectFlagCheckResult.passed,
            description: pSelectFlagCheckResult.failMessage
        ))
        
        let proxyCheckResult = ProxyChecker.amIProxied(considerVPNConnectionAsProxy: true)
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .proxy,
            isDetected: proxyCheckResult,
            description: "设备是否配置了HTTP代理"
        ))
        
        let lockdownCheckResult = ModesChecker.amIInLockdownMode()
        details.append(JailbreakDetectionResult.JailbreakCheckDetail(
            checkType: .lockdown,
            isDetected: lockdownCheckResult,
            description: "设备是否处于锁定模式"
        ))
            
            
        
        // 判断是否安全，只要有任何一项检测为true就认为设备已越狱
        let isJailbroken = details.contains { $0.isDetected }
        
        return JailbreakDetectionResult(isJailbroken: isJailbroken, details: details)
    }
    
    private func checkVendor() -> Bool {
        print(IOSSecuritySuite.amIJailbrokenWithFailMessage());
        if IOSSecuritySuite.amIJailbroken() {
            return true
        } else {
            return false
        }
    }
    
    // 权限检测 - 检查越狱相关文件是否存在
    private func checkJailbreakFiles() -> Bool {
        let jailbreakFiles = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/",
            "/private/var/stash",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/lib/cydia",
            "/private/etc/profile",
            "/private/etc/ssh/sshd_config",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app",
            "/usr/libexec/sftp-server",
            "/usr/bin/sshd",
            "/usr/libexec/ssh-keysign",
            "/usr/libexec/sftp-server",
            "/usr/libexec/cydia",
            "/usr/libexec/sileo",
            "/var/lib/cydia",
            "/usr/sbin/frida-server"
        ]
        
        for file in jailbreakFiles {
            if FileManager.default.fileExists(atPath: file) {
                return true
            }
        }
        return false
    }
    
    // Scheme检测 - 检查越狱相关URL Schemes
    private func checkJailbreakURLSchemes() -> Bool {
        let jailbreakSchemes = [
            "cydia://",
            "sileo://",
            "zbra://",
            "filza://"
        ]
        
        for scheme in jailbreakSchemes {
            if let url = URL(string: scheme) {
                if UIApplication.shared.canOpenURL(url) {
                    return true
                }
            }
        }
        return false
    }
    
    // 符号链接检测
    private func checkSymbolicLinks() -> Bool {
        let suspiciousPaths = [
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/libexec/cydia",
            "/usr/libexec/sileo",
            "/var/lib/cydia"
        ]
        
        for path in suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) {
                do {
                    let attributes = try FileManager.default.attributesOfItem(atPath: path)
                    if let fileType = attributes[.type] as? String {
                        if fileType == "NSFileTypeSymbolicLink" {
                            return true
                        }
                    }
                } catch {
                    // 忽略错误，继续检查其他路径
                }
            }
        }
        return false
    }
    
    // 写入权限检测 - 检查是否能在系统目录写入文件
    private func checkWritePermission() -> Bool {
        let systemPaths = [
            "/private/jailbreakTest.txt",
            "/ Applications/.test",
            "/tmp/.test",
            "/var/mobile/test.txt"
        ]
        
        for path in systemPaths {
            do {
                try "test".write(toFile: path, atomically: true, encoding: .utf8)
                // 如果能写入成功，说明设备可能已越狱
                try FileManager.default.removeItem(atPath: path)
                return true
            } catch {
                // 无法写入，继续检查其他路径
            }
        }
        return false
    }
    
    // 进程检测 - 检查是否有越狱相关进程在运行
    private func checkSuspiciousProcesses() -> Bool {
        #if targetEnvironment(simulator)
        // 在模拟器中跳过此项检测
        return false
        #else
        let suspiciousProcesses = [
            "cydia",
            "sileo",
            "zebra",
            "substrated",
            "apt",
            "dpkg",
            "sshd",
            "ssh",
            "openssh"
        ]
        
        // 注意: 在实际应用中，检查进程需要使用更底层的API，
        // 这里提供一个概念性的实现
        // 由于iOS的安全限制，我们通常无法直接访问进程列表
        return false
        #endif
    }
    
    // 环境变量检测 - 检查DYLD_INSERT_LIBRARIES等可疑环境变量
    private func checkEnvironmentVariables() -> (passed: Bool, failMessage: String) {
        #if targetEnvironment(simulator)
        // 在模拟器中跳过此项检测
        return (true, "")
        #else
        // 检查DYLD_INSERT_LIBRARIES环境变量
        if let dyldInsertLibraries = ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] {
            // 如果该环境变量存在且不为空，则可能是越狱设备
            if !dyldInsertLibraries.isEmpty {
                return (false, "DYLD_INSERT_LIBRARIES")
            }
        }
        
        // 检查其他可疑环境变量
        let suspiciousEnvVars = [
            "DYLD_FORCE_FLAT_NAMESPACE",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH"
        ]
        
        var existEnvVars: [String] = []
        
        for envVar in suspiciousEnvVars {
            if let value = ProcessInfo.processInfo.environment[envVar], !value.isEmpty {
                existEnvVars.append(envVar)
            }
        }
        
        if !existEnvVars.isEmpty {
            return (false, existEnvVars.joined(separator: "\n"))
        } else {
            return (true, "")
        }
        #endif
    }
}
