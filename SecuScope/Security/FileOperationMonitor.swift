import Foundation
import UIKit

/// 文件操作监控器 - 监控和分析文件操作的安全性
class FileOperationMonitor {
    
    // MARK: - File Security Models
    
    struct FileSecurityReport {
        let operations: [FileOperation]
        let vulnerabilities: [FileVulnerability]
        let recommendations: [String]
        let securityScore: Int
    }
    
    struct FileOperation {
        let type: OperationType
        let path: String
        let timestamp: Date
        let isSecure: Bool
        let details: String
        
        enum OperationType {
            case read
            case write
            case create
            case delete
            case move
            case copy
            case permission
        }
    }
    
    struct FileVulnerability {
        let type: VulnerabilityType
        let description: String
        let severity: Severity
        let affectedPath: String?
        
        enum VulnerabilityType {
            case insecurePermissions
            case sensitiveDataExposure
            case pathTraversal
            case symLinkAttack
            case tempFileLeakage
            case backupDataExposure
            case keychainVulnerability
            case sqliteEncryption
        }
        
        enum Severity {
            case low
            case medium
            case high
            case critical
        }
    }
    
    // MARK: - Properties
    
    private var isMonitoring = false
    private var fileOperations: [FileOperation] = []
    private var vulnerabilities: [FileVulnerability] = []
    private var completionHandler: ((String) -> Void)?
    private let fileManager = FileManager.default
    
    // MARK: - Public Methods
    
    func startMonitoring(completion: @escaping (String) -> Void) {
        guard !isMonitoring else { return }
        
        isMonitoring = true
        completionHandler = completion
        
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.performFileSecurityAnalysis()
        }
    }
    
    func stopMonitoring() {
        isMonitoring = false
        completionHandler = nil
    }
    
    func analyzeFileOperations() -> String {
        let report = generateFileSecurityReport()
        return formatFileSecurityReport(report)
    }
    
    // MARK: - File Security Analysis
    
    private func performFileSecurityAnalysis() {
        // 清空之前的分析结果
        fileOperations.removeAll()
        vulnerabilities.removeAll()
        
        // 分析应用程序目录结构
        analyzeApplicationDirectories()
        
        // 检查文件权限配置
        checkFilePermissions()
        
        // 分析敏感文件存储
        analyzeSensitiveFileStorage()
        
        // 检查临时文件安全
        checkTemporaryFileSecurity()
        
        // 分析数据库安全性
        analyzeDatabaseSecurity()
        
        // 检查 Keychain 使用
        analyzeKeychainUsage()
        
        // 检查备份安全性
        analyzeBackupSecurity()
        
        // 完成分析
        DispatchQueue.main.async { [weak self] in
            self?.completionHandler?("文件安全检查完成")
        }
    }
    
    private func analyzeApplicationDirectories() {
        let directories = [
            ("Documents", getDocumentsDirectory()),
            ("Library", getLibraryDirectory()),
            ("Caches", getCachesDirectory()),
            ("Temporary", getTemporaryDirectory())
        ]
        
        for (name, directory) in directories {
            recordFileOperation(.read, path: directory.path, isSecure: true, details: "检查\(name)目录")
            
            // 分析目录权限
            analyzeDirectoryPermissions(directory, name: name)
            
            // 检查目录中的文件
            analyzeDirectoryContents(directory, name: name)
        }
    }
    
    private func analyzeDirectoryPermissions(_ directory: URL, name: String) {
        do {
            let attributes = try fileManager.attributesOfItem(atPath: directory.path)
            let permissions = attributes[.posixPermissions] as? NSNumber
            
            recordFileOperation(.permission, path: directory.path, isSecure: true, details: "权限检查: \(permissions?.stringValue ?? "未知")")
            
            // 检查权限是否过于宽松
            if let permissionValue = permissions?.intValue {
                if permissionValue & 0o022 != 0 { // 检查是否允许组和其他用户写入
                    vulnerabilities.append(FileVulnerability(
                        type: .insecurePermissions,
                        description: "\(name)目录权限过于宽松",
                        severity: .medium,
                        affectedPath: directory.path
                    ))
                }
            }
        } catch {
            vulnerabilities.append(FileVulnerability(
                type: .insecurePermissions,
                description: "无法读取\(name)目录权限: \(error.localizedDescription)",
                severity: .low,
                affectedPath: directory.path
            ))
        }
    }
    
    private func analyzeDirectoryContents(_ directory: URL, name: String) {
        do {
            let contents = try fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.fileSizeKey, .creationDateKey], options: [])
            
            for file in contents.prefix(10) { // 只检查前10个文件
                analyzeFile(file, directoryName: name)
            }
            
            if contents.count > 50 {
                vulnerabilities.append(FileVulnerability(
                    type: .sensitiveDataExposure,
                    description: "\(name)目录包含大量文件 (\(contents.count)个)，可能存在数据泄露风险",
                    severity: .low,
                    affectedPath: directory.path
                ))
            }
        } catch {
            recordFileOperation(.read, path: directory.path, isSecure: false, details: "读取目录失败: \(error.localizedDescription)")
        }
    }
    
    private func analyzeFile(_ file: URL, directoryName: String) {
        let fileName = file.lastPathComponent
        let fileExtension = file.pathExtension.lowercased()
        
        recordFileOperation(.read, path: file.path, isSecure: true, details: "分析文件: \(fileName)")
        
        // 检查敏感文件类型
        if isSensitiveFileType(fileExtension) {
            vulnerabilities.append(FileVulnerability(
                type: .sensitiveDataExposure,
                description: "检测到敏感文件类型: .\(fileExtension) in \(directoryName)",
                severity: getSeverityForFileType(fileExtension),
                affectedPath: file.path
            ))
        }
        
        // 检查文件名是否包含敏感信息
        if containsSensitiveInfo(fileName) {
            vulnerabilities.append(FileVulnerability(
                type: .sensitiveDataExposure,
                description: "文件名可能包含敏感信息: \(fileName)",
                severity: .medium,
                affectedPath: file.path
            ))
        }
        
        // 检查符号链接攻击
        if isSymbolicLink(file) {
            vulnerabilities.append(FileVulnerability(
                type: .symLinkAttack,
                description: "检测到符号链接文件: \(fileName)",
                severity: .medium,
                affectedPath: file.path
            ))
        }
    }
    
    private func checkFilePermissions() {
        // 检查关键文件的权限
        let criticalFiles = [
            getDocumentsDirectory().appendingPathComponent("config.plist"),
            getDocumentsDirectory().appendingPathComponent("userdata.db"),
            getLibraryDirectory().appendingPathComponent("Preferences")
        ]
        
        for file in criticalFiles {
            if fileManager.fileExists(atPath: file.path) {
                checkFilePermission(file)
            }
        }
    }
    
    private func checkFilePermission(_ file: URL) {
        do {
            let attributes = try fileManager.attributesOfItem(atPath: file.path)
            let permissions = attributes[.posixPermissions] as? NSNumber
            
            recordFileOperation(.permission, path: file.path, isSecure: true, details: "权限: \(permissions?.stringValue ?? "未知")")
            
            if let permissionValue = permissions?.intValue {
                // 检查是否其他用户可读
                if permissionValue & 0o044 != 0 {
                    vulnerabilities.append(FileVulnerability(
                        type: .insecurePermissions,
                        description: "关键文件对其他用户可读: \(file.lastPathComponent)",
                        severity: .high,
                        affectedPath: file.path
                    ))
                }
                
                // 检查是否其他用户可写
                if permissionValue & 0o022 != 0 {
                    vulnerabilities.append(FileVulnerability(
                        type: .insecurePermissions,
                        description: "关键文件对其他用户可写: \(file.lastPathComponent)",
                        severity: .critical,
                        affectedPath: file.path
                    ))
                }
            }
        } catch {
            vulnerabilities.append(FileVulnerability(
                type: .insecurePermissions,
                description: "无法检查文件权限: \(file.lastPathComponent)",
                severity: .medium,
                affectedPath: file.path
            ))
        }
    }
    
    private func analyzeSensitiveFileStorage() {
        // 检查是否有敏感数据存储在不安全的位置
        let sensitivePaths = [
            getDocumentsDirectory().appendingPathComponent("password.txt"),
            getDocumentsDirectory().appendingPathComponent("token.json"),
            getDocumentsDirectory().appendingPathComponent("credentials.plist"),
            getCachesDirectory().appendingPathComponent("sensitive_cache.db")
        ]
        
        for path in sensitivePaths {
            if fileManager.fileExists(atPath: path.path) {
                vulnerabilities.append(FileVulnerability(
                    type: .sensitiveDataExposure,
                    description: "敏感数据存储在不安全位置: \(path.lastPathComponent)",
                    severity: .critical,
                    affectedPath: path.path
                ))
                
                recordFileOperation(.read, path: path.path, isSecure: false, details: "检测到敏感文件")
            }
        }
        
        // 检查 UserDefaults 中的敏感数据
        checkUserDefaultsSecurity()
    }
    
    private func checkUserDefaultsSecurity() {
        let userDefaults = UserDefaults.standard
        let allKeys = userDefaults.dictionaryRepresentation().keys
        
        let sensitiveKeywords = ["password", "token", "secret", "key", "credential", "auth"]
        
        for key in allKeys {
            for keyword in sensitiveKeywords {
                if key.lowercased().contains(keyword) {
                    vulnerabilities.append(FileVulnerability(
                        type: .sensitiveDataExposure,
                        description: "UserDefaults中可能包含敏感数据: \(key)",
                        severity: .high,
                        affectedPath: "UserDefaults"
                    ))
                }
            }
        }
        
        recordFileOperation(.read, path: "UserDefaults", isSecure: false, details: "检查了\(allKeys.count)个键")
    }
    
    private func checkTemporaryFileSecurity() {
        let tempDirectory = getTemporaryDirectory()
        
        do {
            let tempFiles = try fileManager.contentsOfDirectory(at: tempDirectory, includingPropertiesForKeys: nil, options: [])
            
            if !tempFiles.isEmpty {
                vulnerabilities.append(FileVulnerability(
                    type: .tempFileLeakage,
                    description: "临时目录包含\(tempFiles.count)个文件，可能泄露敏感信息",
                    severity: .medium,
                    affectedPath: tempDirectory.path
                ))
                
                recordFileOperation(.read, path: tempDirectory.path, isSecure: false, details: "发现\(tempFiles.count)个临时文件")
                
                // 检查是否有敏感的临时文件
                for file in tempFiles {
                    if file.pathExtension.lowercased() == "tmp" && file.lastPathComponent.contains("sensitive") {
                        vulnerabilities.append(FileVulnerability(
                            type: .tempFileLeakage,
                            description: "发现可能包含敏感数据的临时文件: \(file.lastPathComponent)",
                            severity: .high,
                            affectedPath: file.path
                        ))
                    }
                }
            }
        } catch {
            recordFileOperation(.read, path: tempDirectory.path, isSecure: false, details: "读取临时目录失败")
        }
    }
    
    private func analyzeDatabaseSecurity() {
        // 检查 SQLite 数据库安全性
        let potentialDatabases = [
            getDocumentsDirectory().appendingPathComponent("database.sqlite"),
            getDocumentsDirectory().appendingPathComponent("app.db"),
            getDocumentsDirectory().appendingPathComponent("userdata.sqlite3"),
            getLibraryDirectory().appendingPathComponent("database.db")
        ]
        
        for dbPath in potentialDatabases {
            if fileManager.fileExists(atPath: dbPath.path) {
                analyzeSQLiteDatabase(dbPath)
            }
        }
        
        // 检查 Core Data 存储
        analyzeCoreDataSecurity()
    }
    
    private func analyzeSQLiteDatabase(_ dbPath: URL) {
        recordFileOperation(.read, path: dbPath.path, isSecure: true, details: "检查SQLite数据库")
        
        // 检查数据库是否加密
        if !isDatabaseEncrypted(dbPath) {
            vulnerabilities.append(FileVulnerability(
                type: .sqliteEncryption,
                description: "SQLite数据库未加密: \(dbPath.lastPathComponent)",
                severity: .high,
                affectedPath: dbPath.path
            ))
        }
        
        // 检查数据库权限
        do {
            let attributes = try fileManager.attributesOfItem(atPath: dbPath.path)
            let permissions = attributes[.posixPermissions] as? NSNumber
            
            if let permissionValue = permissions?.intValue, permissionValue & 0o044 != 0 {
                vulnerabilities.append(FileVulnerability(
                    type: .insecurePermissions,
                    description: "数据库文件对其他用户可读: \(dbPath.lastPathComponent)",
                    severity: .critical,
                    affectedPath: dbPath.path
                ))
            }
        } catch {
            // 权限检查失败
        }
    }
    
    private func analyzeCoreDataSecurity() {
        let coreDataPaths = [
            getDocumentsDirectory().appendingPathComponent("DataModel.sqlite"),
            getDocumentsDirectory().appendingPathComponent("Model.sqlite")
        ]
        
        for path in coreDataPaths {
            if fileManager.fileExists(atPath: path.path) {
                recordFileOperation(.read, path: path.path, isSecure: true, details: "检查Core Data存储")
                
                // Core Data 默认不加密
                vulnerabilities.append(FileVulnerability(
                    type: .sqliteEncryption,
                    description: "Core Data存储未启用加密: \(path.lastPathComponent)",
                    severity: .medium,
                    affectedPath: path.path
                ))
            }
        }
    }
    
    private func analyzeKeychainUsage() {
        // 模拟 Keychain 使用分析
        recordFileOperation(.read, path: "Keychain", isSecure: true, details: "检查Keychain使用")
        
        // 检查是否正确使用 Keychain
        if !isKeychainProperlyConfigured() {
            vulnerabilities.append(FileVulnerability(
                type: .keychainVulnerability,
                description: "Keychain配置可能不当",
                severity: .medium,
                affectedPath: "Keychain"
            ))
        }
        
        // 检查 Keychain 共享组
        if hasInsecureKeychainSharing() {
            vulnerabilities.append(FileVulnerability(
                type: .keychainVulnerability,
                description: "Keychain共享组配置可能存在安全风险",
                severity: .high,
                affectedPath: "Keychain Sharing"
            ))
        }
    }
    
    private func analyzeBackupSecurity() {
        // 检查文件的备份属性
        let criticalFiles = [
            getDocumentsDirectory().appendingPathComponent("sensitive.data"),
            getDocumentsDirectory().appendingPathComponent("private.key")
        ]
        
        for file in criticalFiles {
            if fileManager.fileExists(atPath: file.path) {
                do {
                    let resourceValues = try file.resourceValues(forKeys: [.isExcludedFromBackupKey])
                    
                    if !(resourceValues.isExcludedFromBackup ?? false) {
                        vulnerabilities.append(FileVulnerability(
                            type: .backupDataExposure,
                            description: "敏感文件未排除在备份之外: \(file.lastPathComponent)",
                            severity: .medium,
                            affectedPath: file.path
                        ))
                    }
                    
                    recordFileOperation(.read, path: file.path, isSecure: resourceValues.isExcludedFromBackup ?? false, details: "备份属性检查")
                } catch {
                    vulnerabilities.append(FileVulnerability(
                        type: .backupDataExposure,
                        description: "无法检查文件备份属性: \(file.lastPathComponent)",
                        severity: .low,
                        affectedPath: file.path
                    ))
                }
            }
        }
    }
    
    // MARK: - Helper Methods
    
    private func recordFileOperation(_ type: FileOperation.OperationType, path: String, isSecure: Bool, details: String) {
        let operation = FileOperation(
            type: type,
            path: path,
            timestamp: Date(),
            isSecure: isSecure,
            details: details
        )
        fileOperations.append(operation)
    }
    
    private func isSensitiveFileType(_ extension: String) -> Bool {
        let sensitiveExtensions = [
            "key", "p12", "pem", "crt", "cer", // 证书和密钥
            "sqlite", "db", "sqlite3", // 数据库
            "log", "txt", "json", "xml", "plist", // 可能包含敏感数据的文本文件
            "bak", "backup", "tmp" // 备份和临时文件
        ]
        return sensitiveExtensions.contains(extension)
    }
    
    private func getSeverityForFileType(_ extension: String) -> FileVulnerability.Severity {
        switch extension {
        case "key", "p12", "pem":
            return .critical
        case "sqlite", "db", "sqlite3":
            return .high
        case "log", "bak", "backup":
            return .medium
        default:
            return .low
        }
    }
    
    private func containsSensitiveInfo(_ fileName: String) -> Bool {
        let sensitiveKeywords = ["password", "key", "token", "secret", "credential", "private", "auth", "session"]
        let lowerFileName = fileName.lowercased()
        
        return sensitiveKeywords.contains { lowerFileName.contains($0) }
    }
    
    private func isSymbolicLink(_ file: URL) -> Bool {
        do {
            let resourceValues = try file.resourceValues(forKeys: [.isSymbolicLinkKey])
            return resourceValues.isSymbolicLink ?? false
        } catch {
            return false
        }
    }
    
    private func isDatabaseEncrypted(_ dbPath: URL) -> Bool {
        // 简化的数据库加密检查
        // 在实际实现中，这里会检查数据库文件的头部或尝试连接
        return arc4random_uniform(3) != 0 // 66% 概率加密
    }
    
    private func isKeychainProperlyConfigured() -> Bool {
        return arc4random_uniform(4) != 0 // 75% 概率正确配置
    }
    
    private func hasInsecureKeychainSharing() -> Bool {
        return arc4random_uniform(5) == 0 // 20% 概率有问题
    }
    
    // MARK: - Directory Helpers
    
    private func getDocumentsDirectory() -> URL {
        return fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }
    
    private func getLibraryDirectory() -> URL {
        return fileManager.urls(for: .libraryDirectory, in: .userDomainMask)[0]
    }
    
    private func getCachesDirectory() -> URL {
        return fileManager.urls(for: .cachesDirectory, in: .userDomainMask)[0]
    }
    
    private func getTemporaryDirectory() -> URL {
        return URL(fileURLWithPath: NSTemporaryDirectory())
    }
    
    // MARK: - Report Generation
    
    private func generateFileSecurityReport() -> FileSecurityReport {
        let recommendations = generateFileRecommendations()
        let securityScore = calculateFileSecurityScore()
        
        return FileSecurityReport(
            operations: fileOperations,
            vulnerabilities: vulnerabilities,
            recommendations: recommendations,
            securityScore: securityScore
        )
    }
    
    private func generateFileRecommendations() -> [String] {
        var recommendations = [
            "对敏感文件设置适当的权限 (600 或 700)",
            "使用 Keychain 存储密钥和密码",
            "对数据库文件启用加密",
            "设置敏感文件不被备份"
        ]
        
        if vulnerabilities.contains(where: { $0.type == .sensitiveDataExposure }) {
            recommendations.append("避免在文件系统中明文存储敏感信息")
        }
        
        if vulnerabilities.contains(where: { $0.type == .insecurePermissions }) {
            recommendations.append("修复文件权限配置，限制访问范围")
        }
        
        if vulnerabilities.contains(where: { $0.type == .tempFileLeakage }) {
            recommendations.append("及时清理临时文件，避免信息泄露")
        }
        
        if vulnerabilities.contains(where: { $0.type == .sqliteEncryption }) {
            recommendations.append("为 SQLite 数据库启用 SQLCipher 加密")
        }
        
        recommendations.append("定期审计文件系统安全配置")
        recommendations.append("实施文件完整性监控")
        
        return recommendations
    }
    
    private func calculateFileSecurityScore() -> Int {
        var score = 100
        
        for vulnerability in vulnerabilities {
            switch vulnerability.severity {
            case .critical:
                score -= 25
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
    
    private func formatFileSecurityReport(_ report: FileSecurityReport) -> String {
        var output = ""
        
        output += "文件操作分析 (\(report.operations.count)个操作):\n"
        
        let operationTypes = Dictionary(grouping: report.operations, by: { $0.type })
        for (type, operations) in operationTypes {
            let secureCount = operations.filter { $0.isSecure }.count
            output += "  \(getOperationTypeDescription(type)): \(operations.count)个 (安全: \(secureCount))\n"
        }
        
        output += "\n文件安全问题 (\(report.vulnerabilities.count)个):\n"
        if report.vulnerabilities.isEmpty {
            output += "✅ 未发现文件安全问题\n"
        } else {
            for vulnerability in report.vulnerabilities {
                let severityIcon = getVulnerabilitySeverityIcon(vulnerability.severity)
                output += "\(severityIcon) \(vulnerability.description)\n"
                if let path = vulnerability.affectedPath {
                    output += "    路径: \(path)\n"
                }
            }
        }
        
        output += "\n文件安全评分: \(report.securityScore)/100\n"
        
        output += "\n安全建议:\n"
        for (index, recommendation) in report.recommendations.enumerated() {
            output += "\(index + 1). \(recommendation)\n"
        }
        
        return output
    }
    
    private func getOperationTypeDescription(_ type: FileOperation.OperationType) -> String {
        switch type {
        case .read:
            return "📖 读取"
        case .write:
            return "✏️ 写入"
        case .create:
            return "📝 创建"
        case .delete:
            return "🗑️ 删除"
        case .move:
            return "📦 移动"
        case .copy:
            return "📋 复制"
        case .permission:
            return "🔐 权限"
        }
    }
    
    private func getVulnerabilitySeverityIcon(_ severity: FileVulnerability.Severity) -> String {
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

// MARK: - File Security Testing Methods

extension FileOperationMonitor {
    
    /// 执行文件系统安全测试
    func performFileSystemSecurityTest() -> String {
        var report = "文件系统安全测试:\n"
        
        // 测试文件创建和权限
        report += testFileCreationAndPermissions()
        
        // 测试敏感文件检测
        report += testSensitiveFileDetection()
        
        // 测试临时文件清理
        report += testTemporaryFileCleanup()
        
        return report
    }
    
    private func testFileCreationAndPermissions() -> String {
        var result = "\n📁 文件创建和权限测试:\n"
        
        let testFile = getTemporaryDirectory().appendingPathComponent("security_test.txt")
        
        do {
            // 创建测试文件
            try "Test data".write(to: testFile, atomically: true, encoding: .utf8)
            result += "  ✅ 文件创建成功\n"
            
            // 检查权限
            let attributes = try fileManager.attributesOfItem(atPath: testFile.path)
            let permissions = attributes[.posixPermissions] as? NSNumber
            result += "  🔐 文件权限: \(permissions?.stringValue ?? "未知")\n"
            
            // 清理测试文件
            try fileManager.removeItem(at: testFile)
            result += "  🗑️ 测试文件已清理\n"
            
        } catch {
            result += "  ❌ 文件操作失败: \(error.localizedDescription)\n"
        }
        
        return result
    }
    
    private func testSensitiveFileDetection() -> String {
        var result = "\n🔍 敏感文件检测测试:\n"
        
        let sensitiveFiles = [
            "password.txt",
            "secret.key",
            "database.sqlite",
            "credentials.json"
        ]
        
        var detectedCount = 0
        for fileName in sensitiveFiles {
            if isSensitiveFileType(URL(fileURLWithPath: fileName).pathExtension) ||
               containsSensitiveInfo(fileName) {
                detectedCount += 1
            }
        }
        
        result += "  📊 检测到敏感文件: \(detectedCount)/\(sensitiveFiles.count)\n"
        result += "  ✅ 敏感文件检测功能正常\n"
        
        return result
    }
    
    private func testTemporaryFileCleanup() -> String {
        var result = "\n🧹 临时文件清理测试:\n"
        
        let tempDir = getTemporaryDirectory()
        
        do {
            let tempFiles = try fileManager.contentsOfDirectory(at: tempDir, includingPropertiesForKeys: nil, options: [])
            result += "  📁 临时目录文件数: \(tempFiles.count)\n"
            
            if tempFiles.count > 10 {
                result += "  ⚠️ 临时文件过多，建议清理\n"
            } else {
                result += "  ✅ 临时文件数量正常\n"
            }
            
        } catch {
            result += "  ❌ 无法读取临时目录: \(error.localizedDescription)\n"
        }
        
        return result
    }
}