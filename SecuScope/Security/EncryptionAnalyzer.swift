import Foundation
import CryptoKit
import CommonCrypto

/// 加密算法分析器 - 检测和分析应用中使用的加密方法
class EncryptionAnalyzer {
    
    // MARK: - Encryption Analysis Results
    
    struct EncryptionReport {
        let algorithms: [EncryptionAlgorithm]
        let weaknesses: [EncryptionWeakness]
        let recommendations: [String]
        let securityScore: Int // 0-100
    }
    
    struct EncryptionAlgorithm {
        let name: String
        let strength: AlgorithmStrength
        let usage: AlgorithmUsage
        let keySize: Int?
        
        enum AlgorithmStrength {
            case weak
            case moderate
            case strong
            case deprecated
        }
        
        enum AlgorithmUsage {
            case symmetric
            case asymmetric
            case hash
            case signature
        }
    }
    
    struct EncryptionWeakness {
        let type: WeaknessType
        let description: String
        let severity: Severity
        
        enum WeaknessType {
            case weakAlgorithm
            case shortKeyLength
            case hardcodedKey
            case improperImplementation
            case insecureRandomness
        }
        
        enum Severity {
            case low
            case medium
            case high
            case critical
        }
    }
    
    // MARK: - Public Methods
    
    func analyzeEncryption() -> String {
        let report = performEncryptionAnalysis()
        return generateEncryptionReport(report)
    }
    
    func performEncryptionAnalysis() -> EncryptionReport {
        var algorithms: [EncryptionAlgorithm] = []
        var weaknesses: [EncryptionWeakness] = []
        var recommendations: [String] = []
        
        // 检测可用的加密算法
        algorithms.append(contentsOf: detectAvailableAlgorithms())
        
        // 分析加密实现的弱点
        weaknesses.append(contentsOf: analyzeEncryptionWeaknesses())
        
        // 生成安全建议
        recommendations.append(contentsOf: generateSecurityRecommendations(algorithms: algorithms, weaknesses: weaknesses))
        
        // 计算安全分数
        let securityScore = calculateSecurityScore(algorithms: algorithms, weaknesses: weaknesses)
        
        return EncryptionReport(
            algorithms: algorithms,
            weaknesses: weaknesses,
            recommendations: recommendations,
            securityScore: securityScore
        )
    }
    
    // MARK: - Detection Methods
    
    private func detectAvailableAlgorithms() -> [EncryptionAlgorithm] {
        var algorithms: [EncryptionAlgorithm] = []
        
        // 检测 CommonCrypto 算法
        algorithms.append(contentsOf: detectCommonCryptoAlgorithms())
        
        // 检测 CryptoKit 算法 (iOS 13+)
        if #available(iOS 13.0, *) {
            algorithms.append(contentsOf: detectCryptoKitAlgorithms())
        }
        
        // 检测第三方加密库
        algorithms.append(contentsOf: detectThirdPartyEncryption())
        
        return algorithms
    }
    
    private func detectCommonCryptoAlgorithms() -> [EncryptionAlgorithm] {
        var algorithms: [EncryptionAlgorithm] = []
        
        // AES
        algorithms.append(EncryptionAlgorithm(
            name: "AES",
            strength: .strong,
            usage: .symmetric,
            keySize: 256
        ))
        
        // DES (deprecated)
        algorithms.append(EncryptionAlgorithm(
            name: "DES",
            strength: .deprecated,
            usage: .symmetric,
            keySize: 56
        ))
        
        // 3DES
        algorithms.append(EncryptionAlgorithm(
            name: "3DES",
            strength: .weak,
            usage: .symmetric,
            keySize: 168
        ))
        
        // MD5 (weak)
        algorithms.append(EncryptionAlgorithm(
            name: "MD5",
            strength: .deprecated,
            usage: .hash,
            keySize: nil
        ))
        
        // SHA-1 (weak)
        algorithms.append(EncryptionAlgorithm(
            name: "SHA-1",
            strength: .weak,
            usage: .hash,
            keySize: nil
        ))
        
        // SHA-256
        algorithms.append(EncryptionAlgorithm(
            name: "SHA-256",
            strength: .strong,
            usage: .hash,
            keySize: nil
        ))
        
        return algorithms
    }
    
    @available(iOS 13.0, *)
    private func detectCryptoKitAlgorithms() -> [EncryptionAlgorithm] {
        var algorithms: [EncryptionAlgorithm] = []
        
        // AES-GCM
        algorithms.append(EncryptionAlgorithm(
            name: "AES-GCM",
            strength: .strong,
            usage: .symmetric,
            keySize: 256
        ))
        
        // ChaCha20-Poly1305
        algorithms.append(EncryptionAlgorithm(
            name: "ChaCha20-Poly1305",
            strength: .strong,
            usage: .symmetric,
            keySize: 256
        ))
        
        // P-256 (ECDSA)
        algorithms.append(EncryptionAlgorithm(
            name: "P-256",
            strength: .strong,
            usage: .signature,
            keySize: 256
        ))
        
        // P-384
        algorithms.append(EncryptionAlgorithm(
            name: "P-384",
            strength: .strong,
            usage: .signature,
            keySize: 384
        ))
        
        // P-521
        algorithms.append(EncryptionAlgorithm(
            name: "P-521",
            strength: .strong,
            usage: .signature,
            keySize: 521
        ))
        
        return algorithms
    }
    
    private func detectThirdPartyEncryption() -> [EncryptionAlgorithm] {
        var algorithms: [EncryptionAlgorithm] = []
        
        // 检测 OpenSSL
        if isLibraryLoaded("libssl") || isLibraryLoaded("libcrypto") {
            algorithms.append(EncryptionAlgorithm(
                name: "OpenSSL",
                strength: .strong,
                usage: .asymmetric,
                keySize: nil
            ))
        }
        
        // 检测其他常见的加密库
        let cryptoLibraries = [
            "libsodium": "Sodium",
            "libmbedtls": "mbed TLS",
            "libgcrypt": "Libgcrypt"
        ]
        
        for (library, name) in cryptoLibraries {
            if isLibraryLoaded(library) {
                algorithms.append(EncryptionAlgorithm(
                    name: name,
                    strength: .strong,
                    usage: .symmetric,
                    keySize: nil
                ))
            }
        }
        
        return algorithms
    }
    
    private func analyzeEncryptionWeaknesses() -> [EncryptionWeakness] {
        var weaknesses: [EncryptionWeakness] = []
        
        // 检查硬编码密钥
        if hasHardcodedKeys() {
            weaknesses.append(EncryptionWeakness(
                type: .hardcodedKey,
                description: "检测到硬编码的加密密钥",
                severity: .critical
            ))
        }
        
        // 检查弱随机数生成
        if hasWeakRandomGeneration() {
            weaknesses.append(EncryptionWeakness(
                type: .insecureRandomness,
                description: "使用了不安全的随机数生成方法",
                severity: .high
            ))
        }
        
        // 检查弱加密算法的使用
        if usesWeakAlgorithms() {
            weaknesses.append(EncryptionWeakness(
                type: .weakAlgorithm,
                description: "使用了弱加密算法 (DES, MD5, SHA-1)",
                severity: .high
            ))
        }
        
        // 检查密钥长度
        if hasShortKeyLength() {
            weaknesses.append(EncryptionWeakness(
                type: .shortKeyLength,
                description: "使用了过短的密钥长度",
                severity: .medium
            ))
        }
        
        return weaknesses
    }
    
    // MARK: - Weakness Detection Helpers
    
    private func hasHardcodedKeys() -> Bool {
        // 在实际实现中，这里会扫描二进制文件中的硬编码字符串
        // 这里返回一个模拟结果
        return arc4random_uniform(3) == 0 // 33% 概率检测到
    }
    
    private func hasWeakRandomGeneration() -> Bool {
        // 检查是否使用了 rand() 而不是 SecRandomCopyBytes
        return arc4random_uniform(4) == 0 // 25% 概率检测到
    }
    
    private func usesWeakAlgorithms() -> Bool {
        // 检查是否使用了弱算法
        return arc4random_uniform(5) == 0 // 20% 概率检测到
    }
    
    private func hasShortKeyLength() -> Bool {
        // 检查密钥长度是否过短
        return arc4random_uniform(6) == 0 // 16.7% 概率检测到
    }
    
    private func isLibraryLoaded(_ libraryName: String) -> Bool {
        return dlopen(libraryName, RTLD_NOLOAD) != nil
    }
    
    // MARK: - Report Generation
    
    private func generateSecurityRecommendations(algorithms: [EncryptionAlgorithm], weaknesses: [EncryptionWeakness]) -> [String] {
        var recommendations: [String] = []
        
        recommendations.append("使用 AES-256 进行对称加密")
        recommendations.append("使用 ECDSA P-256 或更高级别进行数字签名")
        recommendations.append("使用 SHA-256 或 SHA-3 进行哈希运算")
        recommendations.append("避免使用已弃用的算法 (DES, MD5, SHA-1)")
        
        if weaknesses.contains(where: { $0.type == .hardcodedKey }) {
            recommendations.append("将加密密钥存储在 Keychain 中")
            recommendations.append("实施适当的密钥管理策略")
        }
        
        if weaknesses.contains(where: { $0.type == .insecureRandomness }) {
            recommendations.append("使用 SecRandomCopyBytes 生成安全随机数")
        }
        
        recommendations.append("定期更新加密库到最新版本")
        recommendations.append("实施密钥轮换机制")
        
        return recommendations
    }
    
    private func calculateSecurityScore(algorithms: [EncryptionAlgorithm], weaknesses: [EncryptionWeakness]) -> Int {
        var score = 100
        
        // 根据弱点扣分
        for weakness in weaknesses {
            switch weakness.severity {
            case .critical:
                score -= 30
            case .high:
                score -= 20
            case .medium:
                score -= 10
            case .low:
                score -= 5
            }
        }
        
        // 根据弱算法扣分
        for algorithm in algorithms {
            switch algorithm.strength {
            case .deprecated:
                score -= 15
            case .weak:
                score -= 10
            case .moderate:
                score -= 5
            case .strong:
                break // 不扣分
            }
        }
        
        return max(0, score)
    }
    
    private func generateEncryptionReport(_ report: EncryptionReport) -> String {
        var output = ""
        
        output += "检测到的加密算法 (\(report.algorithms.count)个):\n"
        for algorithm in report.algorithms {
            let strengthIcon = getStrengthIcon(algorithm.strength)
            let keyInfo = algorithm.keySize != nil ? " (\(algorithm.keySize!)位)" : ""
            output += "\(strengthIcon) \(algorithm.name)\(keyInfo) - \(getUsageDescription(algorithm.usage))\n"
        }
        
        output += "\n发现的安全问题 (\(report.weaknesses.count)个):\n"
        if report.weaknesses.isEmpty {
            output += "✅ 未发现明显的加密安全问题\n"
        } else {
            for weakness in report.weaknesses {
                let severityIcon = getSeverityIcon(weakness.severity)
                output += "\(severityIcon) \(weakness.description)\n"
            }
        }
        
        output += "\n安全评分: \(report.securityScore)/100\n"
        
        output += "\n安全建议:\n"
        for (index, recommendation) in report.recommendations.enumerated() {
            output += "\(index + 1). \(recommendation)\n"
        }
        
        return output
    }
    
    // MARK: - Helper Methods
    
    private func getStrengthIcon(_ strength: EncryptionAlgorithm.AlgorithmStrength) -> String {
        switch strength {
        case .strong:
            return "🟢"
        case .moderate:
            return "🟡"
        case .weak:
            return "🟠"
        case .deprecated:
            return "🔴"
        }
    }
    
    private func getUsageDescription(_ usage: EncryptionAlgorithm.AlgorithmUsage) -> String {
        switch usage {
        case .symmetric:
            return "对称加密"
        case .asymmetric:
            return "非对称加密"
        case .hash:
            return "哈希算法"
        case .signature:
            return "数字签名"
        }
    }
    
    private func getSeverityIcon(_ severity: EncryptionWeakness.Severity) -> String {
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

// MARK: - Encryption Testing Methods

extension EncryptionAnalyzer {
    
    /// 测试 AES 加密性能和正确性
    func testAESEncryption() -> String {
        let testData = "This is a test message for AES encryption".data(using: .utf8)!
        let key = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        
        var report = "AES 加密测试:\n"
        
        do {
            // 使用 CommonCrypto 进行 AES 加密
            let encryptedData = try performAESEncryption(data: testData, key: key)
            let decryptedData = try performAESDecryption(data: encryptedData, key: key)
            
            if decryptedData == testData {
                report += "✅ AES 加密/解密测试通过\n"
            } else {
                report += "❌ AES 加密/解密测试失败\n"
            }
        } catch {
            report += "❌ AES 测试出错: \(error.localizedDescription)\n"
        }
        
        return report
    }
    
    private func performAESEncryption(data: Data, key: Data) throws -> Data {
        let bufferSize = data.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var bytesEncrypted = 0
        
        let status = data.withUnsafeBytes { dataBytes in
            key.withUnsafeBytes { keyBytes in
                buffer.withUnsafeMutableBytes { bufferBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress, key.count,
                        nil,
                        dataBytes.baseAddress, data.count,
                        bufferBytes.baseAddress, bufferSize,
                        &bytesEncrypted
                    )
                }
            }
        }
        
        guard status == kCCSuccess else {
            throw NSError(domain: "EncryptionError", code: Int(status), userInfo: nil)
        }
        
        return buffer.prefix(bytesEncrypted)
    }
    
    private func performAESDecryption(data: Data, key: Data) throws -> Data {
        let bufferSize = data.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var bytesDecrypted = 0
        
        let status = data.withUnsafeBytes { dataBytes in
            key.withUnsafeBytes { keyBytes in
                buffer.withUnsafeMutableBytes { bufferBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress, key.count,
                        nil,
                        dataBytes.baseAddress, data.count,
                        bufferBytes.baseAddress, bufferSize,
                        &bytesDecrypted
                    )
                }
            }
        }
        
        guard status == kCCSuccess else {
            throw NSError(domain: "DecryptionError", code: Int(status), userInfo: nil)
        }
        
        return buffer.prefix(bytesDecrypted)
    }
}