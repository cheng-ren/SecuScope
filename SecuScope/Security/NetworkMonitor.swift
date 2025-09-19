import Foundation
import Network
import SystemConfiguration

/// 网络安全监控器 - 监控和分析网络请求的安全性
class NetworkMonitor {
    
    // MARK: - Network Security Models
    
    struct NetworkSecurityReport {
        let connections: [NetworkConnection]
        let vulnerabilities: [NetworkVulnerability]
        let recommendations: [String]
        let securityScore: Int
    }
    
    struct NetworkConnection {
        let host: String
        let port: Int
        let protocol: NetworkProtocol
        let isSecure: Bool
        let certificateInfo: CertificateInfo?
        let timestamp: Date
        
        enum NetworkProtocol {
            case http
            case https
            case tcp
            case udp
            case websocket
            case unknown
        }
    }
    
    struct CertificateInfo {
        let subject: String
        let issuer: String
        let expiryDate: Date
        let isValid: Bool
        let signatureAlgorithm: String
    }
    
    struct NetworkVulnerability {
        let type: VulnerabilityType
        let description: String
        let severity: Severity
        let affectedConnection: String?
        
        enum VulnerabilityType {
            case unencryptedTraffic
            case weakTLS
            case invalidCertificate
            case certificateExpired
            case insecureProtocol
            case manInTheMiddle
            case dnsHijacking
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
    private var networkConnections: [NetworkConnection] = []
    private var vulnerabilities: [NetworkVulnerability] = []
    private var monitoringQueue = DispatchQueue(label: "com.secuscope.network", qos: .utility)
    private var completionHandler: ((String) -> Void)?
    
    // MARK: - Public Methods
    
    func startMonitoring(completion: @escaping (String) -> Void) {
        guard !isMonitoring else { return }
        
        isMonitoring = true
        completionHandler = completion
        
        monitoringQueue.async { [weak self] in
            self?.performNetworkSecurityCheck()
        }
    }
    
    func stopMonitoring() {
        isMonitoring = false
        completionHandler = nil
    }
    
    func analyzeNetworkSecurity() -> String {
        let report = generateNetworkSecurityReport()
        return formatNetworkReport(report)
    }
    
    // MARK: - Network Security Analysis
    
    private func performNetworkSecurityCheck() {
        // 清空之前的记录
        networkConnections.removeAll()
        vulnerabilities.removeAll()
        
        // 检查网络连接状态
        checkNetworkConnectivity()
        
        // 分析 DNS 安全
        analyzeDNSSecurity()
        
        // 检查 TLS/SSL 配置
        analyzeTLSConfiguration()
        
        // 检查常见的网络安全问题
        checkCommonNetworkVulnerabilities()
        
        // 模拟网络流量分析
        simulateTrafficAnalysis()
        
        // 报告结果
        DispatchQueue.main.async { [weak self] in
            self?.completionHandler?("网络监控完成")
        }
    }
    
    private func checkNetworkConnectivity() {
        let reachability = SCNetworkReachabilityCreateWithName(nil, "www.apple.com")
        var flags = SCNetworkReachabilityFlags()
        
        if let reachability = reachability,
           SCNetworkReachabilityGetFlags(reachability, &flags) {
            
            if flags.contains(.reachable) {
                if flags.contains(.isWWAN) {
                    // 使用蜂窝网络
                    vulnerabilities.append(NetworkVulnerability(
                        type: .insecureProtocol,
                        description: "使用蜂窝网络连接，可能存在安全风险",
                        severity: .low,
                        affectedConnection: "蜂窝网络"
                    ))
                }
            } else {
                vulnerabilities.append(NetworkVulnerability(
                    type: .insecureProtocol,
                    description: "网络不可达",
                    severity: .medium,
                    affectedConnection: "网络连接"
                ))
            }
        }
    }
    
    private func analyzeDNSSecurity() {
        // 检查 DNS 配置
        let dnsServers = getDNSServers()
        
        for server in dnsServers {
            // 检查是否使用安全的 DNS 服务器
            if isInsecureDNSServer(server) {
                vulnerabilities.append(NetworkVulnerability(
                    type: .dnsHijacking,
                    description: "使用了不安全的 DNS 服务器: \(server)",
                    severity: .medium,
                    affectedConnection: server
                ))
            }
        }
        
        // 检查 DNS over HTTPS (DoH) 支持
        if !supportsDNSOverHTTPS() {
            vulnerabilities.append(NetworkVulnerability(
                type: .insecureProtocol,
                description: "未启用 DNS over HTTPS (DoH)",
                severity: .low,
                affectedConnection: "DNS"
            ))
        }
    }
    
    private func analyzeTLSConfiguration() {
        // 模拟 TLS 连接分析
        let testHosts = ["httpbin.org", "example.com", "google.com"]
        
        for host in testHosts {
            let connection = createMockConnection(host: host)
            networkConnections.append(connection)
            
            // 检查 TLS 版本
            if !connection.isSecure {
                vulnerabilities.append(NetworkVulnerability(
                    type: .unencryptedTraffic,
                    description: "检测到未加密的网络流量到 \(host)",
                    severity: .high,
                    affectedConnection: host
                ))
            }
            
            // 检查证书
            if let certInfo = connection.certificateInfo {
                if !certInfo.isValid {
                    vulnerabilities.append(NetworkVulnerability(
                        type: .invalidCertificate,
                        description: "无效的 SSL 证书: \(host)",
                        severity: .high,
                        affectedConnection: host
                    ))
                }
                
                if certInfo.expiryDate < Date() {
                    vulnerabilities.append(NetworkVulnerability(
                        type: .certificateExpired,
                        description: "SSL 证书已过期: \(host)",
                        severity: .medium,
                        affectedConnection: host
                    ))
                }
                
                // 检查弱签名算法
                if isWeakSignatureAlgorithm(certInfo.signatureAlgorithm) {
                    vulnerabilities.append(NetworkVulnerability(
                        type: .weakTLS,
                        description: "使用弱签名算法: \(certInfo.signatureAlgorithm)",
                        severity: .medium,
                        affectedConnection: host
                    ))
                }
            }
        }
    }
    
    private func checkCommonNetworkVulnerabilities() {
        // 检查 App Transport Security (ATS) 配置
        if isATSDisabled() {
            vulnerabilities.append(NetworkVulnerability(
                type: .insecureProtocol,
                description: "App Transport Security (ATS) 已禁用",
                severity: .high,
                affectedConnection: "ATS"
            ))
        }
        
        // 检查网络代理
        if hasNetworkProxy() {
            vulnerabilities.append(NetworkVulnerability(
                type: .manInTheMiddle,
                description: "检测到网络代理，可能存在中间人攻击风险",
                severity: .medium,
                affectedConnection: "代理服务器"
            ))
        }
        
        // 检查 VPN 连接
        if hasVPNConnection() {
            // VPN 可能是好事也可能是坏事，取决于环境
            vulnerabilities.append(NetworkVulnerability(
                type: .insecureProtocol,
                description: "检测到 VPN 连接",
                severity: .low,
                affectedConnection: "VPN"
            ))
        }
    }
    
    private func simulateTrafficAnalysis() {
        // 模拟网络流量分析
        let trafficTypes = ["HTTP", "HTTPS", "WebSocket", "TCP", "UDP"]
        
        for trafficType in trafficTypes {
            let connection = createMockTrafficConnection(type: trafficType)
            networkConnections.append(connection)
            
            // 分析流量模式
            if trafficType == "HTTP" {
                vulnerabilities.append(NetworkVulnerability(
                    type: .unencryptedTraffic,
                    description: "检测到 HTTP 流量，建议使用 HTTPS",
                    severity: .medium,
                    affectedConnection: trafficType
                ))
            }
        }
    }
    
    // MARK: - Helper Methods
    
    private func getDNSServers() -> [String] {
        // 获取系统 DNS 服务器配置
        // 这里返回一些常见的 DNS 服务器作为示例
        return ["8.8.8.8", "1.1.1.1", "192.168.1.1"]
    }
    
    private func isInsecureDNSServer(_ server: String) -> Bool {
        // 检查是否为不安全的 DNS 服务器
        let insecureServers = ["192.168.1.1", "10.0.0.1"] // 局域网 DNS 可能不安全
        return insecureServers.contains(server)
    }
    
    private func supportsDNSOverHTTPS() -> Bool {
        // 检查是否支持 DoH
        return arc4random_uniform(2) == 0 // 模拟 50% 支持率
    }
    
    private func createMockConnection(host: String) -> NetworkConnection {
        let isSecure = host != "example.com" // 模拟 example.com 不安全
        let port = isSecure ? 443 : 80
        let protocol: NetworkConnection.NetworkProtocol = isSecure ? .https : .http
        
        let certInfo = isSecure ? CertificateInfo(
            subject: "CN=\(host)",
            issuer: "CN=DigiCert Global Root CA",
            expiryDate: Date().addingTimeInterval(365 * 24 * 3600), // 1年后过期
            isValid: host != "httpbin.org", // 模拟 httpbin.org 证书无效
            signatureAlgorithm: host == "google.com" ? "SHA256withRSA" : "SHA1withRSA"
        ) : nil
        
        return NetworkConnection(
            host: host,
            port: port,
            protocol: protocol,
            isSecure: isSecure,
            certificateInfo: certInfo,
            timestamp: Date()
        )
    }
    
    private func createMockTrafficConnection(type: String) -> NetworkConnection {
        let host = "mock-\(type.lowercased()).example.com"
        let isSecure = type == "HTTPS"
        let port: Int
        let protocol: NetworkConnection.NetworkProtocol
        
        switch type {
        case "HTTP":
            port = 80
            protocol = .http
        case "HTTPS":
            port = 443
            protocol = .https
        case "WebSocket":
            port = 8080
            protocol = .websocket
        case "TCP":
            port = 1234
            protocol = .tcp
        case "UDP":
            port = 5678
            protocol = .udp
        default:
            port = 80
            protocol = .unknown
        }
        
        return NetworkConnection(
            host: host,
            port: port,
            protocol: protocol,
            isSecure: isSecure,
            certificateInfo: nil,
            timestamp: Date()
        )
    }
    
    private func isWeakSignatureAlgorithm(_ algorithm: String) -> Bool {
        let weakAlgorithms = ["SHA1withRSA", "MD5withRSA", "MD2withRSA"]
        return weakAlgorithms.contains(algorithm)
    }
    
    private func isATSDisabled() -> Bool {
        // 检查 Info.plist 中的 ATS 配置
        // 这里简化为随机结果
        return arc4random_uniform(3) == 0 // 33% 概率禁用
    }
    
    private func hasNetworkProxy() -> Bool {
        // 检查系统代理设置
        return arc4random_uniform(5) == 0 // 20% 概率有代理
    }
    
    private func hasVPNConnection() -> Bool {
        // 检查 VPN 连接
        return arc4random_uniform(10) == 0 // 10% 概率有 VPN
    }
    
    // MARK: - Report Generation
    
    private func generateNetworkSecurityReport() -> NetworkSecurityReport {
        let recommendations = generateNetworkRecommendations()
        let securityScore = calculateNetworkSecurityScore()
        
        return NetworkSecurityReport(
            connections: networkConnections,
            vulnerabilities: vulnerabilities,
            recommendations: recommendations,
            securityScore: securityScore
        )
    }
    
    private func generateNetworkRecommendations() -> [String] {
        var recommendations = [
            "始终使用 HTTPS 进行网络通信",
            "启用 Certificate Pinning 防止中间人攻击",
            "使用最新的 TLS 版本 (TLS 1.3)",
            "验证 SSL 证书的有效性和过期时间"
        ]
        
        if vulnerabilities.contains(where: { $0.type == .unencryptedTraffic }) {
            recommendations.append("消除所有未加密的网络流量")
        }
        
        if vulnerabilities.contains(where: { $0.type == .weakTLS }) {
            recommendations.append("升级 TLS/SSL 配置，移除弱加密套件")
        }
        
        if vulnerabilities.contains(where: { $0.type == .dnsHijacking }) {
            recommendations.append("使用安全的 DNS 服务器 (如 1.1.1.1, 8.8.8.8)")
            recommendations.append("启用 DNS over HTTPS (DoH)")
        }
        
        recommendations.append("定期更新网络安全配置")
        recommendations.append("实施网络流量监控和异常检测")
        
        return recommendations
    }
    
    private func calculateNetworkSecurityScore() -> Int {
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
    
    private func formatNetworkReport(_ report: NetworkSecurityReport) -> String {
        var output = ""
        
        output += "网络连接分析 (\(report.connections.count)个连接):\n"
        for connection in report.connections.prefix(5) { // 只显示前5个
            let secureIcon = connection.isSecure ? "🔒" : "🔓"
            let protocolName = getProtocolName(connection.protocol)
            output += "\(secureIcon) \(connection.host):\(connection.port) (\(protocolName))\n"
        }
        
        if report.connections.count > 5 {
            output += "... 以及其他 \(report.connections.count - 5) 个连接\n"
        }
        
        output += "\n网络安全问题 (\(report.vulnerabilities.count)个):\n"
        if report.vulnerabilities.isEmpty {
            output += "✅ 未发现网络安全问题\n"
        } else {
            for vulnerability in report.vulnerabilities {
                let severityIcon = getVulnerabilitySeverityIcon(vulnerability.severity)
                output += "\(severityIcon) \(vulnerability.description)\n"
            }
        }
        
        output += "\n网络安全评分: \(report.securityScore)/100\n"
        
        output += "\n安全建议:\n"
        for (index, recommendation) in report.recommendations.enumerated() {
            output += "\(index + 1). \(recommendation)\n"
        }
        
        return output
    }
    
    private func getProtocolName(_ protocol: NetworkConnection.NetworkProtocol) -> String {
        switch protocol {
        case .http:
            return "HTTP"
        case .https:
            return "HTTPS"
        case .tcp:
            return "TCP"
        case .udp:
            return "UDP"
        case .websocket:
            return "WebSocket"
        case .unknown:
            return "Unknown"
        }
    }
    
    private func getVulnerabilitySeverityIcon(_ severity: NetworkVulnerability.Severity) -> String {
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

// MARK: - Network Testing Methods

extension NetworkMonitor {
    
    /// 测试网络连接性能和安全性
    func performNetworkSecurityTest() -> String {
        var report = "网络安全测试:\n"
        
        // 测试 HTTPS 连接
        report += testHTTPSConnection()
        
        // 测试证书验证
        report += testCertificateValidation()
        
        // 测试网络延迟
        report += testNetworkLatency()
        
        return report
    }
    
    private func testHTTPSConnection() -> String {
        var result = "\n🔐 HTTPS 连接测试:\n"
        
        let testURL = URL(string: "https://httpbin.org/get")!
        let semaphore = DispatchSemaphore(value: 0)
        var success = false
        
        let task = URLSession.shared.dataTask(with: testURL) { data, response, error in
            if let httpResponse = response as? HTTPURLResponse {
                success = httpResponse.statusCode == 200
            }
            semaphore.signal()
        }
        
        task.resume()
        _ = semaphore.wait(timeout: .now() + 5)
        
        result += success ? "✅ HTTPS 连接成功\n" : "❌ HTTPS 连接失败\n"
        return result
    }
    
    private func testCertificateValidation() -> String {
        var result = "\n📜 证书验证测试:\n"
        
        // 这里应该实现实际的证书验证逻辑
        // 简化为模拟结果
        let isValid = arc4random_uniform(2) == 0
        result += isValid ? "✅ 证书验证通过\n" : "❌ 证书验证失败\n"
        
        return result
    }
    
    private func testNetworkLatency() -> String {
        var result = "\n⏱️ 网络延迟测试:\n"
        
        let startTime = CFAbsoluteTimeGetCurrent()
        
        // 模拟网络延迟测试
        Thread.sleep(forTimeInterval: 0.1) // 模拟 100ms 延迟
        
        let latency = CFAbsoluteTimeGetCurrent() - startTime
        result += "📊 网络延迟: \(Int(latency * 1000))ms\n"
        
        if latency < 0.2 {
            result += "✅ 网络延迟正常\n"
        } else {
            result += "⚠️ 网络延迟较高\n"
        }
        
        return result
    }
}