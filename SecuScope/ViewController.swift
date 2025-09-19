import UIKit

class ViewController: UIViewController {
    
    @IBOutlet weak var securityStatusLabel: UILabel!
    @IBOutlet weak var encryptionStatusLabel: UILabel!
    @IBOutlet weak var networkStatusLabel: UILabel!
    @IBOutlet weak var uiSecurityStatusLabel: UILabel!
    @IBOutlet weak var fileSecurityStatusLabel: UILabel!
    @IBOutlet weak var runSecurityScanButton: UIButton!
    @IBOutlet weak var resultTextView: UITextView!
    
    private let securityDetector = SecurityDetector.shared
    private let encryptionAnalyzer = EncryptionAnalyzer()
    private let networkMonitor = NetworkMonitor()
    private let uiSecurityChecker = UISecurityChecker()
    private let fileOperationMonitor = FileOperationMonitor()

    override func viewDidLoad() {
        super.viewDidLoad()
        
        setupUI()
        setupSecurityMonitoring()
    }
    
    private func setupUI() {
        view.backgroundColor = UIColor.systemBackground
        title = "SecuScope - 安全检测"
        
        // Create UI elements programmatically if storyboard outlets are not connected
        if securityStatusLabel == nil {
            createUIElements()
            setupConstraints()
        }
        
        updateSecurityStatus()
    }
    
    private func createUIElements() {
        // Title Label
        let titleLabel = UILabel()
        titleLabel.text = "SecuScope - iOS 安全分析工具"
        titleLabel.font = UIFont.boldSystemFont(ofSize: 24)
        titleLabel.textAlignment = .center
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(titleLabel)
        
        // Security Status Labels
        securityStatusLabel = createStatusLabel(text: "整体安全状态: 检测中...")
        encryptionStatusLabel = createStatusLabel(text: "加密算法: 检测中...")
        networkStatusLabel = createStatusLabel(text: "网络安全: 检测中...")
        uiSecurityStatusLabel = createStatusLabel(text: "UI安全: 检测中...")
        fileSecurityStatusLabel = createStatusLabel(text: "文件操作: 检测中...")
        
        // Run Scan Button
        runSecurityScanButton = UIButton(type: .system)
        runSecurityScanButton.setTitle("运行安全扫描", for: .normal)
        runSecurityScanButton.titleLabel?.font = UIFont.boldSystemFont(ofSize: 18)
        runSecurityScanButton.backgroundColor = UIColor.systemBlue
        runSecurityScanButton.setTitleColor(.white, for: .normal)
        runSecurityScanButton.layer.cornerRadius = 8
        runSecurityScanButton.translatesAutoresizingMaskIntoConstraints = false
        runSecurityScanButton.addTarget(self, action: #selector(runSecurityScan), for: .touchUpInside)
        view.addSubview(runSecurityScanButton)
        
        // Result Text View
        resultTextView = UITextView()
        resultTextView.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        resultTextView.backgroundColor = UIColor.systemGray6
        resultTextView.layer.cornerRadius = 8
        resultTextView.isEditable = false
        resultTextView.text = "安全扫描结果将在这里显示..."
        resultTextView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(resultTextView)
        
        // Set up constraints
        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            titleLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            
            securityStatusLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 30),
            securityStatusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            securityStatusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            
            encryptionStatusLabel.topAnchor.constraint(equalTo: securityStatusLabel.bottomAnchor, constant: 10),
            encryptionStatusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            encryptionStatusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            
            networkStatusLabel.topAnchor.constraint(equalTo: encryptionStatusLabel.bottomAnchor, constant: 10),
            networkStatusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            networkStatusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            
            uiSecurityStatusLabel.topAnchor.constraint(equalTo: networkStatusLabel.bottomAnchor, constant: 10),
            uiSecurityStatusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            uiSecurityStatusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            
            fileSecurityStatusLabel.topAnchor.constraint(equalTo: uiSecurityStatusLabel.bottomAnchor, constant: 10),
            fileSecurityStatusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            fileSecurityStatusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            
            runSecurityScanButton.topAnchor.constraint(equalTo: fileSecurityStatusLabel.bottomAnchor, constant: 30),
            runSecurityScanButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            runSecurityScanButton.widthAnchor.constraint(equalToConstant: 200),
            runSecurityScanButton.heightAnchor.constraint(equalToConstant: 50),
            
            resultTextView.topAnchor.constraint(equalTo: runSecurityScanButton.bottomAnchor, constant: 20),
            resultTextView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            resultTextView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            resultTextView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -20)
        ])
    }
    
    private func createStatusLabel(text: String) -> UILabel {
        let label = UILabel()
        label.text = text
        label.font = UIFont.systemFont(ofSize: 16)
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        return label
    }
    
    private func setupConstraints() {
        // This method would be used if we had more complex constraint setup
    }
    
    private func setupSecurityMonitoring() {
        // Start all security monitoring components
        networkMonitor.startMonitoring { [weak self] results in
            DispatchQueue.main.async {
                self?.updateNetworkStatus(results)
            }
        }
        
        fileOperationMonitor.startMonitoring { [weak self] results in
            DispatchQueue.main.async {
                self?.updateFileSecurityStatus(results)
            }
        }
        
        uiSecurityChecker.startMonitoring { [weak self] results in
            DispatchQueue.main.async {
                self?.updateUISecurityStatus(results)
            }
        }
    }
    
    @objc private func runSecurityScan() {
        runSecurityScanButton.isEnabled = false
        runSecurityScanButton.setTitle("扫描中...", for: .normal)
        resultTextView.text = "开始安全扫描...\n"
        
        // Run comprehensive security scan
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            
            var scanResults = ""
            
            // Encryption Analysis
            scanResults += "=== 加密算法分析 ===\n"
            let encryptionResults = self.encryptionAnalyzer.analyzeEncryption()
            scanResults += encryptionResults + "\n\n"
            
            // Network Security Analysis
            scanResults += "=== 网络安全分析 ===\n"
            let networkResults = self.networkMonitor.analyzeNetworkSecurity()
            scanResults += networkResults + "\n\n"
            
            // UI Security Analysis
            scanResults += "=== UI安全分析 ===\n"
            let uiResults = self.uiSecurityChecker.analyzeUIComponents()
            scanResults += uiResults + "\n\n"
            
            // File Operation Analysis
            scanResults += "=== 文件操作分析 ===\n"
            let fileResults = self.fileOperationMonitor.analyzeFileOperations()
            scanResults += fileResults + "\n\n"
            
            // Overall Security Assessment
            scanResults += "=== 整体安全评估 ===\n"
            let overallResults = self.securityDetector.performComprehensiveSecurityCheck()
            scanResults += overallResults
            
            DispatchQueue.main.async {
                self.resultTextView.text = scanResults
                self.runSecurityScanButton.isEnabled = true
                self.runSecurityScanButton.setTitle("运行安全扫描", for: .normal)
                self.updateSecurityStatus()
            }
        }
    }
    
    private func updateSecurityStatus() {
        securityStatusLabel?.text = "整体安全状态: \(securityDetector.getOverallSecurityStatus())"
        securityStatusLabel?.textColor = securityDetector.isSecure() ? .systemGreen : .systemRed
    }
    
    private func updateNetworkStatus(_ results: String) {
        networkStatusLabel?.text = "网络安全: \(results)"
        networkStatusLabel?.textColor = results.contains("安全") ? .systemGreen : .systemOrange
    }
    
    private func updateUISecurityStatus(_ results: String) {
        uiSecurityStatusLabel?.text = "UI安全: \(results)"
        uiSecurityStatusLabel?.textColor = results.contains("安全") ? .systemGreen : .systemOrange
    }
    
    private func updateFileSecurityStatus(_ results: String) {
        fileSecurityStatusLabel?.text = "文件操作: \(results)"
        fileSecurityStatusLabel?.textColor = results.contains("安全") ? .systemGreen : .systemOrange
    }
}