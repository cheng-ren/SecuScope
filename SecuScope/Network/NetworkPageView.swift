//
//  NetworkPageView.swift
//  SecuScope
//
//  Created by yiche on 2025/9/25.
//

import SwiftUI
import Combine
import Network

// MARK: - Network Response Model
struct NetworkResponse: Identifiable {
    let id = UUID()
    let type: String
    let statusCode: Int?
    let error: String?
    var isRunning: Bool = false
    
    init(type: String, statusCode: Int? = nil, error: String? = nil, isRunning: Bool = false) {
        self.type = type
        self.statusCode = statusCode
        self.error = error
        self.isRunning = isRunning
    }
}

// MARK: - Network Manager
class NetworkManager {
    func makeHTTPCall() async -> NetworkResponse {
        guard let url = URL(string: "http://baidu.com") else {
            return NetworkResponse(type: "HTTP", error: "Invalid URL")
        }
        
        do {
            let (_, response) = try await URLSession.shared.data(from: url)
            if let httpResponse = response as? HTTPURLResponse {
                return NetworkResponse(type: "HTTP", statusCode: httpResponse.statusCode)
            } else {
                return NetworkResponse(type: "HTTP", error: "Invalid response")
            }
        } catch {
            return NetworkResponse(type: "HTTP", error: error.localizedDescription)
        }
    }
    
    func makeHTTPSCall() async -> NetworkResponse {
        guard let url = URL(string: "https://baidu.com") else {
            return NetworkResponse(type: "HTTPS", error: "Invalid URL")
        }
        
        do {
            let (_, response) = try await URLSession.shared.data(from: url)
            if let httpResponse = response as? HTTPURLResponse {
                return NetworkResponse(type: "HTTPS", statusCode: httpResponse.statusCode)
            } else {
                return NetworkResponse(type: "HTTPS", error: "Invalid response")
            }
        } catch {
            return NetworkResponse(type: "HTTPS", error: error.localizedDescription)
        }
    }
    
    // 注意：QUIC 支持需要特定的网络库，在标准 iOS SDK 中不直接支持
    // 这里提供一个模拟实现
    func makeQUICCall() async -> NetworkResponse {
        // 模拟 QUIC 请求
        do {
            let connection = NWConnection(host: "https://baidu.com", port: 443, using: .quic(alpn: ["myproto"]));
            connection.start(queue: .global())
            
            
            // 模拟成功响应
            return NetworkResponse(type: "QUIC", statusCode: 200)
        } catch {
            return NetworkResponse(type: "QUIC", error: "QUIC not supported in this implementation")
        }
    }
    
    // Socket 请求实现（简化版本）
    func makeSocketCall() async -> NetworkResponse {
        // 模拟 Socket 请求
        do {
            try await Task.sleep(nanoseconds: 1_000_000_000) // 1秒延迟模拟网络请求
            // 模拟成功响应
            return NetworkResponse(type: "Socket", statusCode: 200)
        } catch {
            return NetworkResponse(type: "Socket", error: "Socket connection failed")
        }
    }
}

// MARK: - View Model
@MainActor
class NetworkViewModel: ObservableObject {
    @Published var responses: [NetworkResponse] = [
        NetworkResponse(type: "HTTP"),
        NetworkResponse(type: "HTTPS"),
        NetworkResponse(type: "QUIC"),
        NetworkResponse(type: "Socket")
    ]
    
    private let networkManager = NetworkManager()
    
    func runAllTests() {
        Task {
            await runHTTPTest()
            await runHTTPSTest()
            await runQUICTest()
            await runSocketTest()
        }
    }
    
    private func runHTTPTest() async {
        await updateResponse(type: "HTTP", isRunning: true)
        let result = await networkManager.makeHTTPCall()
        await updateResponse(type: "HTTP", response: result)
    }
    
    private func runHTTPSTest() async {
        await updateResponse(type: "HTTPS", isRunning: true)
        let result = await networkManager.makeHTTPSCall()
        await updateResponse(type: "HTTPS", response: result)
    }
    
    private func runQUICTest() async {
        await updateResponse(type: "QUIC", isRunning: true)
        let result = await networkManager.makeQUICCall()
        await updateResponse(type: "QUIC", response: result)
    }
    
    private func runSocketTest() async {
        await updateResponse(type: "Socket", isRunning: true)
        let result = await networkManager.makeSocketCall()
        await updateResponse(type: "Socket", response: result)
    }
    
    private func updateResponse(type: String, isRunning: Bool = false, response: NetworkResponse? = nil) async {
        await MainActor.run {
            if let index = responses.firstIndex(where: { $0.type == type }) {
                if let response = response {
                    responses[index] = response
                } else {
                    var updatedResponse = responses[index]
                    updatedResponse.isRunning = isRunning
                    responses[index] = updatedResponse
                }
            }
        }
    }
}

// MARK: - View
struct NetworkPageView: View {
    @StateObject private var viewModel = NetworkViewModel()
    
    var body: some View {
        NavigationStack {
            List {
                ForEach(viewModel.responses) { response in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(response.type)
                                .font(.headline)
                            Spacer()
                            if response.isRunning {
                                ProgressView()
                                    .scaleEffect(0.8)
                            }
                        }
                        
                        if let statusCode = response.statusCode {
                            Text("状态码: \(statusCode)")
                                .font(.subheadline)
                                .foregroundColor(statusCode >= 200 && statusCode < 300 ? .green : .red)
                        } else if let error = response.error {
                            Text("错误: \(error)")
                                .font(.subheadline)
                                .foregroundColor(.red)
                        } else {
                            Text("未执行")
                                .font(.subheadline)
                                .foregroundColor(.gray)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            .navigationTitle("网络检测")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("运行测试") {
                        viewModel.runAllTests()
                    }
                }
            }
        }
    }
}

#Preview {
    NetworkPageView()
}
