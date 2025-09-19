import Foundation
import CryptoKit

class EncryptionUtils {
    // MARK: - AES Encryption/Decryption
    static func aesEncrypt(_ text: String, key: String) -> Data? {
        guard let data = text.data(using: .utf8) else { return nil }
        guard let keyData = key.data(using: .utf8) else { return nil }
        
        // Pad key to 32 bytes for AES-256
        let paddedKey = padData(keyData, toLength: 32)
        
        do {
            let key = SymmetricKey(data: paddedKey)
            let sealedBox = try AES.GCM.seal(data, using: key)
            return sealedBox.combined
        } catch {
            print("AES encryption error: \(error)")
            return nil
        }
    }
    
    static func aesDecrypt(_ data: Data, key: String) -> String? {
        guard let keyData = key.data(using: .utf8) else { return nil }
        
        // Pad key to 32 bytes for AES-256
        let paddedKey = padData(keyData, toLength: 32)
        
        do {
            let key = SymmetricKey(data: paddedKey)
            let sealedBox = try AES.GCM.SealedBox(combined: data)
            let decryptedData = try AES.GCM.open(sealedBox, using: key)
            return String(data: decryptedData, encoding: .utf8)
        } catch {
            print("AES decryption error: \(error)")
            return nil
        }
    }
    
    // MARK: - MD5 Hash
    static func md5(_ text: String) -> String {
        guard let data = text.data(using: .utf8) else { return "" }
        let hashed = Insecure.MD5.hash(data: data)
        return hashed.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    // MARK: - SHA256 Hash
    static func sha256(_ text: String) -> String {
        guard let data = text.data(using: .utf8) else { return "" }
        let hashed = SHA256.hash(data: data)
        return hashed.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    // MARK: - Helper Functions
    private static func padData(_ data: Data, toLength length: Int) -> Data {
        var result = Data(data)
        if result.count < length {
            let padding = Data(repeating: 0, count: length - result.count)
            result.append(padding)
        } else if result.count > length {
            result = result.subdata(in: 0..<length)
        }
        return result
    }
}
