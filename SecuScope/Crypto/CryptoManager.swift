import Foundation
import CommonCrypto

class CryptoManager {
    static let shared = CryptoManager()
    
    private init() {}
    
    // MARK: - AES Encryption/Decryption
    
    func aesEncrypt(data: Data, key: String, iv: String) -> Data? {
        let keyData = key.data(using: .utf8)!
        let ivData = iv.data(using: .utf8)!
        
        let cryptLength = size_t(data.count + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)
        
        let keyLength = keyData.count
        let ivLength = ivData.count
        
        var numBytesEncrypted = 0
        
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                keyData.withUnsafeBytes { keyBytes in
                    ivData.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress,
                            keyLength,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress,
                            data.count,
                            cryptBytes.baseAddress,
                            cryptLength,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }
        
        if cryptStatus == CCCryptorStatus(kCCSuccess) {
            cryptData.removeSubrange(numBytesEncrypted..<cryptData.count)
            return cryptData
        }
        
        return nil
    }
    
    func aesDecrypt(data: Data, key: String, iv: String) -> Data? {
        let keyData = key.data(using: .utf8)!
        let ivData = iv.data(using: .utf8)!
        
        let cryptLength = size_t(data.count + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)
        
        let keyLength = keyData.count
        let ivLength = ivData.count
        
        var numBytesDecrypted = 0
        
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                keyData.withUnsafeBytes { keyBytes in
                    ivData.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress,
                            keyLength,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress,
                            data.count,
                            cryptBytes.baseAddress,
                            cryptLength,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }
        
        if cryptStatus == CCCryptorStatus(kCCSuccess) {
            cryptData.removeSubrange(numBytesDecrypted..<cryptData.count)
            return cryptData
        }
        
        return nil
    }
    
    // MARK: - Hash Functions
    
    func md5(_ input: String) -> String {
        let data = input.data(using: .utf8)!
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        
        data.withUnsafeBytes { buffer in
            CC_MD5(buffer.baseAddress, CC_LONG(data.count), &digest)
        }
        
        return digest.map { String(format: "%02x", $0) }.joined()
    }
    
    func sha256(_ input: String) -> String {
        let data = input.data(using: .utf8)!
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        data.withUnsafeBytes { buffer in
            CC_SHA256(buffer.baseAddress, CC_LONG(data.count), &digest)
        }
        
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
