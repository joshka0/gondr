import Foundation
import Security

private let service = "gondr-token.cloudflare"
private let account = "bootstrap"
private let brokerPath = "/Users/you/.local/share/cloudflare-token-mint/cloudflare-token-mint"

private var result: CFTypeRef?
private let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecAttrAccount as String: account,
    kSecReturnRef as String: true,
    kSecMatchLimit as String: kSecMatchLimitOne,
]

private let findStatus = SecItemCopyMatching(query as CFDictionary, &result)
guard findStatus == errSecSuccess, let item = result as! SecKeychainItem? else {
    FileHandle.standardError.write(Data("bind=failed stage=find status=\(findStatus)\n".utf8))
    exit(1)
}

private var trustedApplication: SecTrustedApplication?
private let trustStatus = SecTrustedApplicationCreateFromPath(brokerPath, &trustedApplication)
guard trustStatus == errSecSuccess, let trustedApplication else {
    FileHandle.standardError.write(Data("bind=failed stage=trusted-application status=\(trustStatus)\n".utf8))
    exit(1)
}

private var access: SecAccess?
private let accessStatus = SecAccessCreate(
    "Approve Cloudflare token creation" as CFString,
    [trustedApplication] as CFArray,
    &access
)
guard accessStatus == errSecSuccess, let access else {
    FileHandle.standardError.write(Data("bind=failed stage=access status=\(accessStatus)\n".utf8))
    exit(1)
}

private let bindStatus = SecKeychainItemSetAccess(item, access)
guard bindStatus == errSecSuccess else {
    FileHandle.standardError.write(Data("bind=failed stage=set-access status=\(bindStatus)\n".utf8))
    exit(1)
}

print("bind=complete")
print("trusted_executable=cloudflare-token-mint")
