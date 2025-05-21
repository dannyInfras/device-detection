import { createCipheriv, createDecipheriv, randomBytes } from "crypto"
import { Injectable } from "@nestjs/common"
import type { ConfigService } from "@nestjs/config"

@Injectable()
export class CryptoService {
  private algorithm = "aes-256-cbc"
  private key: Buffer

  constructor(configService: ConfigService) {
    const encryptionKey = configService.get<string>("app.encryption.key")
    if (!encryptionKey) {
      // Generate a 32-byte key (required for AES-256)
      this.key = randomBytes(32);
    } else {
      // If a key is provided, ensure it's the correct length
      if (Buffer.from(encryptionKey, 'hex').length !== 32) {
        // If the provided key doesn't have the correct length, generate a new one
        this.key = randomBytes(32);
      } else {
        this.key = Buffer.from(encryptionKey, "hex")
      }
    }
  }

  encrypt(text: string): string {
    const iv = randomBytes(16)
    const cipher = createCipheriv(this.algorithm, this.key, iv)
    let encrypted = cipher.update(text, "utf8", "hex")
    encrypted += cipher.final("hex")
    return `${iv.toString("hex")}:${encrypted}`
  }

  decrypt(encryptedText: string): string {
    const [ivHex, encrypted] = encryptedText.split(":")
    const iv = Buffer.from(ivHex, "hex")
    const decipher = createDecipheriv(this.algorithm, this.key, iv)
    let decrypted = decipher.update(encrypted, "hex", "utf8")
    decrypted += decipher.final("utf8")
    return decrypted
  }
}
