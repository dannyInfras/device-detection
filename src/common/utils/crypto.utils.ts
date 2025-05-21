import { createCipheriv, createDecipheriv, randomBytes } from "crypto"
import { Injectable } from "@nestjs/common"
import type { ConfigService } from "@nestjs/config"

@Injectable()
export class CryptoService {
  private algorithm = "aes-256-cbc"
  private key: Buffer

  constructor(configService: ConfigService) {
    this.key = Buffer.from(configService.get("app.encryption.key"), "hex")
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
