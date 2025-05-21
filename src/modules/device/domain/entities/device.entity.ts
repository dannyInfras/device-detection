import { v4 as uuidv4 } from "uuid"

/**
 * Domain entity representing a user device.
 */
export class Device {
  private id: string
  private userId: string
  private fingerprint: string // Encrypted in storage
  private userAgent: string
  private ipAddress: string
  private isVerified: boolean
  private createdAt: Date
  private lastUsedAt: Date

  constructor(props: {
    id?: string
    userId: string
    fingerprint: string
    userAgent: string
    ipAddress: string
  }) {
    this.id = props.id ?? uuidv4()
    this.userId = props.userId
    this.fingerprint = props.fingerprint
    this.userAgent = props.userAgent
    this.ipAddress = props.ipAddress
    this.isVerified = false
    this.createdAt = new Date()
    this.lastUsedAt = new Date()
  }

  verify(): void {
    this.isVerified = true
    this.lastUsedAt = new Date()
  }

  updateLastUsed(): void {
    this.lastUsedAt = new Date()
  }

  getId(): string {
    return this.id
  }
  getUserId(): string {
    return this.userId
  }
  getFingerprint(): string {
    return this.fingerprint
  }
  getIsVerified(): boolean {
    return this.isVerified
  }
  getUserAgent(): string {
    return this.userAgent
  }
  getIpAddress(): string {
    return this.ipAddress
  }
  getCreatedAt(): Date {
    return this.createdAt
  }
  getLastUsedAt(): Date {
    return this.lastUsedAt
  }
}
