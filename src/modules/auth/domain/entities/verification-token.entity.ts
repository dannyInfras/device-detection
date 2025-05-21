import { v4 as uuidv4 } from "uuid"

/**
 * Domain entity for verification tokens.
 */
export class VerificationToken {
  private id: string
  private deviceId: string
  private token: string
  private expiresAt: Date

  constructor(props: { id?: string; deviceId: string; token?: string; expiresAt: Date }) {
    this.id = props.id ?? uuidv4()
    this.deviceId = props.deviceId
    this.token = props.token ?? uuidv4()
    this.expiresAt = props.expiresAt
  }

  isExpired(): boolean {
    return new Date() > this.expiresAt
  }

  getId(): string {
    return this.id
  }
  getDeviceId(): string {
    return this.deviceId
  }
  getToken(): string {
    return this.token
  }
  getExpiresAt(): Date {
    return this.expiresAt
  }
}
