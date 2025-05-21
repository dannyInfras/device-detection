export interface EmailService {
  sendVerificationEmail(to: string, token: string, deviceId: string): Promise<void>
}
