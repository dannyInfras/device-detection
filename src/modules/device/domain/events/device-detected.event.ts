export class DeviceDetectedEvent {
  constructor(
    public readonly deviceId: string,
    public readonly userId: string,
    public readonly fingerprint: string,
    public readonly userAgent: string,
    public readonly ipAddress: string,
  ) {}
}
