export class VerificationInitiatedEvent {
  constructor(
    public readonly deviceId: string,
    public readonly userEmail: string,
    public readonly token: string,
  ) {}
}
