import { Entity, Column, PrimaryColumn, Index } from "typeorm"

@Entity("verification_tokens")
@Index(["token"], { unique: true })
export class VerificationTokenOrmEntity {
  @PrimaryColumn()
  id: string

  @Column()
  deviceId: string

  @Column()
  token: string

  @Column()
  expiresAt: Date
}
