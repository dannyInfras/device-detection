import { Entity, Column, PrimaryColumn, Index } from "typeorm"

/**
 * Database entity for devices with partitioning support.
 */
@Entity("devices", {
  comment: "Partitioned by userId for scalability",
})
@Index(["fingerprint"], { unique: true })
@Index(["userId"])
export class DeviceOrmEntity {
  @PrimaryColumn()
  id: string

  @Column()
  userId: string

  @Column()
  fingerprint: string // Encrypted

  @Column()
  userAgent: string

  @Column()
  ipAddress: string

  @Column({ default: false })
  isVerified: boolean

  @Column()
  createdAt: Date

  @Column()
  lastUsedAt: Date
}
