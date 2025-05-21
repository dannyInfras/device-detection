import { Entity, Column, PrimaryColumn } from "typeorm"

@Entity("users")
export class UserOrmEntity {
  @PrimaryColumn()
  id: string

  @Column({ unique: true })
  email: string

  @Column()
  passwordHash: string

  @Column()
  fullName: string

  @Column("simple-array")
  roles: string[]

  @Column()
  createdAt: Date

  @Column()
  updatedAt: Date
} 