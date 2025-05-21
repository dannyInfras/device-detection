import { v4 as uuidv4 } from "uuid"
import * as bcrypt from "bcrypt"

export class User {
  private id: string
  private email: string
  private passwordHash: string
  private fullName: string
  private roles: string[]
  private createdAt: Date
  private updatedAt: Date

  constructor(props: {
    id?: string
    email: string
    passwordHash?: string
    password?: string
    fullName: string
    roles?: string[]
  }) {
    this.id = props.id ?? uuidv4()
    this.email = props.email
    
    if (props.passwordHash) {
      this.passwordHash = props.passwordHash
    } else if (props.password) {
      this.passwordHash = this.hashPassword(props.password)
    } else {
      throw new Error("Either password or passwordHash must be provided")
    }
    
    this.fullName = props.fullName
    this.roles = props.roles ?? ["user"]
    this.createdAt = new Date()
    this.updatedAt = new Date()
  }

  private hashPassword(password: string): string {
    const salt = bcrypt.genSaltSync(10)
    return bcrypt.hashSync(password, salt)
  }

  validatePassword(password: string): boolean {
    return bcrypt.compareSync(password, this.passwordHash)
  }

  getId(): string {
    return this.id
  }

  getEmail(): string {
    return this.email
  }

  getPasswordHash(): string {
    return this.passwordHash
  }

  getFullName(): string {
    return this.fullName
  }

  getRoles(): string[] {
    return [...this.roles]
  }

  getCreatedAt(): Date {
    return this.createdAt
  }

  getUpdatedAt(): Date {
    return this.updatedAt
  }
} 