import { registerAs } from "@nestjs/config"
import { randomBytes } from "crypto"

// Generate a default encryption key (32 bytes in hex format)
const defaultEncryptionKey = randomBytes(32).toString('hex');

export default registerAs("app", () => ({
  env: process.env.NODE_ENV || "development",
  port: Number.parseInt(process.env.PORT || "3000", 10),
  url: process.env.APP_URL || "http://localhost:3000",
  jwt: {
    secret: process.env.JWT_SECRET || "default-jwt-secret-for-development-only",
    expiresIn: "24h",
  },
  redis: {
    url: process.env.REDIS_URL || "redis://localhost:6379",
  },
  kafka: {
    brokers: process.env.KAFKA_BROKERS?.split(",") || ["localhost:9092"],
    clientId: process.env.KAFKA_CLIENT_ID || "auth-service",
    groupId: process.env.KAFKA_GROUP_ID || "auth-group",
  },
  email: {
    provider: process.env.EMAIL_PROVIDER || "nodemailer",
    host: process.env.EMAIL_HOST || "smtp.example.com",
    port: Number.parseInt(process.env.EMAIL_PORT || "587", 10),
    user: process.env.EMAIL_USER || "test@example.com",
    pass: process.env.EMAIL_PASS || "password",
  },
  encryption: {
    // Use the provided encryption key or the default one
    key: process.env.ENCRYPTION_KEY || defaultEncryptionKey,
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests
  },
  db: {
    host: process.env.DB_HOST || "localhost",
    port: Number.parseInt(process.env.DB_PORT || "5432", 10),
    username: process.env.DB_USERNAME || "postgres",
    password: process.env.DB_PASSWORD || "postgres",
    name: process.env.DB_NAME || "auth_service",
  },
}))
