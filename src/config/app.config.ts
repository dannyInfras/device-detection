import { registerAs } from "@nestjs/config"
import { randomBytes } from "crypto"

export default registerAs("app", () => ({
  env: process.env.NODE_ENV || "development",
  port: Number.parseInt(process.env.PORT, 10) || 3000,
  url: process.env.APP_URL || "http://localhost:3000",
  jwt: {
    secret: process.env.JWT_SECRET || "your-jwt-secret",
    expiresIn: "24h",
  },
  redis: {
    url: process.env.REDIS_URL || "redis://localhost:6379",
  },
  kafka: {
    brokers: process.env.KAFKA_BROKERS?.split(",") || ["localhost:9092"],
    clientId: "auth-service",
  },
  email: {
    provider: process.env.EMAIL_PROVIDER || "nodemailer",
    host: process.env.EMAIL_HOST,
    port: Number.parseInt(process.env.EMAIL_PORT, 10) || 587,
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  encryption: {
    key: process.env.ENCRYPTION_KEY || Buffer.from(randomBytes(32)).toString("hex"),
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests
  },
  db: {
    host: process.env.DB_HOST || "localhost",
    port: Number.parseInt(process.env.DB_PORT, 10) || 5432,
    username: process.env.DB_USERNAME || "postgres",
    password: process.env.DB_PASSWORD || "postgres",
    name: process.env.DB_NAME || "auth_service",
  },
}))
