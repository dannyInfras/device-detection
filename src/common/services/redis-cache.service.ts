import { Injectable, Logger } from "@nestjs/common"
import type { CacheService } from "../interfaces/cache.interface"
import { Redis } from "ioredis"
import type { ConfigService } from "@nestjs/config"

@Injectable()
export class RedisCacheService implements CacheService {
  private readonly logger = new Logger(RedisCacheService.name)
  private client: Redis

  constructor(configService: ConfigService) {
    const redisUrl = configService.get<string>("app.redis.url") || "redis://localhost:6379"
    this.client = new Redis(redisUrl)
    this.client.on("error", (err) => this.logger.error(`Redis error: ${err.message}`))
  }

  async get<T>(key: string): Promise<T | null> {
    const data = await this.client.get(key)
    return data ? JSON.parse(data) : null
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    const stringValue = JSON.stringify(value)
    if (ttl) {
      await this.client.setex(key, ttl, stringValue)
    } else {
      await this.client.set(key, stringValue)
    }
  }

  async del(key: string): Promise<void> {
    await this.client.del(key)
  }
}
