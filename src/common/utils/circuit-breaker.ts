export class CircuitBreaker {
  private failureCount: number
  private lastFailureTime: number | null
  private readonly options: {
    failureThreshold: number
    resetTimeout: number
  }

  constructor(options: { failureThreshold: number; resetTimeout: number }) {
    this.failureCount = 0
    this.lastFailureTime = null
    this.options = options
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.isOpen()) {
      throw new Error("Circuit breaker is open")
    }

    try {
      const result = await fn()
      this.reset()
      return result
    } catch (error) {
      this.failureCount++
      this.lastFailureTime = Date.now()
      throw error
    }
  }

  private isOpen(): boolean {
    return (
      this.failureCount >= this.options.failureThreshold &&
      (this.lastFailureTime === null || Date.now() - this.lastFailureTime < this.options.resetTimeout)
    )
  }

  private reset(): void {
    this.failureCount = 0
    this.lastFailureTime = null
  }
}
