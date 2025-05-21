import type { VerificationToken } from "../entities/verification-token.entity"
import type { Repository } from "../../../../common/interfaces/repository.interface"

export interface VerificationTokenRepository extends Repository<VerificationToken> {
  findByToken(token: string): Promise<VerificationToken | null>
  deleteById(id: string): Promise<void>
}
