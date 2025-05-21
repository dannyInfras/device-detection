import { Injectable, type CanActivate, type ExecutionContext } from "@nestjs/common"
import type { Reflector } from "@nestjs/core"
import { ROLES_KEY } from "../decorators/roles.decorator"
import type { JwtService } from "@nestjs/jwt"

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private jwtService: JwtService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ])
    if (!requiredRoles) return true

    const request = context.switchToHttp().getRequest()
    const token = request.headers.authorization?.replace("Bearer ", "")
    if (!token) return false

    const payload = this.jwtService.verify(token)
    return requiredRoles.some((role) => payload.roles?.includes(role))
  }
}
