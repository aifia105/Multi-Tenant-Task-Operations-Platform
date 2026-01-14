import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from 'src/auth/types/jwt-payload.type';
import { ROLES_KEY } from 'src/decorators/roles.decorator';
import { UserRoleType } from 'src/users/enum/user-role.enum';

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly reflector: Reflector,
    private readonly configService: ConfigService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<UserRoleType[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles) return true;

    const request = context.switchToHttp().getRequest();
    const token = request.cookies.access_token;

    if (!token) throw new UnauthorizedException();

    const payload: JwtPayload = await this.jwtService.verifyAsync(token, {
      secret: this.configService.get<string>('jwt.secret'),
    });

    if (!payload) throw new UnauthorizedException();

    const hasRole = requiredRoles.some((role) => payload.role === role);

    if (!hasRole) throw new ForbiddenException('Missing required role');

    return true;
  }
}
