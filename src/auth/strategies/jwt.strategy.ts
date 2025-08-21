// src/auth/strategies/jwt.strategy.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService) {
    const secret =
      configService.get<string>('JWT_SECRET') ||
      configService.get<string>('jwt.secret') ||
      process.env.JWT_SECRET;

    if (!secret) {
      throw new Error('JWT_SECRET is not configured for JWT Strategy');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: secret,
    });
  }

  async validate(payload: JwtPayload) {
    const roles = Array.isArray(payload.roles) ? payload.roles : ['user'];

    return {
      id: payload.sub,
      email: payload.email,
      roles: roles,
      impersonatedBy: payload.impersonatedBy,
      impersonatorEmail: payload.impersonatorEmail,
      isImpersonation: !!payload.isImpersonation,
      rememberMe: payload.rememberMe || false,
    };
  }
}
