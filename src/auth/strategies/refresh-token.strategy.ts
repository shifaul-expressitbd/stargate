import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../database/prisma/prisma.service';
import { JwtPayload } from '../auth.service';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'refresh-token',
) {
  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    const refreshSecret = configService.get<string>('JWT_REFRESH_SECRET');

    if (!refreshSecret) {
      throw new Error(
        'JWT_REFRESH_SECRET is not configured for RefreshToken Strategy',
      );
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: refreshSecret,
    });
  }

  async validate(payload: JwtPayload) {
    if (!payload.sub || !payload.email) {
      throw new UnauthorizedException('Invalid refresh token payload');
    }

    try {
      // Do NOT validate JWT exp here - handle expiration in the refresh endpoint
      // This allows for configurable token lifetimes beyond JWT exp

      return {
        id: payload.sub,
        email: payload.email,
        roles: Array.isArray(payload.roles) ? payload.roles : ['user'],
        sessionId: payload.sessionId, // Session ID from token
        tokenFamily: payload.tokenFamily, // Token family for rotation
        rememberMe: payload.rememberMe || false,
      };
    } catch (error) {
      throw new UnauthorizedException(
        'Invalid refresh token: ' + error.message,
      );
    }
  }
}
