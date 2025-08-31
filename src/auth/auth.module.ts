// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { MailModule } from '../mail/mail.module';
import { UsersModule } from '../users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { FacebookStrategy } from './strategies/facebook.strategy';
import { GithubStrategy } from './strategies/github.strategy';
import { GoogleGtmStrategy } from './strategies/google-gtm.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        // Try different ways to get the JWT secret
        const secret =
          configService.get<string>('JWT_SECRET') ||
          configService.get<string>('jwt.secret') ||
          process.env.JWT_SECRET;

        const expiresIn =
          configService.get<string>('JWT_EXPIRES_IN') ||
          configService.get<string>('jwt.expiresIn') ||
          process.env.JWT_EXPIRES_IN ||
          '15m';

        console.log('JWT Config Debug:', {
          secret: secret ? `${secret.substring(0, 10)}...` : 'NOT FOUND',
          expiresIn,
          envVars: {
            JWT_SECRET: process.env.JWT_SECRET ? 'SET' : 'NOT SET',
            NODE_ENV: process.env.NODE_ENV,
          },
        });

        if (!secret) {
          throw new Error(
            'JWT_SECRET is not configured. Please check your .env file and ensure JWT_SECRET is set.',
          );
        }

        if (secret.length < 32) {
          throw new Error('JWT_SECRET must be at least 32 characters long');
        }

        return {
          secret,
          signOptions: {
            expiresIn,
            issuer: 'stargate-api',
            audience: 'stargate-client',
          },
          verifyOptions: {
            issuer: 'stargate-api',
            audience: 'stargate-client',
          },
        };
      },
      inject: [ConfigService],
    }),
    UsersModule,
    MailModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    LocalStrategy,
    JwtStrategy,
    GoogleStrategy,
    GoogleGtmStrategy,
    FacebookStrategy,
    GithubStrategy,
  ],
  exports: [AuthService, JwtModule, PassportModule],
})
export class AuthModule {}
