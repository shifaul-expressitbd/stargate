import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { authenticator, totp } from 'otplib';
import QRCode from 'qrcode-generator';
import { PrismaService } from '../../database/prisma/prisma.service';
import { UsersService } from '../../users/users.service';
import { LoggerService } from '../../utils/logger/logger.service';

export interface TwoFactorGenerateResponse {
  secret: string;
  qrCodeUrl: string;
  manualEntryKey: string;
  otpAuthUrl: string;
}

export interface TwoFactorEnableResponse {
  backupCodes?: string[];
}

export interface TwoFactorStatusResponse {
  isEnabled: boolean;
  hasSecret: boolean;
}

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name);
  private readonly appName = 'StarGate Platform';

  private readonly totpOptions = {
    window: 3,
    step: 30,
  };

  private readonly enhancedTotpConfig = {
    algorithm: 'SHA1' as const,
    digits: 6,
    step: 30,
    window: 3,
  };

  constructor(
    private readonly usersService: UsersService,
    private readonly prisma: PrismaService,
    private readonly loggerService: LoggerService,
  ) {
    this.initializeTOTP();
  }

  private initializeTOTP() {
    authenticator.options = {
      ...this.totpOptions,
    };

    totp.options = {
      ...this.totpOptions,
    };
  }

  async generateTwoFactorSecret(
    userId: string,
  ): Promise<TwoFactorGenerateResponse> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) throw new BadRequestException('User not found');

      this.logger.log(`Generating 2FA secret for user: ${user.email}`);

      const secret = authenticator.generateSecret();
      const serviceName = this.appName.replace(/\s+/g, '');
      const issuer = this.appName;
      const accountName = `${user.email.split('@')[0]}@${user.email.split('@')[1]}`;

      // Enhanced OTP Auth URL generation with multiple improvements
      const otpAuthUrl = this.generateEnhancedOtpAuthUrl(
        secret,
        issuer,
        accountName,
        {
          type: 'TOTP',
          algorithm: this.enhancedTotpConfig.algorithm,
          digits: this.enhancedTotpConfig.digits,
          period: this.enhancedTotpConfig.step,
          // Add image parameter if user has avatar
          image: user.avatar ? encodeURIComponent(user.avatar) : undefined,
        },
      );

      // Handle QR code generation with proper error checking
      try {
        const qr = QRCode(0, 'L');
        qr.addData(otpAuthUrl);
        qr.make();
        const qrCodeUrl = qr.createDataURL(4);

        await this.usersService.update(userId, {
          twoFactorSecret: secret,
        });

        const result = {
          secret,
          qrCodeUrl,
          manualEntryKey: secret,
          otpAuthUrl,
        };

        this.logger.log(
          `✅ 2FA secret generated successfully for user: ${user.email}`,
        );
        return result;
      } catch (qrError) {
        this.logger.error(
          `Failed to generate QR code for user ${userId}:`,
          qrError.message,
        );
        throw new BadRequestException('Failed to generate QR code');
      }
    } catch (error) {
      if (error instanceof BadRequestException) throw error;
      this.logger.error(
        `Failed to generate 2FA secret for user ${userId}:`,
        error.message,
      );
      throw new BadRequestException('Failed to generate 2FA secret');
    }
  }

  async verifyTwoFactorCode(
    userId: string,
    totpCode: string,
  ): Promise<boolean> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user || !user.twoFactorSecret) {
        this.logger.warn(`No 2FA secret found for user: ${userId}`);
        return false;
      }

      const cleanCode = totpCode.replace(/\s/g, '').padStart(6, '0');

      if (!/^\d{6}$/.test(cleanCode)) {
        this.logger.warn(`Invalid code format: ${cleanCode}`);
        return false;
      }

      const secret = user.twoFactorSecret;
      const currentExpected = totp.generate(secret);
      this.logger.debug(`Current expected code: ${currentExpected}`);
      this.logger.debug(`Received code: ${cleanCode}`);

      // Manual window check with logging
      const currentTime = Math.floor(Date.now() / 1000);
      const timeStep = 30;
      const windowSize = 3;
      const isValid = totp.check(cleanCode, secret);

      if (isValid) {
        this.logger.log(`✅ 2FA code verified for user: ${user.email}`);
        return true;
      }

      // Log what codes would be valid in the current window
      this.logger.debug(`Checked time window: ±${windowSize * timeStep}s`);
      for (let i = -windowSize; i <= windowSize; i++) {
        const testTime = currentTime + i * timeStep;
        const testCounter = Math.floor(testTime / timeStep);
        const testCode = this.generateTOTPCode(secret, testCounter);
        this.logger.debug(
          `Expected code at offset ${i * timeStep}s: ${testCode} (time: ${new Date(testTime * 1000).toISOString()})`,
        );
        if (testCode === cleanCode) {
          this.logger.log(
            `✅ 2FA code verified for user: ${user.email} at offset ${i * 30}s`,
          );
          return true;
        }
      }

      const serverTime = new Date().toISOString();
      const serverTimestamp = Math.floor(Date.now() / 1000);

      this.logger.warn(`❌ No matching code found for user: ${user.email}`);
      this.logger.debug(`Received code: ${cleanCode}`);
      this.logger.debug(`Server time: ${serverTime} (${serverTimestamp})`);
      this.logger.debug(
        `Checked time window: ±${this.totpOptions.window * this.totpOptions.step}s`,
      );

      // Provide debugging info in the warning
      this.logger.warn(`⏰ Time sync debugging for user ${userId}:`);
      this.logger.warn(
        `📱 Ensure authenticator app is time-synced with NTP server`,
      );
      this.logger.warn(`🌍 Client timezone differences may cause this issue`);
      this.logger.warn(`⚙️ Check device time vs ${serverTime}`);

      return false;
    } catch (error) {
      this.logger.error(
        `Failed to verify 2FA code for user ${userId}:`,
        error.message,
      );
      return false;
    }
  }

  async enableTwoFactor(
    userId: string,
    totpCode: string,
  ): Promise<TwoFactorEnableResponse | void> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new BadRequestException('User not found');

    // If 2FA is already enabled, disable it first to allow re-enabling with new secret
    if (user.isTwoFactorEnabled) {
      this.logger.log(
        `🔄 Disabling existing 2FA for user: ${user.email} to allow re-enabling`,
      );
      await this.usersService.update(userId, {
        isTwoFactorEnabled: false,
        backupCodes: { set: [] }, // Clear existing backup codes
        // Keep the twoFactorSecret as it might be newly generated
      });
      this.logger.log(
        `✅ Existing 2FA disabled for re-enabling: ${user.email}`,
      );
    }

    if (!user.twoFactorSecret) {
      throw new BadRequestException(
        'No 2FA secret generated. Run /2fa/generate first.',
      );
    }

    const isValid = await this.verifyTwoFactorCode(userId, totpCode);
    if (!isValid) {
      const currentCode = totp.generate(user.twoFactorSecret);
      const timeInfo = `Current server time: ${new Date().toISOString()}`;

      this.logger.warn(
        `2FA enable failed for ${user.email}: Expected=${currentCode}, Received=${totpCode}`,
      );
      this.logger.warn(`Time sync issue? ${timeInfo}`);

      throw new UnauthorizedException(
        `Invalid verification code. Server expected: ${currentCode} (${timeInfo}). ` +
          'Please check your device time synchronization.',
      );
    }

    // Enable 2FA without generating backup codes
    await this.usersService.update(userId, {
      isTwoFactorEnabled: true,
    });

    this.logger.log(`✅ 2FA enabled for user: ${user.email}`);
  }

  async disableTwoFactor(userId: string, totpCode: string): Promise<void> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new BadRequestException('User not found');
    if (!user.isTwoFactorEnabled)
      throw new BadRequestException('2FA is not enabled');
    if (!user.twoFactorSecret) {
      throw new BadRequestException('2FA secret not found');
    }

    this.logger.log(`🔄 Disabling 2FA for user: ${user.email}`);
    this.logger.log(
      `📋 Current state - enabled: ${user.isTwoFactorEnabled}, secret: ${!!user.twoFactorSecret}, backupCodes: ${user.backupCodes?.length || 0}`,
    );

    const isValid = await this.verifyTwoFactorCode(userId, totpCode);
    if (!isValid) {
      const expectedCode = totp.generate(user.twoFactorSecret);
      this.logger.debug(
        `Expected code during disable: ${expectedCode}, Received: ${totpCode}`,
      );
      throw new UnauthorizedException(
        `Invalid verification code. Did you mean ${expectedCode}? Check device time.`,
      );
    }

    await this.usersService.update(userId, {
      isTwoFactorEnabled: false,
      twoFactorSecret: null,
      backupCodes: { set: [] },
    });

    this.logger.log(
      `🗑️ 2FA cleanup completed: secret cleared, backup codes emptied`,
    );
    this.logger.log(`✅ 2FA disabled for user: ${user.email}`);

    // Double-check the cleanup was successful
    const updatedUser = await this.usersService.findById(userId);
    if (updatedUser?.twoFactorSecret || updatedUser?.backupCodes?.length) {
      this.logger.warn(`⚠️ 2FA cleanup incomplete for user ${user.email}`);
    } else {
      this.logger.log(`🛡️ 2FA fully disabled for user: ${user.email}`);
    }
  }

  async regenerateBackupCodes(
    userId: string,
    dto: any,
  ): Promise<TwoFactorEnableResponse> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) {
        throw new BadRequestException('User not found');
      }

      if (!user.isTwoFactorEnabled) {
        throw new BadRequestException(
          'Two-factor authentication is not enabled for this account',
        );
      }

      if (!user.twoFactorSecret) {
        throw new BadRequestException('2FA secret not found');
      }

      // Verify the provided TOTP code
      const isValid = await this.verifyTwoFactorCode(userId, dto.totpCode);
      if (!isValid) {
        const currentCode = totp.generate(user.twoFactorSecret);
        this.logger.warn(
          `2FA regeneration failed for ${user.email}: Expected=${currentCode}, Received=${dto.totpCode}`,
        );
        throw new UnauthorizedException(
          `Invalid verification code. Please verify your device time and try again.`,
        );
      }

      // Generate new backup codes
      const newBackupCodes = Array.from({ length: 10 }, () =>
        Math.random().toString(36).slice(2, 10).toUpperCase(),
      );

      // Hash the new backup codes
      const hashedBackupCodes = await Promise.all(
        newBackupCodes.map((code) => this.hashBackupCode(code)),
      );

      // Update user with new hashed backup codes
      await this.usersService.update(userId, {
        backupCodes: {
          set: hashedBackupCodes,
        },
      });

      this.logger.log(
        `🔄 Regenerated ${newBackupCodes.length} backup codes for user: ${user.email}`,
      );

      return {
        backupCodes: newBackupCodes,
      };
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof UnauthorizedException
      ) {
        throw error;
      }

      this.logger.error(
        `Failed to regenerate backup codes for user ${userId}:`,
        error.message,
      );
      throw new InternalServerErrorException(
        'Failed to regenerate backup codes',
      );
    }
  }

  async getTwoFactorStatus(userId: string): Promise<TwoFactorStatusResponse> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new BadRequestException('User not found');
    return {
      isEnabled: user.isTwoFactorEnabled,
      hasSecret: !!user.twoFactorSecret,
    };
  }

  async generateBackupCodes(
    userId: string,
    dto: any,
  ): Promise<TwoFactorEnableResponse> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new BadRequestException('User not found');
    if (!user.isTwoFactorEnabled)
      throw new BadRequestException('2FA not enabled for this account');
    if (!user.twoFactorSecret)
      throw new BadRequestException('2FA secret not found');

    // Verify the TOTP code
    const isValid = await this.verifyTwoFactorCode(userId, dto.totpCode);
    if (!isValid) {
      throw new UnauthorizedException('Invalid verification code');
    }

    // Generate new backup codes
    const newBackupCodes = Array.from({ length: 10 }, () =>
      Math.random().toString(36).slice(2, 10).toUpperCase(),
    );

    // Hash the new backup codes
    const hashedBackupCodes = await Promise.all(
      newBackupCodes.map((code) => this.hashBackupCode(code)),
    );

    // Update user with new hashed backup codes
    await this.usersService.update(userId, {
      backupCodes: {
        set: hashedBackupCodes,
      },
    });

    this.logger.log(
      `✅ Generated ${newBackupCodes.length} backup codes for user: ${user.email}`,
    );

    return {
      backupCodes: newBackupCodes,
    };
  }

  private async hashBackupCode(code: string): Promise<string> {
    const bcrypt = require('bcryptjs');
    return bcrypt.hash(code, 12);
  }

  private generateTOTPCode(secret: string, timeCounter: number): string {
    try {
      const crypto = require('crypto');
      const buffer = Buffer.allocUnsafe(8);
      buffer.writeUInt32BE(0, 0);
      buffer.writeUInt32BE(timeCounter, 4);

      const key = this.base32Decode(secret);
      const hmac = crypto.createHmac('sha1', key);
      hmac.update(buffer);
      const digest = hmac.digest();

      const offset = digest[digest.length - 1] & 0x0f;

      const code =
        ((digest[offset] & 0x7f) << 24) |
        ((digest[offset + 1] & 0xff) << 16) |
        ((digest[offset + 2] & 0xff) << 8) |
        (digest[offset + 3] & 0xff);

      const finalCode = (code % 1000000).toString().padStart(6, '0');
      this.logger.debug(`TOTP Code: ${finalCode} (time: ${timeCounter})`);

      return finalCode;
    } catch (error) {
      return totp.generate(secret);
    }
  }

  private base32Decode(encoded: string): Buffer {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0;
    let value = 0;
    let index = 0;
    const output = new Uint8Array((encoded.length * 5) >> 3);

    for (const char of encoded.toUpperCase()) {
      const idx = alphabet.indexOf(char);
      if (idx === -1) continue;

      value = (value << 5) | idx;
      bits += 5;

      if (bits >= 8) {
        output[index++] = (value >>> (bits - 8)) & 255;
        bits -= 8;
      }
    }

    return Buffer.from(output.slice(0, index));
  }

  private generateEnhancedOtpAuthUrl(
    secret: string,
    issuer: string,
    accountName: string,
    options: {
      type?: 'TOTP' | 'HOTP';
      algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
      digits?: number;
      period?: number;
      counter?: number;
      image?: string;
    } = {},
  ): string {
    const {
      type = 'TOTP',
      algorithm = this.enhancedTotpConfig.algorithm,
      digits = this.enhancedTotpConfig.digits,
      period = this.enhancedTotpConfig.step,
      counter = 0,
      image,
    } = options;

    // Build the label with proper encoding
    const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;

    // Build query parameters
    const params = new URLSearchParams();
    params.append('secret', secret);
    params.append('issuer', issuer);
    params.append('algorithm', algorithm);
    params.append('digits', digits.toString());

    // Add type-specific parameters
    if (type === 'TOTP') {
      params.append('period', period.toString());
    } else if (type === 'HOTP') {
      params.append('counter', counter.toString());
    }

    // Add optional parameters
    if (image) {
      params.append('image', encodeURIComponent(image));
    }

    // Build the full URL
    const baseUrl = `otpauth://${type.toLowerCase()}/${label}`;
    const queryString = params.toString();

    return `${baseUrl}?${queryString}`;
  }
}
