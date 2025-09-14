import { Logger } from '@nestjs/common';

export class TwoFactorUtils {
  private static readonly logger = new Logger(TwoFactorUtils.name);

  /**
   * Generate TOTP code
   */
  static generateTOTPCode(secret: string, timeCounter?: number): string {
    try {
      const crypto = require('crypto');
      const counter = timeCounter || Math.floor(Date.now() / 1000 / 30);
      const buffer = Buffer.allocUnsafe(8);
      buffer.writeUInt32BE(0, 0);
      buffer.writeUInt32BE(counter, 4);

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
      this.logger.debug(`TOTP Code: ${finalCode} (time: ${counter})`);

      return finalCode;
    } catch (error) {
      const { totp } = require('otplib');
      return totp.generate(secret);
    }
  }

  /**
   * Check TOTP code with window
   */
  static checkTOTPCode(code: string, secret: string): boolean {
    try {
      const { totp } = require('otplib');

      // Configure TOTP with our window settings
      totp.options = {
        window: 5, // Match our window size
        step: 30,
      };

      return totp.check(code, secret);
    } catch (error) {
      this.logger.warn('Failed to check TOTP code with otplib:', error.message);

      // Fallback to manual verification
      try {
        this.logger.debug('Attempting manual TOTP verification as fallback');
        const expectedCode = this.generateTOTPCode(secret);
        return expectedCode === code;
      } catch (fallbackError) {
        this.logger.error(
          'Fallback TOTP verification also failed:',
          fallbackError.message,
        );
        return false;
      }
    }
  }

  /**
   * Verify TOTP code with enhanced validation
   */
  static verifyTwoFactorCode(
    code: string,
    secret: string,
    windowSize = 5,
  ): boolean {
    try {
      // Robust code cleaning and validation
      const cleanCode = code
        .replace(/[^\d]/g, '') // Remove all non-digits
        .substring(0, 6) // Take first 6 digits
        .padStart(6, '0'); // Pad with leading zeros if needed

      this.logger.debug(
        `📝 Raw input: "${code}", Cleaned code: "${cleanCode}"`,
      );

      if (!/^\d{6}$/.test(cleanCode)) {
        this.logger.error(
          `❌ Invalid code format: "${cleanCode}" (must be 6 digits)`,
        );
        return false;
      }

      // Check current window
      if (this.checkTOTPCode(cleanCode, secret)) {
        this.logger.log(`✅ 2FA code verified in current window`);
        return true;
      }

      // Log what codes would be valid in the current window
      this.logger.debug(`⏱️ Checking time window: ±${windowSize * 30}s`);
      const currentTime = Math.floor(Date.now() / 1000);
      const timeStep = 30;

      for (let i = -windowSize; i <= windowSize; i++) {
        const testTime = currentTime + i * timeStep;
        const testCounter = Math.floor(testTime / timeStep);
        const testCode = this.generateTOTPCode(secret, testCounter);
        this.logger.debug(
          `Offset ${i * timeStep}s: ${testCode} (time: ${new Date(testTime * 1000).toISOString()})`,
        );
        if (testCode === cleanCode) {
          this.logger.log(`✅ 2FA code verified at offset ${i * 30}s`);
          return true;
        }
      }

      this.logger.error(`❌ No matching TOTP code found`);
      return false;
    } catch (error) {
      this.logger.error('Failed to verify 2FA code:', error.message);
      return false;
    }
  }

  /**
   * Base32 decode utility
   */
  private static base32Decode(encoded: string): Buffer {
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

  /**
   * Generate backup codes
   */
  static generateBackupCodes(count = 10): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
      codes.push(Math.random().toString(36).slice(2, 10).toUpperCase());
    }
    return codes;
  }

  /**
   * Validate backup code format
   */
  static validateBackupCode(code: string): boolean {
    return /^[A-Z0-9]{8}$/.test(code.toUpperCase());
  }
}
