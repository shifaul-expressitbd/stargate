import { Logger } from '@nestjs/common';

export class ValidationUtils {
  private static readonly logger = new Logger(ValidationUtils.name);

  /**
   * Validate email format
   */
  static isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validate password strength
   */
  static validatePasswordStrength(password: string): {
    isValid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Sanitize string input
   */
  static sanitizeString(input: string): string {
    if (!input) return '';

    return input
      .trim()
      .replace(/[<>\"'&]/g, '') // Remove potentially dangerous characters
      .substring(0, 1000); // Limit length
  }

  /**
   * Validate TOTP code format
   */
  static validateTOTPCode(code: string): boolean {
    const cleanCode = code
      .replace(/[^\d]/g, '')
      .substring(0, 6)
      .padStart(6, '0');
    return /^\d{6}$/.test(cleanCode);
  }

  /**
   * Validate backup code format
   */
  static validateBackupCode(code: string): boolean {
    return /^[A-Z0-9]{8}$/.test(code.toUpperCase());
  }

  /**
   * Check if IP address is valid
   */
  static isValidIP(ip: string): boolean {
    // IPv4 regex
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
      return ip.split('.').every((part) => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255;
      });
    }

    // IPv6 regex (basic check)
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv6Regex.test(ip);
  }

  /**
   * Check if string is empty or whitespace
   */
  static isEmpty(str: string): boolean {
    return !str || str.trim().length === 0;
  }

  /**
   * Validate URL format
   */
  static isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Validate UUID format
   */
  static isValidUUID(uuid: string): boolean {
    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  }

  /**
   * Sanitize user input for logging
   */
  static sanitizeForLogging(input: string): string {
    if (!input) return '';

    // Remove sensitive information
    return input
      .replace(/password["\s]*:[\s"]*[^"\\,]*/gi, 'password: [REDACTED]')
      .replace(/token["\s]*:[\s"]*[^"\\,]*/gi, 'token: [REDACTED]')
      .replace(/secret["\s]*:[\s"]*[^"\\,]*/gi, 'secret: [REDACTED]')
      .substring(0, 500); // Limit log length
  }
}
