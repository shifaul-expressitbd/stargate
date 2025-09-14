import { Logger } from '@nestjs/common';

export class SessionUtils {
  private static readonly logger = new Logger(SessionUtils.name);

  /**
   * Generate browser fingerprint hash from User-Agent and headers
   */
  static generateBrowserFingerprintHash(
    userAgent: string,
    additionalHeaders?: Record<string, string>,
  ): string {
    try {
      const crypto = require('crypto');

      // Create fingerprint from User-Agent and additional headers
      const fingerprintData = {
        userAgent: userAgent || '',
        acceptLanguage: additionalHeaders?.['accept-language'] || '',
        acceptEncoding: additionalHeaders?.['accept-encoding'] || '',
        accept: additionalHeaders?.['accept'] || '',
        dnt: additionalHeaders?.['dnt'] || '',
        secChUa: additionalHeaders?.['sec-ch-ua'] || '',
        secChUaMobile: additionalHeaders?.['sec-ch-ua-mobile'] || '',
        secChUaPlatform: additionalHeaders?.['sec-ch-ua-platform'] || '',
      };

      // Create a stable hash from the fingerprint data
      const fingerprintString = JSON.stringify(
        fingerprintData,
        Object.keys(fingerprintData).sort(),
      );
      return crypto
        .createHash('sha256')
        .update(fingerprintString)
        .digest('hex');
    } catch (error) {
      this.logger.warn(
        'Failed to generate browser fingerprint hash:',
        error.message,
      );
      return '';
    }
  }

  /**
   * Detect geolocation from IP address (simplified implementation)
   */
  static async detectGeolocation(ipAddress: string): Promise<{
    latitude?: number;
    longitude?: number;
    timezone?: string;
    location?: string;
  }> {
    try {
      // Skip geolocation for private/local IPs
      if (this.isPrivateIP(ipAddress)) {
        return { location: 'Local Network' };
      }

      // Simple timezone detection based on IP (this is very basic)
      const timezone = this.guessTimezoneFromIP(ipAddress);

      return {
        timezone,
        location: this.getLocationFromTimezone(timezone),
      };
    } catch (error) {
      this.logger.warn(
        `Failed to detect geolocation for IP ${ipAddress}:`,
        error.message,
      );
      return {};
    }
  }

  /**
   * Check if IP is private/local
   */
  static isPrivateIP(ip: string): boolean {
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^::1$/,
      /^fc00:/,
      /^fe80:/,
    ];
    return privateRanges.some((range) => range.test(ip));
  }

  /**
   * Guess timezone from IP (very basic implementation)
   */
  private static guessTimezoneFromIP(ip: string): string {
    // Default to UTC
    if (!ip || ip === 'unknown' || ip === '::1') {
      return 'UTC';
    }

    // For demonstration, we'll use a simple mapping
    return 'Asia/Dhaka'; // Default for this example
  }

  /**
   * Get location string from timezone
   */
  private static getLocationFromTimezone(timezone: string): string {
    const locationMap: Record<string, string> = {
      UTC: 'Unknown',
      'America/New_York': 'New York, US',
      'America/Los_Angeles': 'Los Angeles, US',
      'Europe/London': 'London, UK',
      'Europe/Paris': 'Paris, France',
      'Asia/Tokyo': 'Tokyo, Japan',
      'Asia/Shanghai': 'Shanghai, China',
      'Asia/Dhaka': 'Dhaka, Bangladesh',
      'Australia/Sydney': 'Sydney, Australia',
    };

    return locationMap[timezone] || timezone;
  }

  /**
   * Generate unique session ID
   */
  static generateSessionId(): string {
    return require('crypto').randomBytes(32).toString('hex');
  }

  /**
   * Generate unique token family for refresh token rotation
   */
  static generateTokenFamily(): string {
    return require('crypto').randomBytes(16).toString('hex');
  }
}
