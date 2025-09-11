import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Cron, CronExpression } from '@nestjs/schedule';
import { randomBytes } from 'crypto';
import { LoggerService } from '../utils/logger/logger.service';

export interface SecretRotationEvent {
  secretName: string;
  oldValue: string;
  newValue: string;
  timestamp: Date;
  rotationType: 'scheduled' | 'manual';
  userId?: string;
}

export interface SecretRotationOptions {
  enabled: boolean;
  intervalHours: number;
  gracePeriodMinutes: number;
  supportedSecrets: string[];
}

@Injectable()
export class SecretRotationService {
  private readonly logger = new Logger(SecretRotationService.name);
  private readonly options: SecretRotationOptions;
  private rotationHistory: SecretRotationEvent[] = [];
  private readonly maxHistorySize = 100;

  constructor(
    private configService: ConfigService,
    private loggerService: LoggerService,
    private eventEmitter: EventEmitter2,
  ) {
    this.options = {
      enabled:
        this.configService.get<string>('SECRET_ROTATION_ENABLED', 'false') ===
        'true',
      intervalHours: this.configService.get<number>(
        'SECRET_ROTATION_INTERVAL_HOURS',
        168,
      ),
      gracePeriodMinutes: this.configService.get<number>(
        'SECRET_ROTATION_GRACE_PERIOD_MINUTES',
        60,
      ),
      supportedSecrets: [
        'JWT_SECRET',
        'JWT_REFRESH_SECRET',
        'BASH_RUNNER_API_KEY',
        'BASH_RUNNER_API_KEY_INDIA',
        'BASH_RUNNER_API_KEY_US_EAST',
        'BASH_RUNNER_API_KEY_US_WEST',
        'BASH_RUNNER_API_KEY_EUROPE',
        'GOOGLE_CLIENT_SECRET',
        'GOOGLE_GTM_CLIENT_SECRET',
        'FACEBOOK_APP_SECRET',
        'GITHUB_CLIENT_SECRET',
      ],
    };

    if (this.options.enabled) {
      this.logger.log(
        `🔄 Secret rotation enabled with ${this.options.intervalHours}h interval`,
      );
    } else {
      this.logger.log('🔄 Secret rotation is disabled');
    }
  }

  /**
   * Generate a cryptographically secure random secret
   */
  private generateSecureSecret(length: number = 64): string {
    return randomBytes(length).toString('hex');
  }

  /**
   * Rotate a specific secret
   */
  async rotateSecret(secretName: string, userId?: string): Promise<boolean> {
    if (!this.options.enabled) {
      this.logger.warn('Secret rotation is disabled');
      return false;
    }

    if (!this.options.supportedSecrets.includes(secretName)) {
      this.logger.error(`Unsupported secret: ${secretName}`);
      return false;
    }

    try {
      const oldValue = this.configService.get<string>(secretName);
      if (!oldValue) {
        this.logger.warn(`Secret ${secretName} not found, skipping rotation`);
        return false;
      }

      // Generate new secret
      const newValue = this.generateSecureSecret();

      // Log rotation event
      const rotationEvent: SecretRotationEvent = {
        secretName,
        oldValue,
        newValue,
        timestamp: new Date(),
        rotationType: userId ? 'manual' : 'scheduled',
        userId,
      };

      this.addToHistory(rotationEvent);

      // Emit event for other services to handle (e.g., cache invalidation)
      this.eventEmitter.emit('secret.rotated', rotationEvent);

      // Log audit event
      this.loggerService.audit('SECRET_ROTATION', userId, secretName, {
        rotationType: rotationEvent.rotationType,
        timestamp: rotationEvent.timestamp,
      });

      this.logger.log(`🔄 Successfully rotated secret: ${secretName}`);

      return true;
    } catch (error) {
      this.logger.error(
        `Failed to rotate secret ${secretName}:`,
        error.message,
      );
      return false;
    }
  }

  /**
   * Rotate all supported secrets
   */
  async rotateAllSecrets(userId?: string): Promise<{ [key: string]: boolean }> {
    const results: { [key: string]: boolean } = {};

    for (const secretName of this.options.supportedSecrets) {
      results[secretName] = await this.rotateSecret(secretName, userId);
    }

    return results;
  }

  /**
   * Scheduled rotation - runs every configured interval
   */
  @Cron(CronExpression.EVERY_HOUR)
  async scheduledRotation(): Promise<void> {
    if (!this.options.enabled) {
      return;
    }

    const now = new Date();
    const lastRotation = this.getLastRotationTime();

    if (
      !lastRotation ||
      now.getTime() - lastRotation.getTime() >=
        this.options.intervalHours * 60 * 60 * 1000
    ) {
      this.logger.log('🔄 Starting scheduled secret rotation');
      await this.rotateAllSecrets();
    }
  }

  /**
   * Get rotation history for a specific secret
   */
  getRotationHistory(secretName?: string): SecretRotationEvent[] {
    if (secretName) {
      return this.rotationHistory.filter(
        (event) => event.secretName === secretName,
      );
    }
    return [...this.rotationHistory];
  }

  /**
   * Get last rotation time for any secret
   */
  private getLastRotationTime(): Date | null {
    if (this.rotationHistory.length === 0) {
      return null;
    }
    return this.rotationHistory[this.rotationHistory.length - 1].timestamp;
  }

  /**
   * Add rotation event to history
   */
  private addToHistory(event: SecretRotationEvent): void {
    this.rotationHistory.push(event);

    // Maintain max history size
    if (this.rotationHistory.length > this.maxHistorySize) {
      this.rotationHistory = this.rotationHistory.slice(-this.maxHistorySize);
    }
  }

  /**
   * Check if a secret needs rotation based on grace period
   */
  isSecretExpired(secretName: string): boolean {
    const history = this.getRotationHistory(secretName);
    if (history.length === 0) {
      return false;
    }

    const lastRotation = history[history.length - 1].timestamp;
    const gracePeriodMs = this.options.gracePeriodMinutes * 60 * 1000;
    const expirationTime =
      lastRotation.getTime() +
      this.options.intervalHours * 60 * 60 * 1000 +
      gracePeriodMs;

    return Date.now() > expirationTime;
  }

  /**
   * Get rotation statistics
   */
  getRotationStats(): {
    totalRotations: number;
    enabled: boolean;
    intervalHours: number;
    gracePeriodMinutes: number;
    lastRotation?: Date;
    secretsRotated: string[];
  } {
    const secretsRotated = [
      ...new Set(this.rotationHistory.map((event) => event.secretName)),
    ];
    const lastRotation =
      this.rotationHistory.length > 0
        ? this.rotationHistory[this.rotationHistory.length - 1].timestamp
        : undefined;

    return {
      totalRotations: this.rotationHistory.length,
      enabled: this.options.enabled,
      intervalHours: this.options.intervalHours,
      gracePeriodMinutes: this.options.gracePeriodMinutes,
      lastRotation,
      secretsRotated,
    };
  }
}
