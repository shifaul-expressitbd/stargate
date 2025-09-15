import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(PrismaService.name);

  constructor(private configService: ConfigService) {
    super({
      log: [
        { emit: 'event', level: 'query' },
        { emit: 'event', level: 'error' },
        { emit: 'event', level: 'info' },
        { emit: 'event', level: 'warn' },
      ],
      errorFormat: 'colorless',
    });
  }

  async onModuleInit() {
    this.logger.log('Connecting to database...');

    // Log queries when debug level is enabled
    const logLevel = this.configService
      .get<string>('LOG_LEVEL', 'info')
      .toLowerCase();
    if (logLevel === 'debug') {
      this.$on('query' as never, (e: any) => {
        this.logger.debug(
          `Query: ${e.query} - Params: ${e.params} - Duration: ${e.duration}ms`,
        );
      });
    }

    this.$on('error' as never, (e: any) => {
      this.logger.error('Database error:', e);
    });

    await this.$connect();
    this.logger.log('Database connected successfully');
  }

  async onModuleDestroy() {
    this.logger.log('Disconnecting from database...');
    await this.$disconnect();
    this.logger.log('Database disconnected');
  }

  async cleanDatabase() {
    const cleaningEnabled = this.configService.get<string>(
      'DATABASE_CLEANING_ENABLED',
      'false',
    );
    if (cleaningEnabled !== 'true') {
      throw new Error('Database cleaning is disabled');
    }

    this.logger.warn('Cleaning database...');

    // Get all model names and delete in correct order
    const modelNames = Object.keys(this)
      .filter(
        (key) =>
          key[0] !== '_' && typeof this[key as keyof typeof this] === 'object',
      )
      .filter(
        (key) =>
          key !== '$on' &&
          key !== '$connect' &&
          key !== '$disconnect' &&
          key !== '$use' &&
          key !== '$transaction' &&
          key !== '$extends',
      );

    for (const modelName of modelNames) {
      try {
        const model = this[modelName as keyof typeof this] as any;
        if (model && typeof model.deleteMany === 'function') {
          await model.deleteMany();
          this.logger.debug(`Cleaned ${modelName} table`);
        }
      } catch (error) {
        this.logger.warn(
          `Could not clean ${modelName} table:`,
          error instanceof Error ? error.message : String(error),
        );
      }
    }

    this.logger.log('Database cleaned successfully');
  }

  async enableShutdownHooks(app: any) {
    this.$on('beforeExit' as never, async () => {
      await app.close();
    });
  }
}
