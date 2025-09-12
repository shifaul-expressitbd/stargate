import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from './database/prisma/prisma.service';

@Injectable()
export class AppService {
  constructor(
    private configService: ConfigService,
    private prismaService: PrismaService,
  ) { }

  getHello(): string {
    return 'StarGate NestJS API is running! 🚀';
  }

  private async checkDatabaseHealth() {
    const startTime = Date.now();
    try {
      // Simple query to test database responsiveness
      await this.prismaService.$queryRaw`SELECT 1`;

      const duration = Date.now() - startTime;
      return {
        status: 'UP' as const,
        duration,
        lastChecked: new Date(),
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      return {
        status: 'DOWN' as const,
        duration,
        error: error instanceof Error ? error.message : String(error),
        lastChecked: new Date(),
      };
    }
  }

  private async checkApiHealth() {
    const startTime = Date.now();
    try {
      // Simple API check - just verify the service is running
      const duration = Date.now() - startTime;
      return {
        status: 'UP' as const,
        duration,
        lastChecked: new Date(),
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      return {
        status: 'DOWN' as const,
        duration,
        error: error instanceof Error ? error.message : String(error),
        lastChecked: new Date(),
      };
    }
  }

  async getHealth() {
    const [apiHealth, databaseHealth] = await Promise.all([
      this.checkApiHealth(),
      this.checkDatabaseHealth(),
    ]);

    const overallStatus = apiHealth.status === 'UP' && databaseHealth.status === 'UP' ? 'UP' : 'DOWN';

    return {
      status: overallStatus,
      timestamp: new Date(),
      uptime: process.uptime(),
      environment: this.configService.get<string>('NODE_ENV', 'development'),
      version: this.configService.get<string>('npm_package_version', '1.0.0'),
      components: {
        api: apiHealth,
        database: databaseHealth,
      },
    };
  }
}
