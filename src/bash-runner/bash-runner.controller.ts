import { Controller, Get, Logger } from '@nestjs/common';
import { BashRunnerService } from './bash-runner.service';

@Controller('api/bash-runner')
export class BashRunnerController {
  private readonly logger = new Logger(BashRunnerController.name);

  constructor(private readonly bashRunnerService: BashRunnerService) {}

  @Get('health')
  async getHealth() {
    try {
      const healthInfo = await this.bashRunnerService.getHealthInfo();
      return {
        success: true,
        data: healthInfo,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      this.logger.error('Health check failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };
    }
  }

  @Get('status')
  getStatus() {
    return {
      success: true,
      data: {
        isConnected: this.bashRunnerService.isConnected(),
        isAvailable: this.bashRunnerService.isAvailable(),
        connectionStatus: this.bashRunnerService.getConnectionStatus(),
      },
      timestamp: new Date().toISOString(),
    };
  }

  @Get('retry')
  async retryConnection() {
    try {
      const success = await this.bashRunnerService.retryConnection();
      return {
        success: true,
        data: {
          connectionAttempted: true,
          connectionSuccessful: success,
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      this.logger.error('Retry connection failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };
    }
  }
}