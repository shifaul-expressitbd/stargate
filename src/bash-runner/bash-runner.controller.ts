import {
  Body,
  Controller,
  Get,
  Headers,
  Logger,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { BashRunnerService } from './bash-runner.service';

interface RunCommandDto {
  commandId: string;
  args?: string[];
  timeout?: number;
}

interface ApiKeyDto {
  apiKey: string;
}

@Controller('api/bash-runner')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT-auth')
export class BashRunnerController {
  private readonly logger = new Logger(BashRunnerController.name);

  constructor(private readonly bashRunnerService: BashRunnerService) {}

  @Post('command')
  async runCommand(
    @Body() dto: RunCommandDto,
    @Headers('x-api-key') apiKey?: string,
    @Query('apiKey') queryApiKey?: string,
  ) {
    try {
      const { commandId, args, timeout } = dto;

      if (!commandId) {
        return {
          status: 400,
          error: 'commandId is required',
        };
      }

      // Use API key from header or query parameter
      const key = apiKey || queryApiKey;
      if (!key) {
        return {
          status: 401,
          error: 'API key required',
        };
      }

      this.logger.log(
        `REST command received: ${commandId} with API key: ${key}`,
      );

      // Create a unique command ID for tracking
      const uniqueCommandId = `${commandId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      try {
        // Execute the command
        await this.bashRunnerService.sendCommand(uniqueCommandId, {
          commandId: commandId,
          action: commandId,
          containerId: args?.[0],
          name: args?.[1],
          user: 'rest-user', // In a real app, you'd get this from JWT token
          subdomain: args?.[2],
          config: args?.[3],
          lines: args?.[4] ? parseInt(args[4]) : undefined,
        });

        // For REST API, we return immediate success since the actual result
        // will be handled asynchronously. In a production app, you might want
        // to implement polling or server-sent events for real-time updates.
        return {
          status: 200,
          message: 'Command sent successfully',
          commandId: uniqueCommandId,
          note: 'Use Socket.IO connection for real-time output streaming',
        };
      } catch (error: any) {
        return {
          status: 500,
          error: error.message || 'Command execution failed',
          commandId: uniqueCommandId,
        };
      }
    } catch (error: any) {
      this.logger.error('Error in REST command execution:', error);
      return {
        status: 500,
        error: error.message || 'Internal server error',
      };
    }
  }

  @Get('health')
  async getHealth() {
    try {
      const health = await this.bashRunnerService.getHealthInfo();
      return {
        status: 200,
        data: health,
      };
    } catch (error: any) {
      return {
        status: 500,
        error: error.message || 'Failed to get health info',
      };
    }
  }

  @Post('ping')
  async ping() {
    return {
      status: 200,
      message: 'pong',
      timestamp: new Date().toISOString(),
    };
  }
}
