// src/sgtm-container/sgtm-container.controller.ts
import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { BashRunnerService } from '../bash-runner/bash-runner.service';
import { User } from '../common/decorators/user.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CreateSgtmContainerDto } from './dto/create-sgtm-container.dto';
import { RunSgtmContainerDto } from './dto/run-sgtm-container.dto';
import { SgtmContainerService } from './sgtm-container.service';

@ApiTags('sgtm-containers')
@Controller('sgtm-containers')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT-auth')
export class SgtmContainerController {
  constructor(
    private readonly sgtmContainerService: SgtmContainerService,
    private readonly bashRunnerService: BashRunnerService,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Create a new GTM container' })
  @ApiResponse({
    status: 201,
    description: 'Container created and started successfully',
    schema: {
      example: {
        success: true,
        message: 'Container creation completed successfully',
        data: {
          commandId: 'create-cmeqncqjh0001jxf3a2sibmvy-1756097908843',
          exitCode: 0,
          executionTime: 1756097908843,
          containerId: 'cmeqncqjh0001jxf3a2sibmvy',
          container: {
            id: 'cmeqncqjh0001jxf3a2sibmvy',
            name: 'gtm-unified',
            fullName: 'sgtm-cmepifo1-d58058f9',
            status: 'RUNNING',
            subdomain: 'tags.bikobazaar.xyz',
            createdAt: '2025-08-25T04:58:28.819Z',
            updatedAt: '2025-08-25T04:58:35.091Z',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 202,
    description: 'Container created but startup deferred',
    schema: {
      example: {
        success: true,
        message: 'Container created successfully (runner service unavailable)',
        data: {
          container: {
            id: 'cmeqncqjh0001jxf3a2sibmvy',
            name: 'gtm-unified',
            fullName: 'sgtm-cmepifo1-d58058f9',
            status: 'CREATED',
            subdomain: 'tags.bikobazaar.xyz',
            createdAt: '2025-08-25T04:58:28.819Z',
            updatedAt: '2025-08-25T04:58:28.819Z',
          },
          warning: 'Bash runner service unavailable - container not started',
        },
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Bad request' })
  async create(
    @User('id') userId: string,
    @Body() createSgtmContainerDto: CreateSgtmContainerDto,
  ) {
    const result = await this.sgtmContainerService.create(
      userId,
      createSgtmContainerDto,
    );

    // Set appropriate HTTP status based on the result
    if (result.success && result.data && (result.data as any).warning) {
      // Container created but with warnings (e.g., runner unavailable)
      return result;
    } else if (result.success) {
      // Container created and started successfully
      return result;
    } else {
      // Container creation failed
      throw new BadRequestException(result);
    }
  }

  @Get()
  @ApiOperation({ summary: 'Get all GTM containers for the current user' })
  @ApiResponse({
    status: 200,
    description: 'Containers retrieved successfully',
  })
  async findAll(@User('id') userId: string) {
    return this.sgtmContainerService.findAllByUser(userId);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a specific GTM container' })
  @ApiResponse({ status: 200, description: 'Container retrieved successfully' })
  @ApiResponse({ status: 404, description: 'Container not found' })
  async findOne(@Param('id') id: string, @User('id') userId: string) {
    return this.sgtmContainerService.findByIdAndUser(id, userId);
  }

  @Post(':id/run')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Run a GTM container' })
  @ApiResponse({ status: 200, description: 'Container started successfully' })
  @ApiResponse({
    status: 400,
    description: 'Container is already running or invalid request',
  })
  @ApiResponse({ status: 404, description: 'Container not found' })
  async run(
    @Param('id') id: string,
    @User('id') userId: string,
    @Body() runDto: RunSgtmContainerDto,
  ) {
    return this.sgtmContainerService.run(id, userId, runDto);
  }

  @Post(':id/stop')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Stop a running GTM container' })
  @ApiResponse({ status: 200, description: 'Container stopped successfully' })
  @ApiResponse({
    status: 400,
    description: 'Container is not running or invalid request',
  })
  @ApiResponse({ status: 404, description: 'Container not found' })
  async stop(@Param('id') id: string, @User('id') userId: string) {
    return this.sgtmContainerService.stop(id, userId);
  }

  @Get(':id/logs')
  @ApiOperation({ summary: 'Get logs for a GTM container' })
  @ApiResponse({ status: 200, description: 'Logs retrieved successfully' })
  @ApiResponse({ status: 400, description: 'Failed to retrieve logs' })
  @ApiResponse({ status: 404, description: 'Container not found' })
  async getLogs(
    @Param('id') id: string,
    @User('id') userId: string,
    @Query('lines') lines?: number,
  ) {
    return this.sgtmContainerService.getLogs(id, userId, lines || 100);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Delete a GTM container' })
  @ApiResponse({ status: 200, description: 'Container deleted successfully' })
  @ApiResponse({ status: 400, description: 'Cannot delete running container' })
  @ApiResponse({ status: 404, description: 'Container not found' })
  async remove(@Param('id') id: string, @User('id') userId: string) {
    return this.sgtmContainerService.delete(id, userId);
  }

  @Get('health/bash-runner')
  @ApiOperation({ summary: 'Check bash runner service health' })
  @ApiResponse({ status: 200, description: 'Service health status retrieved' })
  async getBashRunnerHealth() {
    const isConnected = this.bashRunnerService.isConnected();
    const isAvailable = this.bashRunnerService.isAvailable();
    const connectionStatus = this.bashRunnerService.getConnectionStatus();

    return {
      status: isConnected
        ? 'healthy'
        : isAvailable
          ? 'connecting'
          : 'unavailable',
      isConnected,
      isAvailable,
      connectionStatus,
      timestamp: new Date().toISOString(),
    };
  }
}
