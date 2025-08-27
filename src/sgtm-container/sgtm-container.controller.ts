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
import { ConfigService } from '@nestjs/config';
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

@ApiTags('sGTM-containers')
@Controller('sgtm-containers')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT-auth')
export class SgtmContainerController {
  constructor(
    private readonly sgtmContainerService: SgtmContainerService,
    private readonly bashRunnerService: BashRunnerService,
    private readonly configService: ConfigService,
  ) {}

  @Post()
  @ApiOperation({
    summary: 'Create a new GTM container',
    description:
      'Creates and starts a new GTM container using the docker-tagserver-run command. The container will be automatically configured with Nginx and SSL if available.',
  })
  @ApiResponse({
    status: 201,
    description: 'Container created and started successfully',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            message: {
              type: 'string',
              example: 'Container creation completed successfully',
            },
            data: {
              type: 'object',
              properties: {
                commandId: {
                  type: 'string',
                  example: 'create-cmeqncqjh0001jxf3a2sibmvy-1756097908843',
                },
                exitCode: { type: 'number', example: 0 },
                executionTime: { type: 'number', example: 1756097908843 },
                containerId: {
                  type: 'string',
                  example: 'cmeqncqjh0001jxf3a2sibmvy',
                },
                container: {
                  type: 'object',
                  properties: {
                    id: {
                      type: 'string',
                      example: 'cmeqncqjh0001jxf3a2sibmvy',
                    },
                    name: { type: 'string', example: 'gtm-unified' },
                    fullName: {
                      type: 'string',
                      example: 'sgtm-cmepifo1-d58058f9',
                    },
                    status: { type: 'string', example: 'RUNNING' },
                    subdomain: {
                      type: 'string',
                      example: 'tags.bikobazaar.xyz',
                    },
                    createdAt: { type: 'string', format: 'date-time' },
                    updatedAt: { type: 'string', format: 'date-time' },
                  },
                },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 202,
    description:
      'Container created but startup deferred due to service unavailability',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            message: {
              type: 'string',
              example:
                'Container created successfully (runner service unavailable)',
            },
            data: {
              type: 'object',
              properties: {
                container: {
                  type: 'object',
                  properties: {
                    id: {
                      type: 'string',
                      example: 'cmeqncqjh0001jxf3a2sibmvy',
                    },
                    name: { type: 'string', example: 'gtm-unified' },
                    fullName: {
                      type: 'string',
                      example: 'sgtm-cmepifo1-d58058f9',
                    },
                    status: { type: 'string', example: 'CREATED' },
                    subdomain: {
                      type: 'string',
                      example: 'tags.bikobazaar.xyz',
                    },
                    createdAt: { type: 'string', format: 'date-time' },
                    updatedAt: { type: 'string', format: 'date-time' },
                  },
                },
                warning: {
                  type: 'string',
                  example:
                    'Bash runner service unavailable - container not started',
                },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid request parameters or container creation failed',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            message: { type: 'string', example: 'Container creation failed' },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string', example: 'VALIDATION_FAILED' },
                details: {
                  type: 'string',
                  example:
                    'Name is required and must be at least 3 characters long',
                },
              },
            },
          },
        },
      },
    },
  })
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
  @ApiOperation({
    summary: 'Run a GTM container',
    description:
      'Starts a stopped or created GTM container using the docker-tagserver-run command.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container started successfully',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            message: {
              type: 'string',
              example: 'Container run completed successfully',
            },
            data: {
              type: 'object',
              properties: {
                commandId: {
                  type: 'string',
                  example: 'run-cmeqncqjh0001jxf3a2sibmvy-1756097908843',
                },
                exitCode: { type: 'number', example: 0 },
                executionTime: { type: 'number', example: 1756097908843 },
                containerId: {
                  type: 'string',
                  example: 'cmeqncqjh0001jxf3a2sibmvy',
                },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Container is already running or invalid request',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            message: {
              type: 'string',
              example: 'Container is already running',
            },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string', example: 'CONTAINER_ALREADY_RUNNING' },
                details: {
                  type: 'string',
                  example: 'Cannot start container that is already running',
                },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: 'Container not found',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            message: {
              type: 'string',
              example: 'Container not found or access denied',
            },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string', example: 'CONTAINER_NOT_FOUND' },
                details: {
                  type: 'string',
                  example: 'No container found with the specified ID',
                },
              },
            },
          },
        },
      },
    },
  })
  async run(
    @Param('id') id: string,
    @User('id') userId: string,
    @Body() runDto: RunSgtmContainerDto,
  ) {
    return this.sgtmContainerService.run(id, userId, runDto);
  }

  @Post(':id/stop')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Stop a running GTM container',
    description:
      'Stops a running GTM container using the docker-tagserver-stop command.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container stopped successfully',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            message: {
              type: 'string',
              example: 'Container stop completed successfully',
            },
            data: {
              type: 'object',
              properties: {
                commandId: {
                  type: 'string',
                  example: 'stop-cmeqncqjh0001jxf3a2sibmvy-1756097908843',
                },
                exitCode: { type: 'number', example: 0 },
                executionTime: { type: 'number', example: 1756097908843 },
                containerId: {
                  type: 'string',
                  example: 'cmeqncqjh0001jxf3a2sibmvy',
                },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Container is not running or invalid request',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            message: { type: 'string', example: 'Container is not running' },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string', example: 'CONTAINER_NOT_RUNNING' },
                details: {
                  type: 'string',
                  example: 'Cannot stop container that is not running',
                },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: 'Container not found',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            message: {
              type: 'string',
              example: 'Container not found or access denied',
            },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string', example: 'CONTAINER_NOT_FOUND' },
                details: {
                  type: 'string',
                  example: 'No container found with the specified ID',
                },
              },
            },
          },
        },
      },
    },
  })
  async stop(@Param('id') id: string, @User('id') userId: string) {
    return this.sgtmContainerService.stop(id, userId);
  }

  @Get(':id/logs')
  @ApiOperation({
    summary: 'Get logs for a GTM container',
    description:
      'Retrieves logs from a GTM container using the docker-tagserver-get command.',
  })
  @ApiResponse({
    status: 200,
    description: 'Logs retrieved successfully',
    content: {
      'application/json': {
        schema: {
          type: 'string',
          example:
            '2024-08-26 10:30:15 [INFO] Container started successfully\n2024-08-26 10:30:16 [INFO] GTM configuration loaded\n2024-08-26 10:30:17 [INFO] Server listening on port 80',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Failed to retrieve logs',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            message: { type: 'string', example: 'Failed to get logs' },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string', example: 'LOGS_RETRIEVAL_FAILED' },
                details: {
                  type: 'string',
                  example: 'Unable to retrieve container logs',
                },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: 'Container not found',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            message: {
              type: 'string',
              example: 'Container not found or access denied',
            },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string', example: 'CONTAINER_NOT_FOUND' },
                details: {
                  type: 'string',
                  example: 'No container found with the specified ID',
                },
              },
            },
          },
        },
      },
    },
  })
  async getLogs(
    @Param('id') id: string,
    @User('id') userId: string,
    @Query('lines') lines?: number,
  ) {
    return this.sgtmContainerService.getLogs(id, userId, lines || 100);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Delete a GTM container',
    description:
      'Deletes a GTM container using the docker-tagserver-delete command. This will stop and remove the container along with its Nginx configuration.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container deleted successfully',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            message: {
              type: 'string',
              example: 'Container delete completed successfully',
            },
            data: {
              type: 'object',
              properties: {
                commandId: {
                  type: 'string',
                  example: 'delete-cmeqncqjh0001jxf3a2sibmvy-1756097908843',
                },
                exitCode: { type: 'number', example: 0 },
                executionTime: { type: 'number', example: 1756097908843 },
                containerId: {
                  type: 'string',
                  example: 'cmeqncqjh0001jxf3a2sibmvy',
                },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Cannot delete running container or invalid request',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            message: {
              type: 'string',
              example: 'Cannot delete running container',
            },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string', example: 'CONTAINER_RUNNING' },
                details: {
                  type: 'string',
                  example: 'Stop the container before deleting it',
                },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: 'Container not found',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            message: {
              type: 'string',
              example: 'Container not found or access denied',
            },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string', example: 'CONTAINER_NOT_FOUND' },
                details: {
                  type: 'string',
                  example: 'No container found with the specified ID',
                },
              },
            },
          },
        },
      },
    },
  })
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
