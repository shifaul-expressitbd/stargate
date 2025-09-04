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
  Put,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiExtraModels,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { User } from '../common/decorators/user.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CreateSgtmContainerDto } from './dto/sgtm-container.dto';
import { UpdateSgtmContainerConfigDto } from './dto/update-sgtm-container-config.dto';
import { SgtmContainerService } from './sgtm-container.service';

@ApiTags('sGTM-containers')
@ApiExtraModels(CreateSgtmContainerDto, UpdateSgtmContainerConfigDto)
@Controller('sgtm-containers')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT-auth')
export class SgtmContainerController {
  constructor(private readonly sgtmContainerService: SgtmContainerService) {}

  @Post()
  @ApiOperation({
    summary: 'Create a new GTM container',
    description:
      'Creates and starts a new GTM container using the docker-tagserver-create command. The container will be automatically configured with Nginx and SSL if available.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          example: 'gtm-unified',
          minLength: 3,
          maxLength: 50,
          description: 'Container name',
        },
        subdomain: {
          type: 'string',
          example: 'tags.bikobazaar.xyz',
          description: 'Subdomain for the container',
        },
        config: {
          type: 'string',
          example:
            'aWQ9R1RNLVdGOFc4WERIJmVudj0xJmF1dGg9ZXRJdWpPajNPaWJGN2kxcU52d2hqQQ==',
          description: 'Container configuration data (base64 encoded)',
        },
        region: {
          type: 'string',
          example: 'us-east-1',
          description: 'Region where the container should be deployed',
          nullable: true,
        },
      },
      required: ['name', 'subdomain', 'config'],
    },
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
    content: {
      'application/json': {
        schema: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              id: { type: 'string', example: 'cmeqncqjh0001jxf3a2sibmvy' },
              name: { type: 'string', example: 'gtm-unified' },
              fullName: { type: 'string', example: 'sgtm-cmepifo1-d58058f9' },
              containerId: { type: 'string', example: 'a1b2c3d4e5f6' },
              status: {
                type: 'string',
                enum: ['PENDING', 'RUNNING', 'STOPPED', 'ERROR', 'DELETED'],
                example: 'RUNNING',
              },
              subdomain: { type: 'string', example: 'tags.bikobazaar.xyz' },
              config: {
                type: 'string',
                example:
                  'aWQ9R1RNLVdGOFc4WERIJmVudj0xJmF1dGg9ZXRJdWpPajNPaWJGN2kxcU52d2hqQQ==',
              },
              region: { type: 'string', example: 'us-east-1' },
              userId: { type: 'string', example: 'cmepifo1d58058f9' },
              createdAt: { type: 'string', format: 'date-time' },
              updatedAt: { type: 'string', format: 'date-time' },
            },
            required: [
              'id',
              'name',
              'fullName',
              'status',
              'subdomain',
              'userId',
              'createdAt',
              'updatedAt',
            ],
          },
        },
      },
    },
  })
  async findAll(@User('id') userId: string) {
    return this.sgtmContainerService.findAllByUser(userId);
  }

  @Get('sync')
  @ApiOperation({
    summary: 'Get and sync all GTM containers for the current user',
    description:
      'Retrieves all containers for the user and synchronizes their details with the external docker service using docker-tagserver-list command. Updates the database with fresh information for all containers.',
  })
  @ApiResponse({
    status: 200,
    description: 'Containers retrieved and synced successfully',
    content: {
      'application/json': {
        schema: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              id: { type: 'string', example: 'cmeqncqjh0001jxf3a2sibmvy' },
              name: { type: 'string', example: 'gtm-unified' },
              fullName: { type: 'string', example: 'sgtm-cmepifo1-d58058f9' },
              containerId: { type: 'string', example: 'a1b2c3d4e5f6' },
              status: {
                type: 'string',
                enum: ['PENDING', 'RUNNING', 'STOPPED', 'ERROR', 'DELETED'],
                example: 'RUNNING',
              },
              subdomain: { type: 'string', example: 'tags.bikobazaar.xyz' },
              config: {
                type: 'string',
                example:
                  'aWQ9R1RNLVdGOFc4WERIJmVudj0xJmF1dGg9ZXRJdWpPajNPaWJGN2kxcU52d2hqQQ==',
              },
              region: { type: 'string', example: 'us-east-1' },
              userId: { type: 'string', example: 'cmepifo1d58058f9' },
              createdAt: { type: 'string', format: 'date-time' },
              updatedAt: { type: 'string', format: 'date-time' },
            },
          },
        },
      },
    },
  })
  async findAllWithSync(@User('id') userId: string) {
    return this.sgtmContainerService.findAllByUserWithSync(userId);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a specific GTM container' })
  @ApiResponse({
    status: 200,
    description: 'Container retrieved successfully',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            id: { type: 'string', example: 'cmeqncqjh0001jxf3a2sibmvy' },
            name: { type: 'string', example: 'gtm-unified' },
            fullName: { type: 'string', example: 'sgtm-cmepifo1-d58058f9' },
            containerId: { type: 'string', example: 'a1b2c3d4e5f6' },
            status: {
              type: 'string',
              enum: ['PENDING', 'RUNNING', 'STOPPED', 'ERROR', 'DELETED'],
              example: 'RUNNING',
            },
            subdomain: { type: 'string', example: 'tags.bikobazaar.xyz' },
            config: {
              type: 'string',
              example:
                'aWQ9R1RNLVdGOFc4WERIJmVudj0xJmF1dGg9ZXRJdWpPajNPaWJGN2kxcU52d2hqQQ==',
            },
            region: { type: 'string', example: 'us-east-1' },
            userId: { type: 'string', example: 'cmepifo1d58058f9' },
            createdAt: { type: 'string', format: 'date-time' },
            updatedAt: { type: 'string', format: 'date-time' },
          },
          required: [
            'id',
            'name',
            'fullName',
            'status',
            'subdomain',
            'userId',
            'createdAt',
            'updatedAt',
          ],
        },
      },
    },
  })
  @ApiResponse({ status: 404, description: 'Container not found' })
  async findOne(@Param('id') id: string, @User('id') userId: string) {
    return this.sgtmContainerService.findByIdAndUser(id, userId);
  }

  @Get(':id/sync')
  @ApiOperation({
    summary: 'Get and sync a specific GTM container',
    description:
      'Retrieves a container and synchronizes its details with the external docker service using docker-tagserver-get command. Updates the database with fresh information.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container retrieved and synced successfully',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            id: { type: 'string', example: 'cmeqncqjh0001jxf3a2sibmvy' },
            name: { type: 'string', example: 'gtm-unified' },
            fullName: { type: 'string', example: 'sgtm-cmepifo1-d58058f9' },
            containerId: { type: 'string', example: 'a1b2c3d4e5f6' },
            status: {
              type: 'string',
              enum: ['PENDING', 'RUNNING', 'STOPPED', 'ERROR', 'DELETED'],
              example: 'RUNNING',
            },
            subdomain: { type: 'string', example: 'tags.bikobazaar.xyz' },
            config: {
              type: 'string',
              example:
                'aWQ9R1RNLVdGOFc4WERIJmVudj0xJmF1dGg9ZXRJdWpPajNPaWJGN2kxcU52d2hqQQ==',
            },
            region: { type: 'string', example: 'us-east-1' },
            userId: { type: 'string', example: 'cmepifo1d58058f9' },
            createdAt: { type: 'string', format: 'date-time' },
            updatedAt: { type: 'string', format: 'date-time' },
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
  async findOneWithSync(@Param('id') id: string, @User('id') userId: string) {
    return this.sgtmContainerService.findByIdAndUserWithSync(id, userId);
  }

  @Get(':id/config')
  @ApiOperation({
    summary: 'Get GTM container configuration',
    description:
      'Retrieves the current configuration for a specific GTM container, including any custom Configuration Parameters.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container configuration retrieved successfully',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            data: {
              type: 'object',
              properties: {
                config: {
                  type: 'string',
                  description: 'Base64 encoded configuration string',
                  example:
                    'aWQ9R1RNLVdGOFc4WERIJmVudj0xJmF1dGg9ZXRJdWpPajNPaWJGN2kxcU52d2hqQQ==',
                },
                decodedConfig: {
                  type: 'object',
                  description: 'Decoded configuration parameters',
                  properties: {
                    serverContainerUrl: {
                      type: 'string',
                      example: 'https://container.example.com',
                    },
                    // Add other config params as needed
                  },
                },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({ status: 404, description: 'Container not found' })
  async getConfig(@Param('id') id: string, @User('id') userId: string) {
    return this.sgtmContainerService.getConfig(id, userId);
  }

  @Put(':id/config')
  @ApiOperation({
    summary: 'Update GTM container configuration',
    description:
      'Updates the configuration for a specific GTM container, including any custom Configuration Parameters.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        config: {
          type: 'string',
          example:
            'aWQ9R1RNLVdGOFc4WERIJmVudj0xJmF1dGg9ZXRJdWpPajNPaWJGN2kxcU52d2hqQQ==',
          description: 'Container configuration data (base64 encoded)',
        },
        serverContainerUrl: {
          type: 'string',
          example: 'https://container.example.com',
          description: 'URL for server container',
          nullable: true,
        },
      },
      required: ['config'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Container configuration updated successfully',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            message: {
              type: 'string',
              example: 'Configuration updated successfully',
            },
            data: {
              type: 'object',
              properties: {
                config: {
                  type: 'string',
                  example:
                    'aWQ9R1RNLVdGOFc4WERIJmVudj0xJmF1dGg9ZXRJdWpPajNPaWJGN2kxcU52d2hqQQ==',
                },
                decodedConfig: {
                  type: 'object',
                  properties: {
                    serverContainerUrl: {
                      type: 'string',
                      example: 'https://container.example.com',
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({ status: 404, description: 'Container not found' })
  @ApiResponse({ status: 400, description: 'Invalid configuration format' })
  async updateConfig(
    @Param('id') id: string,
    @User('id') userId: string,
    @Body() updateDto: UpdateSgtmContainerConfigDto,
  ) {
    return this.sgtmContainerService.updateConfig(id, userId, updateDto);
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

  @Post(':id/restart')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Restart a GTM container',
    description:
      'Restarts a GTM container using the docker-tagserver-restart command.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container restarted successfully',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            message: {
              type: 'string',
              example: 'Container restart completed successfully',
            },
            data: {
              type: 'object',
              properties: {
                commandId: {
                  type: 'string',
                  example: 'restart-cmeqncqjh0001jxf3a2sibmvy-1756097908843',
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
    description: 'Container cannot be restarted or invalid request',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            message: {
              type: 'string',
              example: 'Cannot restart deleted container',
            },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string', example: 'CONTAINER_DELETED' },
                details: {
                  type: 'string',
                  example: 'Cannot restart container that has been deleted',
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
  async restart(@Param('id') id: string, @User('id') userId: string) {
    return this.sgtmContainerService.restart(id, userId);
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

  @Delete(':id/hard')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Hard delete a GTM container (permanent deletion)',
    description:
      'Permanently deletes a GTM container from both the external service and the database. This action cannot be undone.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container hard deleted successfully',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            message: {
              type: 'string',
              example: 'Container hard delete completed successfully',
            },
            data: {
              type: 'object',
              properties: {
                id: {
                  type: 'string',
                  example: 'cmeqncqjh0001jxf3a2sibmvy',
                },
                deleted: { type: 'boolean', example: true },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid request or hard delete failed',
    content: {
      'application/json': {
        schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            message: {
              type: 'string',
              example: 'Container hard delete failed',
            },
            error: {
              type: 'object',
              properties: {
                code: { type: 'string', example: 'HARD_DELETE_FAILED' },
                details: {
                  type: 'string',
                  example:
                    'Failed to hard delete container from external service',
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
  async hardDelete(@Param('id') id: string, @User('id') userId: string) {
    return this.sgtmContainerService.hardDelete(id, userId);
  }
}
