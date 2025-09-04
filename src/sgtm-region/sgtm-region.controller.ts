import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  NotFoundException,
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
  ApiParam,
  ApiProperty,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { SgtmRegion } from '@prisma/client';
import { Roles } from '../common/decorators/roles.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { SgtmRegionService } from './sgtm-region.service';

class CreateRegionDto {
  @ApiProperty({ example: 'us-east-1' })
  key: string;
  @ApiProperty({ example: 'US East 1' })
  name: string;
  @ApiProperty({ example: 'https://api.example.com' })
  apiUrl: string;
  @ApiProperty({ example: 'your-api-key' })
  apiKey: string;
  @ApiProperty({ required: false, example: 'A description' })
  description?: string;
}

class UpdateRegionDto {
  @ApiProperty({ required: false, example: 'US East 1 Updated' })
  name?: string;
  @ApiProperty({ required: false, example: 'https://api.updated.com' })
  apiUrl?: string;
  @ApiProperty({ required: false, example: 'new-api-key' })
  apiKey?: string;
  @ApiProperty({ required: false, example: true })
  isActive?: boolean;
  @ApiProperty({ required: false, example: 'Updated description' })
  description?: string;
}

class RegionResponseDto {
  @ApiProperty({ example: 'clhjm8x1214520kgfg30kajlm' })
  id: string;
  @ApiProperty({ example: 'us-east-1' })
  key: string;
  @ApiProperty({ example: 'US East 1' })
  name: string;
  @ApiProperty({ example: 'https://api.example.com' })
  apiUrl: string;
  @ApiProperty({ example: 'your-api-key' })
  apiKey: string;
  @ApiProperty({ example: true })
  isActive: boolean;
  @ApiProperty({ example: false })
  isDefault: boolean;
  @ApiProperty({ required: false, example: 'A description' })
  description?: string;
  @ApiProperty({ type: 'string', format: 'date-time' })
  createdAt: Date;
  @ApiProperty({ type: 'string', format: 'date-time' })
  updatedAt: Date;
}

class AvailableRegionsResponseDto {
  @ApiProperty({
    type: 'array',
    items: {
      type: 'object',
      properties: {
        key: { type: 'string', example: 'us-east-1' },
        name: { type: 'string', example: 'US East 1' },
        available: { type: 'boolean', example: true },
        default: { type: 'boolean', example: false },
      },
    },
  })
  regions: Array<{
    key: string;
    name: string;
    available: boolean;
    default: boolean;
  }>;
  @ApiProperty({ example: 'us-east-1' })
  defaultRegion: string;
}

@ApiTags('SGTM Regions')
@ApiExtraModels(
  CreateRegionDto,
  UpdateRegionDto,
  RegionResponseDto,
  AvailableRegionsResponseDto,
)
@Controller('sgtm-regions')
@UseGuards(JwtAuthGuard)
export class SgtmRegionController {
  private readonly logger = new Logger(SgtmRegionController.name);

  constructor(private readonly sgtmRegionService: SgtmRegionService) {}

  @Post()
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Create a new region' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        key: {
          type: 'string',
          example: 'us-east-1',
          description: 'Region key',
        },
        name: {
          type: 'string',
          example: 'US East 1',
          description: 'Region name',
        },
        apiUrl: {
          type: 'string',
          example: 'https://api.example.com',
          description: 'API URL for the region',
        },
        apiKey: {
          type: 'string',
          example: 'your-api-key',
          description: 'API key for authentication',
        },
        description: {
          type: 'string',
          example: 'A description',
          description: 'Optional description',
          nullable: true,
        },
      },
      required: ['key', 'name', 'apiUrl', 'apiKey'],
    },
  })
  @ApiResponse({
    status: 201,
    description: 'Region created successfully',
    type: RegionResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async create(@Body() createRegionDto: CreateRegionDto): Promise<SgtmRegion> {
    this.logger.log(`Creating region: ${createRegionDto.key}`);
    return this.sgtmRegionService.create(createRegionDto);
  }

  @Get()
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Get all regions' })
  @ApiResponse({
    status: 200,
    description: 'Regions retrieved successfully',
    type: [RegionResponseDto],
  })
  async findAll(): Promise<SgtmRegion[]> {
    return this.sgtmRegionService.findAll();
  }

  @Get('available')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Get available regions for API usage' })
  @ApiResponse({
    status: 200,
    description: 'Available regions retrieved successfully',
    type: AvailableRegionsResponseDto,
  })
  async getAvailableRegions(): Promise<AvailableRegionsResponseDto> {
    return this.sgtmRegionService.getAvailableRegionsForApi();
  }

  @Get(':key')
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Get region by key' })
  @ApiParam({ name: 'key', description: 'Region key' })
  @ApiResponse({
    status: 200,
    description: 'Region retrieved successfully',
    type: RegionResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Region not found' })
  async findByKey(@Param('key') key: string): Promise<SgtmRegion> {
    const region = await this.sgtmRegionService.findByKey(key);
    if (!region) {
      throw new NotFoundException(`Region '${key}' not found`);
    }
    return region;
  }

  @Put(':key')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Update region' })
  @ApiParam({ name: 'key', description: 'Region key' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          example: 'US East 1 Updated',
          description: 'Region name',
          nullable: true,
        },
        apiUrl: {
          type: 'string',
          example: 'https://api.updated.com',
          description: 'API URL for the region',
          nullable: true,
        },
        apiKey: {
          type: 'string',
          example: 'new-api-key',
          description: 'API key for authentication',
          nullable: true,
        },
        isActive: {
          type: 'boolean',
          example: true,
          description: 'Whether the region is active',
          nullable: true,
        },
        description: {
          type: 'string',
          example: 'Updated description',
          description: 'Optional description',
          nullable: true,
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Region updated successfully',
    type: RegionResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Region not found' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async update(
    @Param('key') key: string,
    @Body() updateRegionDto: UpdateRegionDto,
  ): Promise<SgtmRegion> {
    this.logger.log(`Updating region: ${key}`);
    return this.sgtmRegionService.update(key, updateRegionDto);
  }

  @Put(':key/set-default')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Set region as default' })
  @ApiParam({ name: 'key', description: 'Region key' })
  @ApiResponse({
    status: 200,
    description: 'Region set as default successfully',
    type: RegionResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Region not found' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async setDefault(@Param('key') key: string): Promise<SgtmRegion> {
    this.logger.log(`Setting default region: ${key}`);
    return this.sgtmRegionService.setDefaultRegion(key);
  }

  @Put(':key/toggle-active')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Toggle region active status' })
  @ApiParam({ name: 'key', description: 'Region key' })
  @ApiResponse({
    status: 200,
    description: 'Region active status toggled successfully',
    type: RegionResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Region not found' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async toggleActive(@Param('key') key: string): Promise<SgtmRegion> {
    this.logger.log(`Toggling active status for region: ${key}`);
    return this.sgtmRegionService.toggleActive(key);
  }

  @Delete(':key')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete region' })
  @ApiParam({ name: 'key', description: 'Region key' })
  @ApiResponse({ status: 204, description: 'Region deleted successfully' })
  @ApiResponse({ status: 404, description: 'Region not found' })
  @ApiResponse({
    status: 400,
    description:
      'Bad request - cannot delete region with containers or default region',
  })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async delete(@Param('key') key: string): Promise<void> {
    this.logger.log(`Deleting region: ${key}`);
    await this.sgtmRegionService.delete(key);
  }

  @Post('seed-default')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Seed default regions' })
  @ApiResponse({
    status: 200,
    description: 'Default regions seeded successfully',
  })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async seedDefaultRegions(): Promise<{ message: string }> {
    this.logger.log('Seeding default regions');
    await this.sgtmRegionService.seedDefaultRegions();
    return { message: 'Default regions seeded successfully' };
  }
}
