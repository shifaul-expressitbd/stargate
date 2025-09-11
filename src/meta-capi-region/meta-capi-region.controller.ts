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
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { MetaCapiRegion } from '@prisma/client';
import { Roles } from '../common/decorators/roles.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import {
  AvailableMetaCapiRegionsResponseDto,
  CreateMetaCapiRegionDto,
  MetaCapiRegionResponseDto,
  UpdateMetaCapiRegionDto,
} from './dto/meta-capi-region.dto';
import { MetaCapiRegionService } from './meta-capi-region.service';

@ApiTags('mCAPI-Regions')
@Controller('api/meta-capi-regions')
@UseGuards(JwtAuthGuard)
export class MetaCapiRegionController {
  private readonly logger = new Logger(MetaCapiRegionController.name);

  constructor(private readonly metaCapiRegionService: MetaCapiRegionService) {}

  @Post()
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Create a new Meta CAPI region' })
  @ApiBody({ type: CreateMetaCapiRegionDto })
  @ApiResponse({
    status: 201,
    description: 'Region created successfully',
    type: MetaCapiRegionResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async create(
    @Body() createMetaCapiRegionDto: CreateMetaCapiRegionDto,
  ): Promise<MetaCapiRegion> {
    this.logger.log(
      `Creating Meta CAPI region: ${createMetaCapiRegionDto.key}`,
    );
    return this.metaCapiRegionService.create(createMetaCapiRegionDto);
  }

  @Get()
  // @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Get all Meta CAPI regions' })
  @ApiResponse({
    status: 200,
    description: 'Regions retrieved successfully',
    type: [MetaCapiRegionResponseDto],
  })
  async findAll(): Promise<MetaCapiRegion[]> {
    return this.metaCapiRegionService.findAll();
  }

  @Get('available')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Get available Meta CAPI regions for API usage' })
  @ApiResponse({
    status: 200,
    description: 'Available regions retrieved successfully',
    type: AvailableMetaCapiRegionsResponseDto,
  })
  async getAvailableRegions(): Promise<AvailableMetaCapiRegionsResponseDto> {
    return this.metaCapiRegionService.getAvailableRegionsForApi();
  }

  @Get(':key')
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Get Meta CAPI region by key' })
  @ApiParam({ name: 'key', description: 'Region key' })
  @ApiResponse({
    status: 200,
    description: 'Region retrieved successfully',
    type: MetaCapiRegionResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Region not found' })
  async findByKey(@Param('key') key: string): Promise<MetaCapiRegion> {
    const region = await this.metaCapiRegionService.findByKey(key);
    if (!region) {
      throw new NotFoundException(`Region '${key}' not found`);
    }
    return region;
  }

  @Put(':key')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Update Meta CAPI region' })
  @ApiParam({ name: 'key', description: 'Region key' })
  @ApiBody({ type: UpdateMetaCapiRegionDto })
  @ApiResponse({
    status: 200,
    description: 'Region updated successfully',
    type: MetaCapiRegionResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Region not found' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async update(
    @Param('key') key: string,
    @Body() updateMetaCapiRegionDto: UpdateMetaCapiRegionDto,
  ): Promise<MetaCapiRegion> {
    this.logger.log(`Updating Meta CAPI region: ${key}`);
    return this.metaCapiRegionService.update(key, updateMetaCapiRegionDto);
  }

  @Put(':key/set-default')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Set Meta CAPI region as default' })
  @ApiParam({ name: 'key', description: 'Region key' })
  @ApiResponse({
    status: 200,
    description: 'Region set as default successfully',
    type: MetaCapiRegionResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Region not found' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async setDefault(@Param('key') key: string): Promise<MetaCapiRegion> {
    this.logger.log(`Setting default Meta CAPI region: ${key}`);
    return this.metaCapiRegionService.setDefaultRegion(key);
  }

  @Put(':key/toggle-active')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Toggle Meta CAPI region active status' })
  @ApiParam({ name: 'key', description: 'Region key' })
  @ApiResponse({
    status: 200,
    description: 'Region active status toggled successfully',
    type: MetaCapiRegionResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Region not found' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async toggleActive(@Param('key') key: string): Promise<MetaCapiRegion> {
    this.logger.log(`Toggling active status for Meta CAPI region: ${key}`);
    return this.metaCapiRegionService.toggleActive(key);
  }

  @Delete(':key')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete Meta CAPI region' })
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
    this.logger.log(`Deleting Meta CAPI region: ${key}`);
    await this.metaCapiRegionService.delete(key);
  }

  @Post('seed-default')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Seed default Meta CAPI regions' })
  @ApiResponse({
    status: 200,
    description: 'Default regions seeded successfully',
  })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async seedDefaultRegions(): Promise<{ message: string }> {
    this.logger.log('Seeding default Meta CAPI regions');
    await this.metaCapiRegionService.seedDefaultRegions();
    return { message: 'Default Meta CAPI regions seeded successfully' };
  }
}
