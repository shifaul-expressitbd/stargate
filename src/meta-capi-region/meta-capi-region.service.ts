import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { MetaCapiRegion } from '@prisma/client';
import { PrismaService } from '../database/prisma/prisma.service';

@Injectable()
export class MetaCapiRegionService {
  private readonly logger = new Logger(MetaCapiRegionService.name);

  constructor(private readonly prisma: PrismaService) {}

  async create(data: {
    key: string;
    name: string;
    baseUrl: string;
    appId: string;
    appSecret: string;
    apiVersion?: string;
    description?: string;
  }): Promise<MetaCapiRegion> {
    this.logger.log(`Creating Meta CAPI region: ${data.key} (${data.name})`);

    // Check if region key already exists
    const existingRegion = await this.prisma.metaCapiRegion.findUnique({
      where: { key: data.key },
    });

    if (existingRegion) {
      throw new BadRequestException(
        `Region with key '${data.key}' already exists`,
      );
    }

    // If this is the first region, make it default
    const regionCount = await this.prisma.metaCapiRegion.count();
    const isDefault = regionCount === 0 ? true : false;

    const region = await this.prisma.metaCapiRegion.create({
      data: {
        ...data,
        apiVersion: data.apiVersion || 'v16.0',
        isDefault,
      },
    });

    this.logger.log(`Meta CAPI region created: ${region.key} (${region.name})`);
    return region;
  }

  async findAll(): Promise<MetaCapiRegion[]> {
    return this.prisma.metaCapiRegion.findMany({
      orderBy: [{ isDefault: 'desc' }, { name: 'asc' }],
    });
  }

  async findByKey(key: string): Promise<MetaCapiRegion | null> {
    return this.prisma.metaCapiRegion.findUnique({
      where: { key },
    });
  }

  async findDefaultRegion(): Promise<MetaCapiRegion | null> {
    return this.prisma.metaCapiRegion.findFirst({
      where: { isDefault: true },
    });
  }

  async update(
    key: string,
    data: Partial<{
      name: string;
      baseUrl: string;
      appId: string;
      appSecret: string;
      apiVersion: string;
      isActive: boolean;
      description: string;
    }>,
  ): Promise<MetaCapiRegion> {
    this.logger.log(`Updating Meta CAPI region: ${key}`);

    const region = await this.findByKey(key);
    if (!region) {
      throw new NotFoundException(`Region '${key}' not found`);
    }

    const updatedRegion = await this.prisma.metaCapiRegion.update({
      where: { key },
      data,
    });

    this.logger.log(`Meta CAPI region updated: ${updatedRegion.key}`);
    return updatedRegion;
  }

  async setDefaultRegion(key: string): Promise<MetaCapiRegion> {
    this.logger.log(`Setting default Meta CAPI region: ${key}`);

    const region = await this.findByKey(key);
    if (!region) {
      throw new NotFoundException(`Region '${key}' not found`);
    }

    // Remove default from all regions
    await this.prisma.metaCapiRegion.updateMany({
      data: { isDefault: false },
    });

    // Set new default
    const updatedRegion = await this.prisma.metaCapiRegion.update({
      where: { key },
      data: { isDefault: true },
    });

    this.logger.log(`Default Meta CAPI region set to: ${updatedRegion.key}`);
    return updatedRegion;
  }

  async delete(key: string): Promise<void> {
    this.logger.log(`Deleting Meta CAPI region: ${key}`);

    const region = await this.findByKey(key);
    if (!region) {
      throw new NotFoundException(`Region '${key}' not found`);
    }

    // Check if this is the default region
    if (region.isDefault) {
      throw new BadRequestException('Cannot delete the default region');
    }

    // Check if any containers are using this region
    const containerCount = await this.prisma.metaCapiContainer.count({
      where: { regionKey: key },
    });

    if (containerCount > 0) {
      throw new BadRequestException(
        `Cannot delete region '${key}' because it has ${containerCount} containers associated with it`,
      );
    }

    await this.prisma.metaCapiRegion.delete({
      where: { key },
    });

    this.logger.log(`Meta CAPI region deleted: ${key}`);
  }

  async toggleActive(key: string): Promise<MetaCapiRegion> {
    this.logger.log(`Toggling active status for Meta CAPI region: ${key}`);

    const region = await this.findByKey(key);
    if (!region) {
      throw new NotFoundException(`Region '${key}' not found`);
    }

    // Prevent toggling isActive for default regions
    if (region.isDefault) {
      throw new BadRequestException(
        'Cannot toggle active status for the default region',
      );
    }

    // If deactivating the default region, we need to set another region as default
    if (region.isDefault && region.isActive) {
      const otherActiveRegion = await this.prisma.metaCapiRegion.findFirst({
        where: {
          key: { not: key },
          isActive: true,
        },
      });

      if (!otherActiveRegion) {
        throw new BadRequestException(
          'Cannot deactivate the only active region',
        );
      }

      // Set another region as default
      await this.setDefaultRegion(otherActiveRegion.key);
    }

    const updatedRegion = await this.prisma.metaCapiRegion.update({
      where: { key },
      data: { isActive: !region.isActive },
    });

    this.logger.log(
      `Meta CAPI region ${key} active status: ${updatedRegion.isActive}`,
    );
    return updatedRegion;
  }

  async getAvailableRegionsForApi(): Promise<{
    regions: Array<{
      key: string;
      name: string;
      available: boolean;
      default: boolean;
    }>;
    defaultRegion: string;
  }> {
    const regions = await this.findAll();
    const defaultRegion = await this.findDefaultRegion();

    const regionData = regions.map((region) => ({
      key: region.key,
      name: region.name,
      available:
        region.isActive &&
        !!region.baseUrl &&
        !!region.appId &&
        !!region.appSecret,
      default: region.isDefault,
    }));

    return {
      regions: regionData,
      defaultRegion: defaultRegion?.key || 'us',
    };
  }

  async seedDefaultRegions(): Promise<void> {
    this.logger.log('Seeding default Meta CAPI regions...');

    const defaultRegions = [
      {
        key: 'us',
        name: 'US',
        baseUrl: 'https://graph.facebook.com',
        appId: '123456789012345',
        appSecret: 'your-app-secret-us',
        apiVersion: 'v16.0',
        description: 'Primary region - US',
        isDefault: true,
        isActive: true,
      },
      {
        key: 'eu',
        name: 'EU',
        baseUrl: 'https://graph.facebook.com',
        appId: '123456789012346',
        appSecret: 'your-app-secret-eu',
        apiVersion: 'v16.0',
        description: 'European region',
        isDefault: false,
        isActive: false,
      },
      {
        key: 'asia',
        name: 'Asia',
        baseUrl: 'https://graph.facebook.com',
        appId: '123456789012347',
        appSecret: 'your-app-secret-asia',
        apiVersion: 'v16.0',
        description: 'Asian region',
        isDefault: false,
        isActive: false,
      },
    ];

    for (const regionData of defaultRegions) {
      const existing = await this.findByKey(regionData.key);
      if (!existing) {
        await this.prisma.metaCapiRegion.create({
          data: regionData,
        });
        this.logger.log(`Created Meta CAPI region: ${regionData.key}`);
      }
    }

    this.logger.log('Default Meta CAPI regions seeded successfully');
  }
}
