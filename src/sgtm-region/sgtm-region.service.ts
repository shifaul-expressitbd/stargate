import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { SgtmRegion } from '@prisma/client';
import { PrismaService } from '../database/prisma/prisma.service';

@Injectable()
export class SgtmRegionService {
  private readonly logger = new Logger(SgtmRegionService.name);

  constructor(private readonly prisma: PrismaService) {}

  async create(data: {
    key: string;
    name: string;
    apiUrl: string;
    apiKey: string;
    description?: string;
  }): Promise<SgtmRegion> {
    this.logger.log(`Creating region: ${data.key} (${data.name})`);

    // Check if region key already exists
    const existingRegion = await this.prisma.sgtmRegion.findUnique({
      where: { key: data.key },
    });

    if (existingRegion) {
      throw new BadRequestException(
        `Region with key '${data.key}' already exists`,
      );
    }

    // If this is the first region, make it default
    const regionCount = await this.prisma.sgtmRegion.count();
    const isDefault = regionCount === 0 ? true : false;

    const region = await this.prisma.sgtmRegion.create({
      data: {
        ...data,
        isDefault,
      },
    });

    this.logger.log(`Region created: ${region.key} (${region.name})`);
    return region;
  }

  async findAll(): Promise<SgtmRegion[]> {
    return this.prisma.sgtmRegion.findMany({
      orderBy: [{ isDefault: 'desc' }, { name: 'asc' }],
    });
  }

  async findByKey(key: string): Promise<SgtmRegion | null> {
    return this.prisma.sgtmRegion.findUnique({
      where: { key },
    });
  }

  async findDefaultRegion(): Promise<SgtmRegion | null> {
    return this.prisma.sgtmRegion.findFirst({
      where: { isDefault: true },
    });
  }

  async update(
    key: string,
    data: Partial<{
      name: string;
      apiUrl: string;
      apiKey: string;
      isActive: boolean;
      description: string;
    }>,
  ): Promise<SgtmRegion> {
    this.logger.log(`Updating region: ${key}`);

    const region = await this.findByKey(key);
    if (!region) {
      throw new NotFoundException(`Region '${key}' not found`);
    }

    const updatedRegion = await this.prisma.sgtmRegion.update({
      where: { key },
      data,
    });

    this.logger.log(`Region updated: ${updatedRegion.key}`);
    return updatedRegion;
  }

  async setDefaultRegion(key: string): Promise<SgtmRegion> {
    this.logger.log(`Setting default region: ${key}`);

    const region = await this.findByKey(key);
    if (!region) {
      throw new NotFoundException(`Region '${key}' not found`);
    }

    // Remove default from all regions
    await this.prisma.sgtmRegion.updateMany({
      data: { isDefault: false },
    });

    // Set new default
    const updatedRegion = await this.prisma.sgtmRegion.update({
      where: { key },
      data: { isDefault: true },
    });

    this.logger.log(`Default region set to: ${updatedRegion.key}`);
    return updatedRegion;
  }

  async delete(key: string): Promise<void> {
    this.logger.log(`Deleting region: ${key}`);

    const region = await this.findByKey(key);
    if (!region) {
      throw new NotFoundException(`Region '${key}' not found`);
    }

    // Check if this is the default region
    if (region.isDefault) {
      throw new BadRequestException('Cannot delete the default region');
    }

    // Check if any containers are using this region
    const containerCount = await this.prisma.sgtmContainer.count({
      where: { region: key },
    });

    if (containerCount > 0) {
      throw new BadRequestException(
        `Cannot delete region '${key}' because it has ${containerCount} containers associated with it`,
      );
    }

    await this.prisma.sgtmRegion.delete({
      where: { key },
    });

    this.logger.log(`Region deleted: ${key}`);
  }

  async toggleActive(key: string): Promise<SgtmRegion> {
    this.logger.log(`Toggling active status for region: ${key}`);

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
      const otherActiveRegion = await this.prisma.sgtmRegion.findFirst({
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

    const updatedRegion = await this.prisma.sgtmRegion.update({
      where: { key },
      data: { isActive: !region.isActive },
    });

    this.logger.log(`Region ${key} active status: ${updatedRegion.isActive}`);
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
      available: region.isActive && !!region.apiUrl && !!region.apiKey,
      default: region.isDefault,
    }));

    return {
      regions: regionData,
      defaultRegion: defaultRegion?.key || 'india',
    };
  }

  async seedDefaultRegions(): Promise<void> {
    this.logger.log('Seeding default regions...');

    const defaultRegions = [
      {
        key: 'india',
        name: 'India',
        apiUrl: 'ws://localhost:4000/ws',
        apiKey:
          'a730cb231049b818f22496b6c4708b0b774e43e24159d77b5450b178326b7436d865bcb3428d87069df6416df5908387619103965aed0206758d52717579fb07',
        description: 'Primary region - India',
        isDefault: true,
        isActive: true,
      },
      {
        key: 'us-east',
        name: 'US East',
        apiUrl: 'ws://us-east.example.com/ws',
        apiKey: 'us-east-api-key',
        description: 'US East Coast region',
        isDefault: false,
        isActive: false,
      },
      {
        key: 'us-west',
        name: 'US West',
        apiUrl: 'ws://us-west.example.com/ws',
        apiKey: 'us-west-api-key',
        description: 'US West Coast region',
        isDefault: false,
        isActive: false,
      },
      {
        key: 'europe',
        name: 'Europe',
        apiUrl: 'ws://europe.example.com/ws',
        apiKey: 'europe-api-key',
        description: 'European region',
        isDefault: false,
        isActive: false,
      },
    ];

    for (const regionData of defaultRegions) {
      const existing = await this.findByKey(regionData.key);
      if (!existing) {
        await this.prisma.sgtmRegion.create({
          data: regionData,
        });
        this.logger.log(`Created region: ${regionData.key}`);
      }
    }

    this.logger.log('Default regions seeded successfully');
  }
}
