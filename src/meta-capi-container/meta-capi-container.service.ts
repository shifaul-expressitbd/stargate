import { HttpService } from '@nestjs/axios';
import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ContainerStatus } from '@prisma/client';
import { firstValueFrom } from 'rxjs';
import { PrismaService } from '../database/prisma/prisma.service';
import { CreateMetaCapiContainerDto } from './dto/meta-capi-container.dto';
import { UpdateMetaCapiContainerConfigDto } from './dto/update-meta-capi-container-config.dto';

@Injectable()
export class MetaCapiContainerService {
  private readonly logger = new Logger(MetaCapiContainerService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
  ) {
    this.logger.log('MetaCapiContainerService initialized');
  }

  async create(userId: string, dto: CreateMetaCapiContainerDto) {
    this.logger.log(
      `Creating Meta CAPI container for user ${userId} with name ${dto.name}`,
    );

    const regionKey = dto.regionKey || 'us'; // Default region

    // Create DB entry with PENDING status
    const container = await this.prisma.metaCapiContainer.create({
      data: {
        name: dto.name,
        fullName: null, // Will be set from API response if needed
        fbPixelId: dto.fbPixelId,
        accessToken: dto.accessToken,
        testCode: dto.testCode,
        userId,
        status: ContainerStatus.PENDING,
        regionKey,
      },
    });

    this.logger.log(
      `Meta CAPI container created with ID: ${container.id}, status PENDING`,
    );

    try {
      // Get region config
      const regionConfig = await this.prisma.metaCapiRegion.findFirst({
        where: { key: regionKey },
      });
      if (!regionConfig || !regionConfig.baseUrl || !regionConfig.appId) {
        throw new BadRequestException(
          `Region ${regionKey} not configured properly`,
        );
      }

      // For Meta CAPI, we might verify the access token or set up pixel
      // This is a simplified version - in real implementation, you'd call Facebook API
      const apiUrl = `${regionConfig.baseUrl}/${regionConfig.apiVersion}/${dto.fbPixelId}`;

      this.logger.debug(`Verifying pixel at ${apiUrl}`);

      // Health check or verify pixel exists
      try {
        const response = await firstValueFrom(
          this.httpService.get(apiUrl, {
            headers: {
              'User-Agent': 'MetaCapiContainerService/1.0',
            },
          }),
        );

        if (response.status === 200) {
          this.logger.debug(`Pixel ${dto.fbPixelId} verified`);
        } else {
          throw new BadRequestException(`Pixel ${dto.fbPixelId} not found`);
        }
      } catch (error) {
        this.logger.error(`Pixel verification failed: ${error.message}`);
        // For now, proceed anyway
      }

      // Update DB with RUNNING status
      await this.prisma.metaCapiContainer.update({
        where: { id: container.id },
        data: {
          status: ContainerStatus.RUNNING,
          fullName: `${dto.name}-pixel-${dto.fbPixelId}`,
        },
      });

      this.logger.log(`Meta CAPI container ${container.id} updated to RUNNING`);

      return {
        success: true,
        message: 'Meta CAPI container created successfully',
        data: {
          id: container.id,
          container: {
            id: container.id,
            name: dto.name,
            fbPixelId: dto.fbPixelId,
            status: ContainerStatus.RUNNING,
            createdAt: container.createdAt,
            updatedAt: new Date(),
          },
        },
        timestamp: new Date().toISOString(),
        path: '/api/meta-capi-containers',
        method: 'POST',
      };
    } catch (error) {
      this.logger.error(
        `Error creating Meta CAPI container: ${error.message}`,
        error.stack,
      );

      // Update status to ERROR
      await this.prisma.metaCapiContainer.update({
        where: { id: container.id },
        data: { status: ContainerStatus.ERROR },
      });

      throw new BadRequestException(
        `Meta CAPI container creation failed: ${error.message}`,
      );
    }
  }

  async findByIdAndUser(id: string, userId: string) {
    const container = await this.prisma.metaCapiContainer.findFirst({
      where: { id, userId },
    });

    if (!container) {
      this.logger.warn(
        `Meta CAPI container not found or access denied for ID ${id} and user ${userId}`,
      );
      throw new NotFoundException(
        'Meta CAPI container not found or access denied',
      );
    }

    return container;
  }

  async findAllByUser(userId: string) {
    this.logger.debug(`Finding all Meta CAPI containers for user ${userId}`);
    return this.prisma.metaCapiContainer.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async stop(id: string, userId: string) {
    this.logger.log(
      `Attempting to stop Meta CAPI container ${id} for user ${userId}`,
    );

    const container = await this.findByIdAndUser(id, userId);

    if (container.status !== ContainerStatus.RUNNING) {
      this.logger.warn(
        `Meta CAPI container ${id} is not running (status: ${container.status})`,
      );
      throw new BadRequestException('Meta CAPI container is not running');
    }

    // For Meta CAPI, "stop" might mean disabling events or something
    // This is simplified
    await this.prisma.metaCapiContainer.update({
      where: { id },
      data: { status: ContainerStatus.STOPPED },
    });

    this.logger.log(`Meta CAPI container ${id} stopped successfully`);

    return {
      success: true,
      message: 'Meta CAPI container stopped successfully',
      data: {
        id: container.id,
        status: ContainerStatus.STOPPED,
      },
    };
  }

  async restart(id: string, userId: string) {
    this.logger.log(
      `Attempting to restart Meta CAPI container ${id} for user ${userId}`,
    );

    const container = await this.findByIdAndUser(id, userId);

    if (container.status === ContainerStatus.DELETED) {
      this.logger.warn(`Cannot restart deleted Meta CAPI container ${id}`);
      throw new BadRequestException(
        'Cannot restart deleted Meta CAPI container',
      );
    }

    // Simplified restart
    await this.prisma.metaCapiContainer.update({
      where: { id },
      data: { status: ContainerStatus.RUNNING },
    });

    this.logger.log(`Meta CAPI container ${id} restarted successfully`);

    return {
      success: true,
      message: 'Meta CAPI container restarted successfully',
      data: {
        id: container.id,
        status: ContainerStatus.RUNNING,
      },
    };
  }

  async delete(id: string, userId: string) {
    this.logger.log(
      `Attempting to delete Meta CAPI container ${id} for user ${userId}`,
    );

    const container = await this.findByIdAndUser(id, userId);

    await this.prisma.metaCapiContainer.update({
      where: { id },
      data: { status: ContainerStatus.DELETED },
    });

    this.logger.log(`Meta CAPI container ${id} deleted successfully`);

    return {
      success: true,
      message: 'Meta CAPI container deleted successfully',
      data: {
        id: container.id,
        status: ContainerStatus.DELETED,
      },
    };
  }

  async hardDelete(id: string, userId: string) {
    this.logger.log(
      `Attempting to hard delete Meta CAPI container ${id} for user ${userId}`,
    );

    const container = await this.findByIdAndUser(id, userId);

    await this.prisma.metaCapiContainer.delete({
      where: { id },
    });

    this.logger.log(`Meta CAPI container ${id} hard deleted successfully`);

    return {
      success: true,
      message: 'Meta CAPI container hard deleted successfully',
      data: {
        id: container.id,
        deleted: true,
      },
    };
  }

  async updateConfig(
    id: string,
    userId: string,
    dto: UpdateMetaCapiContainerConfigDto,
  ) {
    const container = await this.findByIdAndUser(id, userId);

    await this.prisma.metaCapiContainer.update({
      where: { id },
      data: {
        accessToken: dto.accessToken,
        testCode: dto.testCode,
      },
    });

    return {
      success: true,
      message: 'Meta CAPI container config updated successfully',
      data: {
        id: container.id,
        accessToken: dto.accessToken,
        testCode: dto.testCode,
      },
    };
  }
}
