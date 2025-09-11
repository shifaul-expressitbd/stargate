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
import {
  DEFAULT_REGION,
  RegionKey,
  isValidRegion,
} from '../config/region.types';
import { PrismaService } from '../database/prisma/prisma.service';
import { SgtmRegionService } from '../sgtm-region/sgtm-region.service';
import { CreateSgtmContainerDto } from './dto/sgtm-container.dto';
import { UpdateSgtmContainerConfigDto } from './dto/update-sgtm-container-config.dto';
import { DecodedConfig } from './interfaces/config.interface';

@Injectable()
export class SgtmContainerService {
  private readonly logger = new Logger(SgtmContainerService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
    private readonly sgtmRegionService: SgtmRegionService,
  ) {
    this.logger.log('SgtmContainerService initialized');
  }

  async create(userId: string, dto: CreateSgtmContainerDto) {
    this.logger.log(
      `Creating container for user ${userId} with name ${dto.name}`,
    );

    // Determine the region to use (default to DEFAULT_REGION if not specified)
    const region: RegionKey =
      dto.region && isValidRegion(dto.region) ? dto.region : DEFAULT_REGION;

    this.logger.debug(`Using region: ${region} for container creation`);

    // Create DB entry with PENDING status (fullName will be set from API response)
    const container = await this.prisma.sgtmContainer.create({
      data: {
        name: dto.name,
        fullName: null, // Will be updated from API response
        userId,
        status: ContainerStatus.PENDING,
        subdomain: dto.subdomain,
        config: dto.config,
        regionKey: region,
      },
    });

    this.logger.log(
      `Container created with ID: ${container.id}, status PENDING`,
    );

    try {
      // Get region config
      const regionConfig = await this.sgtmRegionService.findByKey(region);
      if (!regionConfig || !regionConfig.apiUrl || !regionConfig.apiKey) {
        throw new BadRequestException(
          `Region ${region} not configured properly`,
        );
      }

      // Prepare base API URL
      const baseApiUrl = regionConfig.apiUrl.replace('ws://', 'http://');

      // Health check before proceeding
      const healthUrl = `${baseApiUrl}/health`;
      this.logger.debug(`Checking health at ${healthUrl}`);

      try {
        const healthResponse = await firstValueFrom(
          this.httpService.get(healthUrl, {
            headers: {
              Accept: 'application/json',
            },
          }),
        );

        if (!healthResponse.data || healthResponse.data.status !== 'healthy') {
          throw new BadRequestException(
            `Region ${region} API server is not healthy`,
          );
        }

        this.logger.debug(`Health check passed for region ${region}`);
      } catch (healthError) {
        this.logger.error(
          `Health check failed for region ${region}: ${healthError.message}`,
        );
        throw new BadRequestException(
          `Region ${region} API server is not available`,
        );
      }

      // Prepare API URL for container creation
      const apiUrl = `${baseApiUrl}/api/run/docker-tagserver-create`;

      // Generate random string for uniqueness
      const randomString = '_' + Math.random().toString(36).substr(2, 6);

      // Prepare args
      const args = {
        subdomain: dto.subdomain,
        config: dto.config,
        name: dto.name + randomString,
        user: userId,
        json: true,
      };

      this.logger.debug(
        `Calling API at ${apiUrl} with args: ${JSON.stringify(args)}`,
      );

      // Call the API
      const response = await firstValueFrom(
        this.httpService.post(
          apiUrl,
          { args },
          {
            headers: {
              'x-api-key': regionConfig.apiKey,
              Accept: 'application/json',
              'Content-Type': 'application/json',
            },
          },
        ),
      );

      const apiData = response.data;
      this.logger.log(
        `API call successful, response: ${JSON.stringify(apiData)}`,
      );

      if (apiData.success && apiData.data) {
        // Update DB with response
        await this.prisma.sgtmContainer.update({
          where: { id: container.id },
          data: {
            status: ContainerStatus.RUNNING,
            containerId: apiData.data.id,
            fullName: apiData.data.name,
            subdomain: apiData.data.domain,
          },
        });

        this.logger.log(`Container ${container.id} updated to RUNNING`);

        return {
          success: true,
          message: 'Container created and started successfully',
          data: {
            id: container.id,
            container: {
              containerId: apiData.data.id,
              name: dto.name,
              fullName: apiData.data.name,
              status: ContainerStatus.RUNNING,
              subdomain: apiData.data.domain,
              createdAt: container.createdAt,
              updatedAt: new Date(),
            },
          },
          timestamp: new Date().toISOString(),
          path: '/api/sgtm-containers',
          method: 'POST',
        };
      } else {
        throw new BadRequestException(
          'API call failed: ' + JSON.stringify(apiData),
        );
      }
    } catch (error) {
      this.logger.error(
        `Error creating container: ${error.message}`,
        error.stack,
      );

      // Update status to ERROR
      await this.prisma.sgtmContainer.update({
        where: { id: container.id },
        data: { status: ContainerStatus.ERROR },
      });

      throw new BadRequestException(
        `Container creation failed: ${error.message}`,
      );
    }
  }

  async findByIdAndUser(id: string, userId: string) {
    const container = await this.prisma.sgtmContainer.findFirst({
      where: { id, userId },
    });

    if (!container) {
      this.logger.warn(
        `Container not found or access denied for ID ${id} and user ${userId}`,
      );
      throw new NotFoundException('Container not found or access denied');
    }

    return container;
  }

  async findByIdAndUserWithSync(id: string, userId: string) {
    this.logger.log(
      `Fetching and syncing container ${id} details for user ${userId}`,
    );

    const container = await this.findByIdAndUser(id, userId);

    // If container is deleted, no need to sync
    if (container.status === ContainerStatus.DELETED) {
      this.logger.debug(`Container ${id} is deleted, skipping sync`);
      return container;
    }

    try {
      // Get region config
      const regionConfig = await this.sgtmRegionService.findByKey(
        container.regionKey,
      );
      if (!regionConfig || !regionConfig.apiUrl || !regionConfig.apiKey) {
        this.logger.warn(
          `Region ${container.regionKey} not configured properly, returning cached data`,
        );
        return container;
      }

      // Prepare base API URL
      const baseApiUrl = regionConfig.apiUrl.replace('ws://', 'http://');

      // Health check before proceeding
      const healthUrl = `${baseApiUrl}/health`;
      this.logger.debug(`Checking health at ${healthUrl}`);

      try {
        const healthResponse = await firstValueFrom(
          this.httpService.get(healthUrl, {
            headers: {
              Accept: 'application/json',
            },
          }),
        );

        if (!healthResponse.data || healthResponse.data.status !== 'healthy') {
          this.logger.warn(
            `Region ${container.regionKey} API server is not healthy, returning cached data`,
          );
          return container;
        }

        this.logger.debug(
          `Health check passed for region ${container.regionKey}`,
        );
      } catch (healthError) {
        this.logger.warn(
          `Health check failed for region ${container.regionKey}: ${healthError.message}, returning cached data`,
        );
        return container;
      }

      // Prepare API URL for container get
      const apiUrl = `${baseApiUrl}/api/run/docker-tagserver-get`;

      // Prepare args
      const args = {
        containerId: container.containerId,
        user: userId,
        json: true,
      };

      this.logger.debug(
        `Calling API at ${apiUrl} with args: ${JSON.stringify(args)}`,
      );

      // Call the API
      const response = await firstValueFrom(
        this.httpService.post(
          apiUrl,
          { args },
          {
            headers: {
              'x-api-key': regionConfig.apiKey,
              Accept: 'application/json',
              'Content-Type': 'application/json',
            },
          },
        ),
      );

      const apiData = response.data;
      this.logger.log(
        `API call successful, response: ${JSON.stringify(apiData)}`,
      );

      if (apiData.success && apiData.data) {
        // Update DB with fresh data from external service
        const updateData: any = {};

        if (apiData.data.status) {
          // Map external status to our ContainerStatus enum
          switch (apiData.data.status.toLowerCase()) {
            case 'running':
              updateData.status = ContainerStatus.RUNNING;
              break;
            case 'stopped':
            case 'exited':
              updateData.status = ContainerStatus.STOPPED;
              break;
            default:
              updateData.status = ContainerStatus.ERROR;
          }
        }

        if (apiData.data.name && apiData.data.name !== container.fullName) {
          updateData.fullName = apiData.data.name;
        }

        if (
          apiData.data.domain &&
          apiData.data.domain !== container.subdomain
        ) {
          updateData.subdomain = apiData.data.domain;
        }

        // Only update if we have changes
        if (Object.keys(updateData).length > 0) {
          await this.prisma.sgtmContainer.update({
            where: { id },
            data: updateData,
          });

          this.logger.log(
            `Container ${id} updated with fresh data: ${JSON.stringify(updateData)}`,
          );

          // Return updated container
          return await this.prisma.sgtmContainer.findFirst({
            where: { id, userId },
          });
        } else {
          this.logger.debug(`No updates needed for container ${id}`);
        }
      } else {
        this.logger.warn(
          `API call failed for container ${id}: ${JSON.stringify(apiData)}`,
        );
      }
    } catch (error) {
      this.logger.warn(
        `Error syncing container ${id} details: ${error.message}, returning cached data`,
      );
    }

    // Return original container if sync failed or no updates needed
    return container;
  }

  async findAllByUser(userId: string) {
    this.logger.debug(`Finding all containers for user ${userId}`);
    return this.prisma.sgtmContainer.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findAllByUserWithSync(userId: string) {
    this.logger.log(`Fetching and syncing all containers for user ${userId}`);

    // First get all containers from database
    const dbContainers = await this.prisma.sgtmContainer.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });

    // Filter out deleted containers as they shouldn't be synced
    const activeContainers = dbContainers.filter(
      (c) => c.status !== ContainerStatus.DELETED,
    );

    if (activeContainers.length === 0) {
      this.logger.debug(
        `No active containers found for user ${userId}, returning empty array`,
      );
      return [];
    }

    try {
      // Get region config - assume all user's containers are in the same region for simplicity
      // If you have containers in multiple regions, you might need to group by region
      const region = activeContainers[0]?.regionKey || DEFAULT_REGION;

      const regionConfig = await this.sgtmRegionService.findByKey(region);
      if (!regionConfig || !regionConfig.apiUrl || !regionConfig.apiKey) {
        this.logger.warn(
          `Region ${region} not configured properly, returning cached data`,
        );
        return dbContainers;
      }

      // Prepare base API URL
      const baseApiUrl = regionConfig.apiUrl.replace('ws://', 'http://');

      // Health check before proceeding
      const healthUrl = `${baseApiUrl}/health`;
      this.logger.debug(`Checking health at ${healthUrl}`);

      try {
        const healthResponse = await firstValueFrom(
          this.httpService.get(healthUrl, {
            headers: {
              Accept: 'application/json',
            },
          }),
        );

        if (!healthResponse.data || healthResponse.data.status !== 'healthy') {
          this.logger.warn(
            `Region ${region} API server is not healthy, returning cached data`,
          );
          return dbContainers;
        }

        this.logger.debug(`Health check passed for region ${region}`);
      } catch (healthError) {
        this.logger.warn(
          `Health check failed for region ${region}: ${healthError.message}, returning cached data`,
        );
        return dbContainers;
      }

      // Prepare API URL for container list
      const apiUrl = `${baseApiUrl}/api/run/docker-tagserver-list`;

      // Prepare args
      const args = {
        user: userId,
        json: true,
      };

      this.logger.debug(
        `Calling API at ${apiUrl} with args: ${JSON.stringify(args)}`,
      );

      // Call the API
      const response = await firstValueFrom(
        this.httpService.post(
          apiUrl,
          { args },
          {
            headers: {
              'x-api-key': regionConfig.apiKey,
              Accept: 'application/json',
              'Content-Type': 'application/json',
            },
          },
        ),
      );

      const apiData = response.data;
      this.logger.log(
        `API call successful, response: ${JSON.stringify(apiData)}`,
      );

      if (apiData.success && apiData.data && Array.isArray(apiData.data)) {
        const externalContainers = apiData.data;
        const updatePromises: Promise<any>[] = [];

        // Create a map for quick lookup by containerId
        const externalContainerMap = new Map();
        externalContainers.forEach((extContainer: any) => {
          if (extContainer.id) {
            externalContainerMap.set(extContainer.id, extContainer);
          }
        });

        // Update each container in database with fresh data
        for (const dbContainer of activeContainers) {
          const externalData = externalContainerMap.get(
            dbContainer.containerId,
          );

          if (externalData) {
            const updateData: any = {};

            // Map external status to our ContainerStatus enum
            if (externalData.status) {
              switch (externalData.status.toLowerCase()) {
                case 'running':
                  updateData.status = ContainerStatus.RUNNING;
                  break;
                case 'stopped':
                case 'exited':
                  updateData.status = ContainerStatus.STOPPED;
                  break;
                default:
                  updateData.status = ContainerStatus.ERROR;
              }
            }

            // Update other fields if they've changed
            if (
              externalData.name &&
              externalData.name !== dbContainer.fullName
            ) {
              updateData.fullName = externalData.name;
            }
            if (
              externalData.domain &&
              externalData.domain !== dbContainer.subdomain
            ) {
              updateData.subdomain = externalData.domain;
            }

            // Only update if we have changes
            if (Object.keys(updateData).length > 0) {
              updatePromises.push(
                this.prisma.sgtmContainer.update({
                  where: { id: dbContainer.id },
                  data: updateData,
                }),
              );
            }
          } else {
            // Container not found in external service, mark as error
            updatePromises.push(
              this.prisma.sgtmContainer.update({
                where: { id: dbContainer.id },
                data: { status: ContainerStatus.ERROR },
              }),
            );
          }
        }

        // Execute all updates
        if (updatePromises.length > 0) {
          await Promise.all(updatePromises);
          this.logger.log(
            `Updated ${updatePromises.length} containers for user ${userId}`,
          );
        }

        // Return fresh data from database
        return await this.prisma.sgtmContainer.findMany({
          where: { userId },
          orderBy: { createdAt: 'desc' },
        });
      } else {
        this.logger.warn(
          `API call failed for user ${userId}: ${JSON.stringify(apiData)}`,
        );
      }
    } catch (error) {
      this.logger.warn(
        `Error syncing containers for user ${userId}: ${error.message}, returning cached data`,
      );
    }

    // Return original containers if sync failed
    return dbContainers;
  }

  async stop(id: string, userId: string) {
    this.logger.log(`Attempting to stop container ${id} for user ${userId}`);

    const container = await this.findByIdAndUser(id, userId);

    if (container.status !== ContainerStatus.RUNNING) {
      this.logger.warn(
        `Container ${id} is not running (status: ${container.status})`,
      );
      throw new BadRequestException('Container is not running');
    }

    try {
      // Get region config
      const regionConfig = await this.sgtmRegionService.findByKey(
        container.regionKey,
      );
      if (!regionConfig || !regionConfig.apiUrl || !regionConfig.apiKey) {
        throw new BadRequestException(
          `Region ${container.regionKey} not configured properly`,
        );
      }

      // Prepare base API URL
      const baseApiUrl = regionConfig.apiUrl.replace('ws://', 'http://');

      // Health check before proceeding
      const healthUrl = `${baseApiUrl}/health`;
      this.logger.debug(`Checking health at ${healthUrl}`);

      try {
        const healthResponse = await firstValueFrom(
          this.httpService.get(healthUrl, {
            headers: {
              Accept: 'application/json',
            },
          }),
        );

        if (!healthResponse.data || healthResponse.data.status !== 'healthy') {
          throw new BadRequestException(
            `Region ${container.regionKey} API server is not healthy`,
          );
        }

        this.logger.debug(
          `Health check passed for region ${container.regionKey}`,
        );
      } catch (healthError) {
        this.logger.error(
          `Health check failed for region ${container.regionKey}: ${healthError.message}`,
        );
        throw new BadRequestException(
          `Region ${container.regionKey} API server is not available`,
        );
      }

      // Prepare API URL for container stop
      const apiUrl = `${baseApiUrl}/api/run/docker-tagserver-stop`;

      // Prepare args
      const args = {
        containerId: container.containerId,
        user: userId,
      };

      this.logger.debug(
        `Calling API at ${apiUrl} with args: ${JSON.stringify(args)}`,
      );

      // Call the API
      const response = await firstValueFrom(
        this.httpService.post(
          apiUrl,
          { args },
          {
            headers: {
              'x-api-key': regionConfig.apiKey,
              Accept: 'application/json',
              'Content-Type': 'application/json',
            },
          },
        ),
      );

      const apiData = response.data;
      this.logger.log(
        `API call successful, response: ${JSON.stringify(apiData)}`,
      );

      if (apiData.success) {
        // Update DB status to STOPPED
        await this.prisma.sgtmContainer.update({
          where: { id },
          data: { status: ContainerStatus.STOPPED },
        });

        this.logger.log(`Container ${id} stopped successfully`);

        return {
          success: true,
          message: 'Container stopped successfully',
          data: {
            id: container.id,
            status: ContainerStatus.STOPPED,
          },
        };
      } else {
        throw new BadRequestException(
          'API call failed: ' + JSON.stringify(apiData),
        );
      }
    } catch (error) {
      this.logger.error(
        `Error stopping container: ${error.message}`,
        error.stack,
      );

      // Update status to ERROR
      await this.prisma.sgtmContainer.update({
        where: { id },
        data: { status: ContainerStatus.ERROR },
      });

      throw new BadRequestException(`Container stop failed: ${error.message}`);
    }
  }

  async restart(id: string, userId: string) {
    this.logger.log(`Attempting to restart container ${id} for user ${userId}`);

    const container = await this.findByIdAndUser(id, userId);

    // No need to block on status — restarting should work for any non-deleted container
    if (container.status === ContainerStatus.DELETED) {
      this.logger.warn(`Cannot restart deleted container ${id}`);
      throw new BadRequestException('Cannot restart deleted container');
    }

    try {
      // Get region config
      const regionConfig = await this.sgtmRegionService.findByKey(
        container.regionKey,
      );
      if (!regionConfig || !regionConfig.apiUrl || !regionConfig.apiKey) {
        throw new BadRequestException(
          `Region ${container.regionKey} not configured properly`,
        );
      }

      // Prepare base API URL
      const baseApiUrl = regionConfig.apiUrl.replace('ws://', 'http://');

      // Health check before proceeding
      const healthUrl = `${baseApiUrl}/health`;
      this.logger.debug(`Checking health at ${healthUrl}`);

      try {
        const healthResponse = await firstValueFrom(
          this.httpService.get(healthUrl, {
            headers: {
              Accept: 'application/json',
            },
          }),
        );

        if (!healthResponse.data || healthResponse.data.status !== 'healthy') {
          throw new BadRequestException(
            `Region ${container.regionKey} API server is not healthy`,
          );
        }

        this.logger.debug(
          `Health check passed for region ${container.regionKey}`,
        );
      } catch (healthError) {
        this.logger.error(
          `Health check failed for region ${container.regionKey}: ${healthError.message}`,
        );
        throw new BadRequestException(
          `Region ${container.regionKey} API server is not available`,
        );
      }

      // Prepare API URL for container restart
      const apiUrl = `${baseApiUrl}/api/run/docker-tagserver-restart`;

      // Prepare args
      const args = {
        containerId: container.containerId,
        user: userId,
      };

      this.logger.debug(
        `Calling API at ${apiUrl} with args: ${JSON.stringify(args)}`,
      );

      // Call the API
      const response = await firstValueFrom(
        this.httpService.post(
          apiUrl,
          { args },
          {
            headers: {
              'x-api-key': regionConfig.apiKey,
              Accept: 'application/json',
              'Content-Type': 'application/json',
            },
          },
        ),
      );

      const apiData = response.data;
      this.logger.log(
        `API call successful, response: ${JSON.stringify(apiData)}`,
      );

      if (apiData.success) {
        // Update DB status to RUNNING
        await this.prisma.sgtmContainer.update({
          where: { id },
          data: { status: ContainerStatus.RUNNING },
        });

        this.logger.log(`Container ${id} restarted successfully`);

        return {
          success: true,
          message: 'Container restarted successfully',
          data: {
            id: container.id,
            status: ContainerStatus.RUNNING,
          },
        };
      } else {
        throw new BadRequestException(
          'API call failed: ' + JSON.stringify(apiData),
        );
      }
    } catch (error) {
      this.logger.error(
        `Error restarting container: ${error.message}`,
        error.stack,
      );

      // Update status to ERROR
      await this.prisma.sgtmContainer.update({
        where: { id },
        data: { status: ContainerStatus.ERROR },
      });

      throw new BadRequestException(
        `Container restart failed: ${error.message}`,
      );
    }
  }

  async delete(id: string, userId: string) {
    this.logger.log(`Attempting to delete container ${id} for user ${userId}`);

    const container = await this.findByIdAndUser(id, userId);

    try {
      // Get region config
      const regionConfig = await this.sgtmRegionService.findByKey(
        container.regionKey,
      );
      if (!regionConfig || !regionConfig.apiUrl || !regionConfig.apiKey) {
        throw new BadRequestException(
          `Region ${container.regionKey} not configured properly`,
        );
      }

      // Prepare base API URL
      const baseApiUrl = regionConfig.apiUrl.replace('ws://', 'http://');

      // Health check before proceeding
      const healthUrl = `${baseApiUrl}/health`;
      this.logger.debug(`Checking health at ${healthUrl}`);

      try {
        const healthResponse = await firstValueFrom(
          this.httpService.get(healthUrl, {
            headers: {
              Accept: 'application/json',
            },
          }),
        );

        if (!healthResponse.data || healthResponse.data.status !== 'healthy') {
          throw new BadRequestException(
            `Region ${container.regionKey} API server is not healthy`,
          );
        }

        this.logger.debug(
          `Health check passed for region ${container.regionKey}`,
        );
      } catch (healthError) {
        this.logger.error(
          `Health check failed for region ${container.regionKey}: ${healthError.message}`,
        );
        throw new BadRequestException(
          `Region ${container.regionKey} API server is not available`,
        );
      }

      // Prepare API URL for container delete
      const apiUrl = `${baseApiUrl}/api/run/docker-tagserver-delete`;

      // Prepare args
      const args = {
        containerId: container.containerId,
        user: userId,
      };

      this.logger.debug(
        `Calling API at ${apiUrl} with args: ${JSON.stringify(args)}`,
      );

      // Call the API
      const response = await firstValueFrom(
        this.httpService.post(
          apiUrl,
          { args },
          {
            headers: {
              'x-api-key': regionConfig.apiKey,
              Accept: 'application/json',
              'Content-Type': 'application/json',
            },
          },
        ),
      );

      const apiData = response.data;
      this.logger.log(
        `API call successful, response: ${JSON.stringify(apiData)}`,
      );

      if (apiData.success) {
        // Update DB status to DELETED
        await this.prisma.sgtmContainer.update({
          where: { id },
          data: { status: ContainerStatus.DELETED },
        });

        this.logger.log(`Container ${id} deleted successfully`);

        return {
          success: true,
          message: 'Container deleted successfully',
          data: {
            id: container.id,
            status: ContainerStatus.DELETED,
          },
        };
      } else {
        throw new BadRequestException(
          'API call failed: ' + JSON.stringify(apiData),
        );
      }
    } catch (error) {
      this.logger.error(
        `Error deleting container: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException(
        `Container delete failed: ${error.message}`,
      );
    }
  }

  async hardDelete(id: string, userId: string) {
    this.logger.log(
      `Attempting to hard delete container ${id} for user ${userId}`,
    );

    const container = await this.findByIdAndUser(id, userId);

    try {
      // Get region config
      const regionConfig = await this.sgtmRegionService.findByKey(
        container.regionKey,
      );
      if (!regionConfig || !regionConfig.apiUrl || !regionConfig.apiKey) {
        throw new BadRequestException(
          `Region ${container.regionKey} not configured properly`,
        );
      }

      // Prepare base API URL
      const baseApiUrl = regionConfig.apiUrl.replace('ws://', 'http://');

      // Health check before proceeding
      const healthUrl = `${baseApiUrl}/health`;
      this.logger.debug(`Checking health at ${healthUrl}`);

      try {
        const healthResponse = await firstValueFrom(
          this.httpService.get(healthUrl, {
            headers: {
              Accept: 'application/json',
            },
          }),
        );

        if (!healthResponse.data || healthResponse.data.status !== 'healthy') {
          throw new BadRequestException(
            `Region ${container.regionKey} API server is not healthy`,
          );
        }

        this.logger.debug(
          `Health check passed for region ${container.regionKey}`,
        );
      } catch (healthError) {
        this.logger.error(
          `Health check failed for region ${container.regionKey}: ${healthError.message}`,
        );
        throw new BadRequestException(
          `Region ${container.regionKey} API server is not available`,
        );
      }

      // Prepare API URL for container delete
      const apiUrl = `${baseApiUrl}/api/run/docker-tagserver-delete`;

      // Prepare args
      const args = {
        containerId: container.containerId,
        user: userId,
      };

      this.logger.debug(
        `Calling API at ${apiUrl} with args: ${JSON.stringify(args)}`,
      );

      // Call the API
      const response = await firstValueFrom(
        this.httpService.post(
          apiUrl,
          { args },
          {
            headers: {
              'x-api-key': regionConfig.apiKey,
              Accept: 'application/json',
              'Content-Type': 'application/json',
            },
          },
        ),
      );

      const apiData = response.data;
      this.logger.log(
        `API call successful, response: ${JSON.stringify(apiData)}`,
      );

      if (apiData.success) {
        // Delete from database completely
        await this.prisma.sgtmContainer.delete({
          where: { id },
        });

        this.logger.log(`Container ${id} hard deleted successfully`);

        return {
          success: true,
          message: 'Container hard deleted successfully',
          data: {
            id: container.id,
            deleted: true,
          },
        };
      } else {
        // Check if the error is "Container not found" - treat as success since it's already deleted
        if (apiData.error && apiData.error.includes('Container not found')) {
          this.logger.log(
            `Container ${container.containerId} not found in external service (already deleted or never existed), proceeding with database deletion`,
          );

          // Delete from database completely
          await this.prisma.sgtmContainer.delete({
            where: { id },
          });

          this.logger.log(`Container ${id} deleted from database successfully`);

          return {
            success: true,
            message: 'Container deleted successfully',
            data: {
              id: container.id,
              deleted: true,
            },
          };
        } else {
          throw new BadRequestException(
            'API call failed: ' + JSON.stringify(apiData),
          );
        }
      }
    } catch (error) {
      this.logger.error(
        `Error hard deleting container: ${error.message}`,
        error.stack,
      );

      // Check if it's a 404 "Container not found" error - in this case, delete from DB anyway
      if (
        error.message &&
        error.message.includes('Request failed with status code 404')
      ) {
        this.logger.log(
          `Container ${container.containerId} not found in external service (404), proceeding with database deletion`,
        );

        // Delete from database completely
        await this.prisma.sgtmContainer.delete({
          where: { id },
        });

        this.logger.log(`Container ${id} deleted from database successfully`);

        return {
          success: true,
          message: 'Container deleted successfully',
          data: {
            id: container.id,
            deleted: true,
          },
        };
      }

      throw new BadRequestException(
        `Container delete failed: ${error.message}`,
      );
    }
  }

  private decodeConfig(encodedConfig: string): DecodedConfig {
    try {
      const decodedStr = Buffer.from(encodedConfig, 'base64').toString('utf-8');
      const params = new URLSearchParams(decodedStr);
      const config: DecodedConfig = {};

      for (const [key, value] of params.entries()) {
        config[key] = value;
      }

      return config;
    } catch (error) {
      this.logger.error(`Error decoding config: ${error.message}`, error.stack);
      throw new BadRequestException('Invalid configuration format');
    }
  }

  private encodeConfig(config: DecodedConfig): string {
    try {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(config)) {
        if (value !== undefined && value !== null) {
          params.append(key, value.toString());
        }
      }
      return Buffer.from(params.toString()).toString('base64');
    } catch (error) {
      this.logger.error(`Error encoding config: ${error.message}`, error.stack);
      throw new BadRequestException('Invalid configuration data');
    }
  }

  async getConfig(id: string, userId: string) {
    const container = await this.findByIdAndUser(id, userId);

    if (!container.config) {
      return {
        success: true,
        data: {
          config: null,
          decodedConfig: {},
        },
      };
    }

    try {
      const decodedConfig = this.decodeConfig(container.config);

      return {
        success: true,
        data: {
          config: container.config,
          decodedConfig,
        },
      };
    } catch (error) {
      this.logger.error(
        `Error getting config for container ${id}: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException('Invalid configuration format');
    }
  }

  async updateConfig(
    id: string,
    userId: string,
    dto: UpdateSgtmContainerConfigDto,
  ) {
    const container = await this.findByIdAndUser(id, userId);

    try {
      let newConfig = dto.config;

      // If serverContainerUrl is provided, update it in the configuration
      if (dto.serverContainerUrl) {
        const currentConfig = dto.config ? this.decodeConfig(dto.config) : {};
        currentConfig.serverContainerUrl = dto.serverContainerUrl;
        newConfig = this.encodeConfig(currentConfig);
      }

      // Update the container configuration
      const updatedContainer = await this.prisma.sgtmContainer.update({
        where: { id },
        data: { config: newConfig },
      });

      const decodedConfig = updatedContainer.config
        ? this.decodeConfig(updatedContainer.config)
        : {};

      return {
        success: true,
        message: 'Configuration updated successfully',
        data: {
          config: updatedContainer.config,
          decodedConfig,
        },
      };
    } catch (error) {
      this.logger.error(
        `Error updating config for container ${id}: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException(
        'Failed to update configuration: ' + error.message,
      );
    }
  }
}
