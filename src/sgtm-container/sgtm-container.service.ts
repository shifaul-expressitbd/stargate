// src/sgtm-container/sgtm-container.service.ts
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
import { CreateSgtmContainerDto } from './dto/create-sgtm-container.dto';
import { RunSgtmContainerDto } from './dto/run-sgtm-container.dto';

@Injectable()
export class SgtmContainerService {
  private readonly logger = new Logger(SgtmContainerService.name);
  private readonly runnerApiUrl: string;

  constructor(
    private prisma: PrismaService,
    private httpService: HttpService,
    private configService: ConfigService,
  ) {
    this.runnerApiUrl = this.configService.get<string>(
      'runner.apiUrl',
      'http://localhost:4000',
    );
  }

  async create(userId: string, dto: CreateSgtmContainerDto) {
    const fullName = `${dto.name}-${dto.subdomain.split('.')[0]}`;

    return this.prisma.sgtmContainer.create({
      data: {
        name: dto.name,
        fullName,
        userId,
        status: ContainerStatus.CREATED,
        subdomain: dto.subdomain,
        config: dto.config,
      },
    });
  }

  async findAllByUser(userId: string) {
    return this.prisma.sgtmContainer.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByIdAndUser(id: string, userId: string) {
    const container = await this.prisma.sgtmContainer.findFirst({
      where: { id, userId },
    });
    if (!container) {
      throw new NotFoundException('Container not found or access denied');
    }
    return container;
  }

  async run(id: string, userId: string, runDto: RunSgtmContainerDto) {
    const container = await this.findByIdAndUser(id, userId);

    if (container.status === ContainerStatus.RUNNING) {
      throw new BadRequestException('Container is already running');
    }

    await this.prisma.sgtmContainer.update({
      where: { id },
      data: { status: ContainerStatus.PENDING },
    });

    try {
      const response = await firstValueFrom(
        this.httpService.post(`${this.runnerApiUrl}/containers/run`, {
          containerId: container.id,
          name: container.fullName,
          subdomain: runDto.subdomain || container.subdomain,
          config: runDto.config || container.config,
          // Add default values for potentially missing fields
          port: 8080, // default port for sGTM containers
          image: 'gcr.io/google.com/tagmanager/gtm-cloud-image:stable', // default sGTM image
          autoRemove: false,
          network: 'bridge',
        }),
      );

      await this.prisma.sgtmContainer.update({
        where: { id },
        data: {
          status: ContainerStatus.RUNNING,
          action: runDto.action || 'run',
        },
      });

      return response.data;
    } catch (error) {
      this.logger.error(
        `Failed to start container ${container.fullName}:`,
        error.message,
      );

      await this.prisma.sgtmContainer.update({
        where: { id },
        data: { status: ContainerStatus.ERROR },
      });

      throw new BadRequestException(
        `Failed to start container: ${error.message}`,
      );
    }
  }

  async stop(id: string, userId: string) {
    const container = await this.findByIdAndUser(id, userId);

    if (container.status !== ContainerStatus.RUNNING) {
      throw new BadRequestException('Container is not running');
    }

    try {
      await firstValueFrom(
        this.httpService.post(`${this.runnerApiUrl}/containers/stop`, {
          containerId: container.id,
          name: container.fullName,
        }),
      );

      await this.prisma.sgtmContainer.update({
        where: { id },
        data: {
          status: ContainerStatus.STOPPED,
          action: 'stop',
        },
      });

      return { message: 'Container stopped successfully' };
    } catch (error) {
      this.logger.error(
        `Failed to stop container ${container.fullName}:`,
        error.message,
      );
      throw new BadRequestException(
        `Failed to stop container: ${error.message}`,
      );
    }
  }

  async getLogs(id: string, userId: string, lines?: number) {
    const container = await this.findByIdAndUser(id, userId);

    try {
      const response = await firstValueFrom(
        this.httpService.get(`${this.runnerApiUrl}/containers/logs`, {
          params: {
            containerId: container.id,
            name: container.fullName,
            lines: lines || 100,
          },
        }),
      );
      return response.data;
    } catch (error) {
      this.logger.error(
        `Failed to get logs for container ${container.fullName}:`,
        error.message,
      );
      throw new BadRequestException(
        `Failed to get container logs: ${error.message}`,
      );
    }
  }

  async delete(id: string, userId: string) {
    const container = await this.findByIdAndUser(id, userId);

    // Check if container is in a state that allows deletion
    if (
      container.status === ContainerStatus.RUNNING ||
      container.status === ContainerStatus.PENDING
    ) {
      throw new BadRequestException(
        'Cannot delete a running or pending container. Stop it first.',
      );
    }

    // Try to delete from Docker runner if it exists
    try {
      await firstValueFrom(
        this.httpService.delete(
          `${this.runnerApiUrl}/containers/${container.fullName}`,
        ),
      );
    } catch (error) {
      this.logger.warn(
        `Could not delete container from runner (may not exist): ${error.message}`,
      );
    }

    // Delete from database
    await this.prisma.sgtmContainer.update({
      where: { id },
      data: { status: ContainerStatus.DELETED },
    });

    return { message: 'Container deleted successfully' };
  }
}
