import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ContainerStatus } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';
import {
  BashRunnerService,
  CommandExecutionResult,
  StandardizedResponse,
} from '../bash-runner/bash-runner.service';
import {
  DEFAULT_REGION,
  RegionKey,
  isValidRegion,
} from '../config/region.types';
import { PrismaService } from '../database/prisma/prisma.service';
import { CreateSgtmContainerDto } from './dto/create-sgtm-container.dto';
import { RunSgtmContainerDto } from './dto/run-sgtm-container.dto';

@Injectable()
export class SgtmContainerService {
  private readonly logger = new Logger(SgtmContainerService.name);
  private pendingContainerPromises = new Map<
    string,
    { resolve: (value: any) => void; reject: (reason?: any) => void }
  >();
  private pendingTimeouts = new Map<
    string,
    { timeout: NodeJS.Timeout; commandId: string }
  >();

  constructor(
    private readonly prisma: PrismaService,
    private readonly bashRunnerService: BashRunnerService,
    private readonly configService: ConfigService,
  ) {
    this.logger.log('SgtmContainerService initialized');

    // Example: Add custom result message interceptor
    this.setupCustomResultInterceptor();
    // Add WebSocket result interceptor for REST API responses
    this.setupWebSocketResultInterceptor();
  }

  /**
   * Example custom interceptor for result messages
   */
  private setupCustomResultInterceptor() {
    this.bashRunnerService.onResultMessage((data, commandId) => {
      this.logger.log(
        `🎯 [CUSTOM INTERCEPTOR] Processing result for command: ${commandId}`,
      );

      // Handle bash runner result format with defensive programming
      const success = data.status === 'success' || data.success;
      const exitCode = data.status === 'success' ? 0 : (data.exitCode ?? 1);

      if (success && exitCode === 0) {
        this.logger.log(
          `✅ [CUSTOM INTERCEPTOR] Command ${commandId} succeeded`,
        );
        // You can add custom logic here, like:
        // - Send notifications
        // - Update metrics
        // - Trigger other actions
        // - Log to external systems
      } else {
        this.logger.error(
          `❌ [CUSTOM INTERCEPTOR] Command ${commandId} failed with exit code ${exitCode}`,
        );
        // Handle failures - maybe retry logic, alerts, etc.
      }
    });
  }

  /**
   * Processes command execution results and returns standardized JSON responses
   */
  private async processCommandResult(
    result: CommandExecutionResult,
    operation: string,
  ): Promise<StandardizedResponse> {
    // Add defensive programming for missing success/exitCode fields
    const success = result.success ?? (result as any).status === 'success';
    const exitCode = result.exitCode ?? (success ? 0 : 1);

    this.logger.log(
      `Command ${result.commandId} completed: success=${success}, exitCode=${exitCode}`,
    );

    if (success && exitCode === 0) {
      // Get updated container info if available
      let containerInfo: any = null;
      if (result.containerId) {
        try {
          containerInfo = await this.prisma.sgtmContainer.findUnique({
            where: { id: result.containerId },
            select: {
              id: true,
              name: true,
              fullName: true,
              status: true,
              subdomain: true,
              createdAt: true,
              updatedAt: true,
            },
          });
        } catch (error) {
          this.logger.warn(
            `Could not fetch updated container info: ${error.message}`,
          );
        }
      }

      const response: StandardizedResponse = {
        success: true,
        message: `${operation} completed successfully`,
        data: {
          commandId: result.commandId,
          exitCode: exitCode,
          executionTime: result.executionTime,
          containerId: result.containerId,
        },
      };

      // Add container info if available
      if (containerInfo) {
        (response.data as any).container = containerInfo;
      }

      // Add Docker info if available (from the command response)
      if (result.message && typeof result.message === 'object') {
        (response.data as any).dockerInfo = result.message;
      }

      if (result.message) {
        this.logger.debug(`Command message: ${JSON.stringify(result.message)}`);
      }

      return response;
    } else {
      // Handle different error scenarios with proper error codes
      const errorMessage =
        result.message || `${operation} failed with exit code ${exitCode}`;

      this.logger.error(
        `❌ Command ${result.commandId} failed: ${errorMessage}`,
      );

      // Determine error code based on exit code and operation context
      let errorCode = 'COMMAND_FAILED';
      if (exitCode === 1) {
        errorCode = 'OPERATION_FAILED';
      } else if (exitCode === 127) {
        errorCode = 'COMMAND_NOT_FOUND';
      } else if (exitCode === 126) {
        errorCode = 'COMMAND_NOT_EXECUTABLE';
      }

      throw new BadRequestException({
        success: false,
        message: errorMessage,
        error: {
          code: errorCode,
          details: `${operation} failed with exit code ${exitCode}`,
        },
      });
    }
  }

  /**
   * Waits for container operation result from WebSocket messages
   */
  private async waitForContainerResult(
    commandId: string,
    containerId: string,
    operation: string,
  ): Promise<CommandExecutionResult> {
    return new Promise<CommandExecutionResult>((resolve, reject) => {
      // Store the promise resolvers for the webhook interceptor to use
      this.pendingContainerPromises.set(commandId, { resolve, reject });

      // Set timeout for the operation (2 minutes)
      const timeout = setTimeout(() => {
        // Remove from pending promises if still there
        this.pendingContainerPromises.delete(commandId);
        reject(new Error(`${operation} timed out after 2 minutes`));
      }, 120000);

      // Store timeout for cleanup
      const timeoutRef = { timeout, commandId };
      this.pendingTimeouts = this.pendingTimeouts || new Map();
      this.pendingTimeouts.set(commandId, timeoutRef);
    });
  }

  /**
   * Sets up WebSocket result interceptor for REST API responses
   */
  private setupWebSocketResultInterceptor() {
    this.bashRunnerService.onResultMessage((data, commandId) => {
      this.logger.log(
        `🎯 [WEBHOOK INTERCEPTOR] Processing result for command: ${commandId}`,
      );

      // Map bash runner result format to expected CommandExecutionResult format
      let success: boolean;
      let exitCode: number;

      if (data.status === 'success') {
        success = true;
        exitCode = 0;
      } else {
        success = data.success || false;
        exitCode = data.exitCode || 1;
      }

      // Check if this result is for a container operation and resolve any waiting promises
      if (
        commandId.startsWith('create-') ||
        commandId.startsWith('run-') ||
        commandId.startsWith('stop-')
      ) {
        const containerId = this.getContainerIdFromCommandId(commandId);
        const action = this.getActionFromCommandId(commandId);

        // Resolve any waiting promises for this command
        const waitingPromise = this.pendingContainerPromises.get(commandId);
        if (waitingPromise) {
          this.pendingContainerPromises.delete(commandId);

          // Clear the timeout
          const timeoutRef = this.pendingTimeouts.get(commandId);
          if (timeoutRef) {
            clearTimeout(timeoutRef.timeout);
            this.pendingTimeouts.delete(commandId);
          }

          const executionResult: CommandExecutionResult = {
            success,
            exitCode,
            message: data.data || data.message,
            commandId,
            action,
            containerId,
            executionTime: Date.now(),
            dockerInfo:
              success && exitCode === 0 && (data.data || data.message)
                ? data.data || data.message
                : null,
          };

          if (success) {
            waitingPromise.resolve(executionResult);
          } else {
            waitingPromise.reject(new Error(data.error || 'Command failed'));
          }
        }
      }

      // Format the result for REST API response
      const formattedResult = this.processCommandResult(
        {
          success,
          exitCode,
          message: data.data || data.message,
          commandId,
          action: this.getActionFromCommandId(commandId),
          containerId: this.getContainerIdFromCommandId(commandId),
          executionTime: Date.now(),
        },
        this.getOperationFromCommandId(commandId),
      );

      this.logger.debug(
        `📤 [WEBHOOK INTERCEPTOR] Formatted result for REST API: ${JSON.stringify(formattedResult)}`,
      );

      // Extract Docker information and update database if available
      if (success && exitCode === 0 && (data.data || data.message)) {
        const dockerInfo = data.data || data.message;
        if (
          typeof dockerInfo === 'object' &&
          dockerInfo.name &&
          dockerInfo.id
        ) {
          const containerDbId = this.getContainerIdFromCommandId(commandId);
          if (containerDbId) {
            // Fire and forget - update database with Docker info
            this.updateContainerWithDockerInfo(containerDbId, {
              name: dockerInfo.name, // This will be stored in fullName
              id: dockerInfo.id, // This will be stored in containerId
              status: dockerInfo.status,
              domain: dockerInfo.domain,
            })
              .then(() => {
                this.logger.log(
                  `✅ Updated container ${containerDbId} with Docker info from ${commandId}`,
                );
              })
              .catch((error) => {
                this.logger.warn(
                  `Failed to update container ${containerDbId} with Docker info: ${error.message}`,
                );
              });
          }
        }
      }

      // Here you could also emit an event or store the result for later retrieval
    });
  }

  /**
   * Cleanup method to remove event handlers and prevent memory leaks
   */
  private cleanupCommandHandlers(commandId: string) {
    try {
      this.bashRunnerService.offMessage(`result`);
      this.bashRunnerService.offMessage(`error`);
      this.bashRunnerService.offMessage(`output`);
      this.logger.debug(`Cleaned up handlers for command: ${commandId}`);
    } catch (error) {
      this.logger.warn(`Error cleaning up handlers for ${commandId}:`, error);
    }
  }

  /**
   * Helper method to extract action from command ID
   */
  private getActionFromCommandId(commandId: string): string {
    if (commandId.startsWith('create-')) return 'create';
    if (commandId.startsWith('run-')) return 'run';
    if (commandId.startsWith('stop-')) return 'stop';
    if (commandId.startsWith('delete-')) return 'delete';
    return 'unknown';
  }

  /**
   * Helper method to extract container ID from command ID
   */
  private getContainerIdFromCommandId(commandId: string): string | undefined {
    const parts = commandId.split('-');
    return parts.length > 1 ? parts[1] : undefined;
  }

  /**
   * Helper method to get operation name from command ID
   */
  private getOperationFromCommandId(commandId: string): string {
    const action = this.getActionFromCommandId(commandId);
    return `Container ${action}`;
  }

  /**
   * Update container record with real Docker container information
   */
  private async updateContainerWithDockerInfo(
    containerId: string,
    dockerInfo: any,
  ) {
    try {
      this.logger.log(
        `Updating container ${containerId} with Docker info:`,
        dockerInfo,
      );

      const updateData: any = {};

      // Update with real Docker container information
      if (dockerInfo.name) {
        updateData.fullName = dockerInfo.name; // Override the generated name with actual Docker name
      }

      if (dockerInfo.id) {
        updateData.containerId = dockerInfo.id; // Store the Docker container ID
      }

      if (dockerInfo.status) {
        // Map Docker status to our enum
        switch (dockerInfo.status.toLowerCase()) {
          case 'running':
            updateData.status = ContainerStatus.RUNNING;
            break;
          case 'stopped':
          case 'exited':
            updateData.status = ContainerStatus.STOPPED;
            break;
          case 'created':
            updateData.status = ContainerStatus.CREATED;
            break;
          default:
            updateData.status = ContainerStatus.ERROR;
        }
      }

      if (dockerInfo.domain) {
        updateData.subdomain = dockerInfo.domain; // Update subdomain with actual domain
      }

      // Only update if we have data to update
      if (Object.keys(updateData).length > 0) {
        const updatedContainer = await this.prisma.sgtmContainer.update({
          where: { id: containerId },
          data: updateData,
        });

        this.logger.log(
          `✅ Container ${containerId} updated with Docker info: ${updatedContainer.fullName}`,
        );
        return updatedContainer;
      }
    } catch (error) {
      this.logger.error(
        `Failed to update container ${containerId} with Docker info:`,
        error,
      );
      throw error;
    }
  }

  async create(userId: string, dto: CreateSgtmContainerDto) {
    this.logger.log(
      `Creating container for user ${userId} with name ${dto.name}`,
    );

    // Determine the region to use (default to DEFAULT_REGION if not specified)
    const region: RegionKey =
      dto.region && isValidRegion(dto.region) ? dto.region : DEFAULT_REGION;

    this.logger.debug(`Using region: ${region} for container creation`);

    // Validate that the selected region is properly configured
    try {
      this.bashRunnerService.getConfigForRegion(region);
    } catch (error) {
      this.logger.error(
        `Region '${region}' is not properly configured: ${error.message}`,
      );
      throw new BadRequestException(
        `Region '${region}' is not available. Please select a different region or contact support.`,
      );
    }

    // Generate a unique container name using userId and a short UUID
    const shortUuid = uuidv4().slice(0, 8);
    const fullName = `sgtm-${userId.substring(0, 8)}-${shortUuid}`;

    this.logger.debug(`Generated container fullName: ${fullName}`);

    const container = await this.prisma.sgtmContainer.create({
      data: {
        name: dto.name,
        fullName,
        userId,
        status: ContainerStatus.CREATED,
        subdomain: dto.subdomain,
        config: dto.config,
        region: region,
      },
    });

    this.logger.log(`Container created with ID: ${container.id}`);

    // Check if bash runner service is available before attempting to run
    if (this.bashRunnerService.isAvailable()) {
      this.logger.log(
        'Bash runner service is available, attempting to run container automatically',
      );
      try {
        // Generate a unique command ID for tracking this operation
        const commandId = `create-${container.id}-${Date.now()}`;

        this.logger.log(`Sending container creation command: ${commandId}`);

        // Use WebSocket to run container
        await this.bashRunnerService.sendCommand(
          commandId,
          {
            commandId: commandId,
            action: 'docker-tagserver-run',
            containerId: container.id,
            subdomain: dto.subdomain || container.subdomain || undefined,
            config: dto.config || container.config || undefined,
            name: dto.name, // Container name prefix (required)
            user: userId, // Required: user identifier
          },
          region,
        );

        // Wait for the container result with improved error handling
        const executionResult = await this.waitForContainerResult(
          commandId,
          container.id,
          'create',
        );

        // Update container status based on result
        if (executionResult.success) {
          await this.prisma.sgtmContainer.update({
            where: { id: container.id },
            data: { status: ContainerStatus.RUNNING },
          });
          this.logger.log(`Container ${container.id} started successfully`);

          // Use Docker info from executionResult if available, otherwise use container data
          const dockerContainerId =
            executionResult.dockerInfo?.id || container.containerId;
          const dockerContainerName =
            executionResult.dockerInfo?.name || container.fullName;

          // Return the standardized response with container information
          return {
            success: true,
            message: 'Container created and started successfully',
            data: {
              commandId: executionResult.commandId,
              exitCode: executionResult.exitCode,
              executionTime: executionResult.executionTime,
              id: container.id,
              container: {
                containerId: dockerContainerId,
                name: container.name,
                fullName: dockerContainerName,
                status: ContainerStatus.RUNNING,
                subdomain: container.subdomain,
                createdAt: container.createdAt,
                updatedAt: container.updatedAt,
              },
            },
            timestamp: new Date().toISOString(),
            path: '/api/sgtm-containers',
            method: 'POST',
          };
        } else {
          await this.prisma.sgtmContainer.update({
            where: { id: container.id },
            data: { status: ContainerStatus.ERROR },
          });
          this.logger.warn(`Container ${container.id} failed to start`);

          // Return error response
          return {
            success: false,
            message: 'Container created but failed to start',
            data: {
              id: container.id,
              container: {
                containerId: container.containerId,
                name: container.name,
                fullName: container.fullName,
                status: ContainerStatus.ERROR,
                subdomain: container.subdomain,
                createdAt: container.createdAt,
                updatedAt: container.updatedAt,
              },
              error: executionResult.message,
            },
            timestamp: new Date().toISOString(),
            path: '/api/sgtm-containers',
            method: 'POST',
          };
        }
      } catch (error) {
        this.logger.warn(
          `Container created but failed to start automatically: ${error.message}`,
        );

        // Update container status to ERROR
        await this.prisma.sgtmContainer.update({
          where: { id: container.id },
          data: { status: ContainerStatus.ERROR },
        });

        // Return the container creation success but with error details
        return {
          success: false,
          message: 'Container created but automatic startup failed',
          data: {
            id: container.id,
            container: {
              containerId: container.containerId,
              name: container.name,
              fullName: container.fullName,
              status: ContainerStatus.ERROR,
              subdomain: container.subdomain,
              createdAt: container.createdAt,
              updatedAt: container.updatedAt,
            },
            startupError: error.message,
          },
          timestamp: new Date().toISOString(),
          path: '/api/sgtm-containers',
          method: 'POST',
        };
      }
    } else {
      this.logger.warn(
        `Container created but bash runner service is unavailable. The container will remain in CREATED status.`,
      );
      // Return success response for container creation
      return {
        success: true,
        message: 'Container created successfully (runner service unavailable)',
        data: {
          id: container.id,
          container: {
            containerId: container.containerId,
            name: container.name,
            fullName: container.fullName,
            status: ContainerStatus.CREATED,
            subdomain: container.subdomain,
            createdAt: container.createdAt,
            updatedAt: container.updatedAt,
          },
          warning: 'Bash runner service unavailable - container not started',
        },
        timestamp: new Date().toISOString(),
        path: '/api/sgtm-containers',
        method: 'POST',
      };
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

  async findAllByUser(userId: string) {
    this.logger.debug(`Finding all containers for user ${userId}`);
    return this.prisma.sgtmContainer.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async run(id: string, userId: string, runDto: RunSgtmContainerDto) {
    this.logger.log(`Attempting to run container ${id} for user ${userId}`);

    const container = await this.findByIdAndUser(id, userId);

    if (container.status === ContainerStatus.RUNNING) {
      this.logger.warn(`Container ${id} is already running`);
      throw new BadRequestException('Container is already running');
    }

    this.logger.log(`Updating container ${id} status to PENDING`);
    await this.prisma.sgtmContainer.update({
      where: { id },
      data: { status: ContainerStatus.PENDING },
    });

    try {
      // Generate a unique command ID for tracking this operation
      const commandId = `run-${container.id}-${Date.now()}`;

      this.logger.log(
        `Running container ${container.fullName} with command ID: ${commandId}`,
      );
      console.log(
        `[CONTAINER_DEBUG] Preparing to run container with commandId: ${commandId}`,
      );
      console.log(`[CONTAINER_DEBUG] Container details:`, {
        id: container.id,
        fullName: container.fullName,
        subdomain: runDto.subdomain || container.subdomain,
        configPresent: !!runDto.config || !!container.config,
        configLength: (runDto.config || container.config)?.length || 0,
      });

      console.log(`[CONTAINER_DEBUG] Checking WebSocket connection status...`);
      console.log(
        `[CONTAINER_DEBUG] Is connected: ${this.bashRunnerService.isConnected()}`,
      );
      console.log(
        `[CONTAINER_DEBUG] Connection status: ${this.bashRunnerService.getConnectionStatus()}`,
      );

      // Set up a promise that resolves when we get the response
      const runPromise = new Promise<CommandExecutionResult>(
        (resolve, reject) => {
          // Register handler for container status updates
          const statusHandler = this.bashRunnerService.onMessage(
            `container-status:${commandId}`,
            (data) => {
              this.logger.log(
                `Container ${container.fullName} status: ${data.status}`,
              );

              if (data.status === 'running') {
                this.prisma.sgtmContainer
                  .update({
                    where: { id },
                    data: { status: ContainerStatus.RUNNING },
                  })
                  .catch((err) =>
                    this.logger.error(
                      `Failed to update container status to RUNNING: ${err.message}`,
                    ),
                  );
                // Resolve with successful execution result
                resolve({
                  success: true,
                  exitCode: 0,
                  message: 'Container started successfully',
                  commandId,
                  action: 'docker-tagserver-run',
                  containerId: container.id,
                  executionTime: Date.now(),
                });
              } else if (data.status === 'error') {
                this.prisma.sgtmContainer
                  .update({
                    where: { id },
                    data: { status: ContainerStatus.ERROR },
                  })
                  .catch((err) =>
                    this.logger.error(
                      `Failed to update container status to ERROR: ${err.message}`,
                    ),
                  );
                reject(
                  new Error(
                    `Container failed to start: ${data.error || 'Unknown error'}`,
                  ),
                );
              }
            },
          );

          // Register handler for stderr in case of errors
          const errorHandler = this.bashRunnerService.onMessage(
            `container-stderr:${commandId}`,
            (data) => {
              this.logger.error(
                `Error starting container ${container.fullName}: ${data}`,
              );
            },
          );

          // Clean up handlers when promise settles
          const cleanup = () => {
            statusHandler();
            errorHandler();
          };

          // Set up cleanup on resolve/reject
          (resolve as any).cleanup = cleanup;
          (reject as any).cleanup = cleanup;
        },
      );

      // Use WebSocket to run container
      console.log(`[CONTAINER_DEBUG] Attempting to send run command...`);

      try {
        await this.bashRunnerService.sendCommand(
          commandId,
          {
            commandId: commandId,
            action: 'docker-tagserver-run',
            containerId: container.id,
            subdomain: runDto.subdomain || container.subdomain || undefined,
            config: runDto.config || container.config || undefined,
            name: container.name, // Container name prefix (required)
            user: userId, // Required: user identifier
          },
          container.region as RegionKey,
        );
        console.log(`[CONTAINER_DEBUG] Run command sent successfully`);
      } catch (sendError) {
        console.error(
          `[CONTAINER_DEBUG] Failed to send run command:`,
          sendError,
        );
        throw sendError;
      }

      console.log(`[CONTAINER_DEBUG] Waiting for runPromise completion...`);
      const executionResult = await runPromise;
      return this.processCommandResult(executionResult, 'Container run');
    } catch (error) {
      this.logger.error(
        `Failed to send start command for container ${container.fullName}:`,
        error.message,
      );

      // Check if this is a service unavailable error
      if (
        error.message.includes('Bash runner service is currently unavailable')
      ) {
        this.logger.warn(
          `Container ${id} cannot be started because the bash runner service is unavailable`,
        );
        await this.prisma.sgtmContainer.update({
          where: { id },
          data: { status: ContainerStatus.CREATED }, // Keep as CREATED instead of ERROR
        });
        throw new BadRequestException(
          `Cannot start container: ${error.message}. Please ensure the bash runner service is running and try again.`,
        );
      }

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
    this.logger.log(`Attempting to stop container ${id} for user ${userId}`);

    const container = await this.findByIdAndUser(id, userId);

    if (container.status !== ContainerStatus.RUNNING) {
      this.logger.warn(
        `Container ${id} is not running (status: ${container.status})`,
      );
      throw new BadRequestException('Container is not running');
    }

    // Check if container has a Docker container ID
    if (!container.containerId) {
      this.logger.warn(
        `Container ${id} does not have a Docker container ID. It may not be running or was not properly started.`,
      );
      throw new BadRequestException(
        'Container does not have a Docker container ID. Cannot stop a container that was not properly started.',
      );
    }

    this.logger.log(`Updating container ${id} status to PENDING (for stop)`);
    await this.prisma.sgtmContainer.update({
      where: { id },
      data: { status: ContainerStatus.PENDING },
    });

    try {
      // Generate a unique command ID for tracking this operation
      const commandId = `stop-${container.id}-${Date.now()}`;

      this.logger.log(
        `Stopping container ${container.fullName} with command ID: ${commandId}`,
      );
      console.log(
        `[CONTAINER_DEBUG] Preparing to stop container with commandId: ${commandId}`,
      );
      console.log(`[CONTAINER_DEBUG] Container details:`, {
        id: container.id,
        fullName: container.fullName,
        dockerContainerId: container.containerId,
        subdomain: container.subdomain,
      });

      console.log(`[CONTAINER_DEBUG] Checking bash runner service status...`);
      console.log(
        `[CONTAINER_DEBUG] Is connected: ${this.bashRunnerService.isConnected()}`,
      );
      console.log(
        `[CONTAINER_DEBUG] Is available: ${this.bashRunnerService.isAvailable()}`,
      );
      console.log(
        `[CONTAINER_DEBUG] Connection status: ${this.bashRunnerService.getConnectionStatus()}`,
      );

      // Set up a promise that resolves when we get the response
      const stopPromise = new Promise<CommandExecutionResult>(
        (resolve, reject) => {
          // Register handler for container status updates
          const statusHandler = this.bashRunnerService.onMessage(
            `container-status:${commandId}`,
            (data) => {
              this.logger.log(
                `Container ${container.fullName} status: ${data.status}`,
              );

              if (data.status === 'stopped') {
                this.prisma.sgtmContainer
                  .update({
                    where: { id },
                    data: { status: ContainerStatus.STOPPED },
                  })
                  .catch((err) =>
                    this.logger.error(
                      `Failed to update container status to STOPPED: ${err.message}`,
                    ),
                  );
                // Resolve with successful execution result
                resolve({
                  success: true,
                  exitCode: 0,
                  message: 'Container stopped successfully',
                  commandId,
                  action: 'docker-tagserver-stop',
                  containerId: container.id,
                  executionTime: Date.now(),
                });
              } else if (data.status === 'error') {
                this.prisma.sgtmContainer
                  .update({
                    where: { id },
                    data: { status: ContainerStatus.ERROR },
                  })
                  .catch((err) =>
                    this.logger.error(
                      `Failed to update container status to ERROR: ${err.message}`,
                    ),
                  );
                reject(
                  new Error(
                    `Failed to stop container: ${data.error || 'Unknown error'}`,
                  ),
                );
              }
            },
          );

          // Register handler for stderr in case of errors
          const errorHandler = this.bashRunnerService.onMessage(
            `container-stderr:${commandId}`,
            (data) => {
              this.logger.error(
                `Error stopping container ${container.fullName}: ${data}`,
              );
            },
          );

          // Clean up handlers when promise settles
          const cleanup = () => {
            statusHandler();
            errorHandler();
          };

          // Set up cleanup on resolve/reject
          (resolve as any).cleanup = cleanup;
          (reject as any).cleanup = cleanup;
        },
      );

      // Use WebSocket to stop container
      console.log(`[CONTAINER_DEBUG] Attempting to send stop command...`);

      try {
        await this.bashRunnerService.sendCommand(
          commandId,
          {
            commandId: commandId,
            action: 'docker-tagserver-stop',
            containerId: container.containerId, // Use Docker container ID instead of database ID
            user: userId, // Required: user identifier
          },
          container.region as RegionKey,
        );
        console.log(`[CONTAINER_DEBUG] Stop command sent successfully`);
      } catch (sendError) {
        console.error(
          `[CONTAINER_DEBUG] Failed to send stop command:`,
          sendError,
        );
        throw sendError;
      }

      console.log(`[CONTAINER_DEBUG] Waiting for stopPromise completion...`);
      const executionResult = await stopPromise;
      return this.processCommandResult(executionResult, 'Container stop');
    } catch (error) {
      this.logger.error(
        `Failed to send stop command for container ${container.fullName}:`,
        error.message,
      );

      // Check if this is a service unavailable error
      if (
        error.message.includes('Bash runner service is currently unavailable')
      ) {
        this.logger.warn(
          `Container ${id} cannot be stopped because the bash runner service is unavailable`,
        );
        throw new BadRequestException(
          `Cannot stop container: ${error.message}. Please ensure the bash runner service is running and try again.`,
        );
      }

      await this.prisma.sgtmContainer.update({
        where: { id },
        data: { status: ContainerStatus.ERROR },
      });
      throw new BadRequestException(
        `Failed to stop container: ${error.message}`,
      );
    }
  }

  async getLogs(id: string, userId: string, lines: number = 100) {
    this.logger.log(`Fetching logs for container ${id} (lines: ${lines})`);

    const container = await this.findByIdAndUser(id, userId);

    try {
      // Generate a unique command ID for tracking this operation
      const commandId = `logs-${container.id}-${Date.now()}`;

      this.logger.log(
        `Getting logs for container ${container.fullName} with command ID: ${commandId}`,
      );
      console.log(
        `[CONTAINER_DEBUG] Preparing to get logs with commandId: ${commandId}`,
      );
      console.log(`[CONTAINER_DEBUG] Container details:`, {
        id: container.id,
        fullName: container.fullName,
        lines: lines,
      });

      console.log(`[CONTAINER_DEBUG] Checking WebSocket connection status...`);
      console.log(
        `[CONTAINER_DEBUG] Is connected: ${this.bashRunnerService.isConnected()}`,
      );
      console.log(
        `[CONTAINER_DEBUG] Connection status: ${this.bashRunnerService.getConnectionStatus()}`,
      );

      // Set up a promise that resolves when we get the logs
      const logsPromise = new Promise<string>((resolve, reject) => {
        let logs = '';

        // Register handler for stdout data
        const stdoutHandler = this.bashRunnerService.onMessage(
          `container-stdout:${commandId}`,
          (data) => {
            logs += data;
          },
        );

        // Register handler for completion
        const completeHandler = this.bashRunnerService.onMessage(
          `container-logs-complete:${commandId}`,
          () => {
            resolve(logs);
          },
        );

        // Register handler for errors
        const errorHandler = this.bashRunnerService.onMessage(
          `container-stderr:${commandId}`,
          (data) => {
            this.logger.error(
              `Error getting logs for container ${container.fullName}: ${data}`,
            );
            reject(new Error(data));
          },
        );

        // Clean up handlers when promise settles
        const cleanup = () => {
          stdoutHandler();
          completeHandler();
          errorHandler();
        };

        // Set up cleanup on resolve/reject
        (resolve as any).cleanup = cleanup;
        (reject as any).cleanup = cleanup;
      });

      // Use WebSocket to get logs
      console.log(`[CONTAINER_DEBUG] Attempting to send get-logs command...`);

      try {
        await this.bashRunnerService.sendCommand(
          commandId,
          {
            commandId: commandId,
            action: 'docker-tagserver-get',
            containerId: container.id,
            user: userId, // Required: user identifier
            lines,
          },
          container.region as RegionKey,
        );
        console.log(`[CONTAINER_DEBUG] Get-logs command sent successfully`);
      } catch (sendError) {
        console.error(
          `[CONTAINER_DEBUG] Failed to send get-logs command:`,
          sendError,
        );
        throw sendError;
      }

      console.log(`[CONTAINER_DEBUG] Waiting for logsPromise completion...`);
      return await logsPromise;
    } catch (error) {
      this.logger.error(
        `Failed to get logs for container ${container.fullName}:`,
        error.message,
      );

      // Check if this is a service unavailable error
      if (
        error.message.includes('Bash runner service is currently unavailable')
      ) {
        this.logger.warn(
          `Cannot get logs for container ${id} because the bash runner service is unavailable`,
        );
        throw new BadRequestException(
          `Cannot get container logs: ${error.message}. Please ensure the bash runner service is running and try again.`,
        );
      }

      throw new BadRequestException(`Failed to get logs: ${error.message}`);
    }
  }

  async delete(id: string, userId: string) {
    this.logger.log(`Attempting to delete container ${id} for user ${userId}`);

    const container = await this.findByIdAndUser(id, userId);

    if (container.status === ContainerStatus.RUNNING) {
      this.logger.warn(`Cannot delete running container ${id}`);
      throw new BadRequestException('Cannot delete running container');
    }

    try {
      // Generate a unique command ID for tracking this operation
      const commandId = `delete-${container.id}-${Date.now()}`;

      this.logger.log(
        `Deleting container ${container.fullName} with command ID: ${commandId}`,
      );
      console.log(
        `[CONTAINER_DEBUG] Preparing to delete container with commandId: ${commandId}`,
      );
      console.log(`[CONTAINER_DEBUG] Container details:`, {
        id: container.id,
        fullName: container.fullName,
      });

      console.log(`[CONTAINER_DEBUG] Checking WebSocket connection status...`);
      console.log(
        `[CONTAINER_DEBUG] Is connected: ${this.bashRunnerService.isConnected()}`,
      );
      console.log(
        `[CONTAINER_DEBUG] Connection status: ${this.bashRunnerService.getConnectionStatus()}`,
      );

      // Set up a promise that resolves when we get the response
      const deletePromise = new Promise<CommandExecutionResult>(
        (resolve, reject) => {
          // Register handler for completion
          const completeHandler = this.bashRunnerService.onMessage(
            `container-deleted:${commandId}`,
            (data) => {
              // Resolve with successful execution result
              resolve({
                success: true,
                exitCode: 0,
                message: 'Container deleted successfully',
                commandId,
                action: 'docker-tagserver-delete',
                containerId: container.id,
                executionTime: Date.now(),
              });
            },
          );

          // Register handler for errors
          const errorHandler = this.bashRunnerService.onMessage(
            `container-error:${commandId}`,
            (data) => {
              this.logger.error(
                `Error deleting container ${container.fullName}: ${data.error}`,
              );
              reject(new Error(data.error || 'Failed to delete container'));
            },
          );

          // Clean up handlers when promise settles
          const cleanup = () => {
            completeHandler();
            errorHandler();
          };

          // Set up cleanup on resolve/reject
          (resolve as any).cleanup = cleanup;
          (reject as any).cleanup = cleanup;
        },
      );

      // Use WebSocket to delete container
      console.log(`[CONTAINER_DEBUG] Attempting to send delete command...`);

      try {
        await this.bashRunnerService.sendCommand(
          commandId,
          {
            commandId: commandId,
            action: 'docker-tagserver-delete',
            containerId: container.id,
            user: userId, // Required: user identifier
          },
          container.region as RegionKey,
        );
        console.log(`[CONTAINER_DEBUG] Delete command sent successfully`);
      } catch (sendError) {
        console.error(
          `[CONTAINER_DEBUG] Failed to send delete command:`,
          sendError,
        );
        throw sendError;
      }

      console.log(`[CONTAINER_DEBUG] Waiting for deletePromise completion...`);
      const executionResult = await deletePromise;
      return this.processCommandResult(executionResult, 'Container delete');

      // Update database to reflect deletion
      await this.prisma.sgtmContainer.update({
        where: { id },
        data: { status: ContainerStatus.DELETED },
      });

      this.logger.log(`Container ${id} marked as deleted in database`);
      return { message: 'Container deleted successfully' };
    } catch (error) {
      // Check if this is a service unavailable error
      if (
        error.message.includes('Bash runner service is currently unavailable')
      ) {
        this.logger.warn(
          `Cannot delete container from runner because the bash runner service is unavailable`,
        );
        // Still mark as deleted in DB since the container might not actually exist in the runner
        await this.prisma.sgtmContainer.update({
          where: { id },
          data: { status: ContainerStatus.DELETED },
        });

        this.logger.log(
          `Container ${id} marked as deleted in database (runner service unavailable)`,
        );
        return {
          message:
            'Container deleted from database successfully (runner service unavailable - container may still exist in runner)',
        };
      }

      this.logger.warn(
        `Could not delete container from runner (may not exist): ${error.message}`,
      );
      // Even if the runner doesn't have it, we can still mark as deleted in DB
      await this.prisma.sgtmContainer.update({
        where: { id },
        data: { status: ContainerStatus.DELETED },
      });

      this.logger.log(
        `Container ${id} marked as deleted in database (runner may not have had it)`,
      );
      return {
        message: 'Container deleted successfully (runner may not have had it)',
      };
    }
  }
}
