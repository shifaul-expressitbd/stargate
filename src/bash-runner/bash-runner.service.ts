import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SgtmRegionService } from '../sgtm-region/sgtm-region.service';
import WebSocket from 'ws';
import type { WebSocket as WebSocketType } from 'ws';
import {
  DEFAULT_REGION,
  RegionConfig,
  RegionKey,
} from '../config/region.types';

// Define message interfaces for type safety
interface CommandMessage {
  commandId: string;
  action: string;
  containerId?: string;
  name?: string;
  subdomain?: string | undefined;
  config?: string | undefined;
  lines?: number;
  [key: string]: any;
}

interface StatusMessage {
  status: string;
  error?: string;
  [key: string]: any;
}

interface ErrorMessage {
  error: string;
  [key: string]: any;
}

interface CommandResultData {
  success: boolean;
  exitCode: number;
  message?: string;
  containerId?: string;
  [key: string]: any;
}

export interface StandardizedResponse {
  success: boolean;
  message: string;
  data?: {
    commandId: string;
    exitCode: number;
    executionTime: number;
    containerId?: string;
  };
  error?: {
    code: string;
    details: string;
  };
}

interface CommandResultMessage {
  type: 'result';
  commandId: string;
  data: CommandResultData;
  [key: string]: any;
}

export interface CommandExecutionResult {
  success: boolean;
  exitCode: number;
  message?: string;
  commandId: string;
  action: string;
  containerId?: string;
  executionTime: number;
  [key: string]: any;
}

@Injectable()
export class BashRunnerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(BashRunnerService.name);
  private ws: WebSocketType | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectTimeout = 3000;
  private connectionTimeout: NodeJS.Timeout | null = null;
  private pingInterval: NodeJS.Timeout | null = null;
  private readonly PING_INTERVAL = 30000; // 30 seconds
  private messageHandlers = new Map<string, (data: any) => void>();
  private commandResolvers = new Map<
    string,
    {
      resolve: (value: any) => void;
      reject: (reason?: any) => void;
      timeout: NodeJS.Timeout;
    }
  >();
  private messageInterceptors = new Set<(message: any) => void>();
  private resultMessageInterceptors = new Set<
    (data: CommandResultData, commandId: string) => void
  >();
  private connectionStatus: 'connecting' | 'connected' | 'disconnected' =
    'disconnected';
  private connectionPromise: Promise<void> | null = null;
  private connectionResolve: (() => void) | null = null;
  private connectionReject: ((error: Error) => void) | null = null;

  constructor(
    private readonly configService: ConfigService,
    private readonly sgtmRegionService: SgtmRegionService,
  ) {
    this.logger.log('BashRunnerService initialized');
    // Add default result message logging
    this.addDefaultResultLogger();
  }

  /**
   * Get configuration for a specific region from database
   */
  async getConfigForRegion(region: RegionKey): Promise<RegionConfig> {
    try {
      const regionData = await this.sgtmRegionService.findByKey(region);

      if (!regionData) {
        throw new Error(
          `Configuration for region '${region}' not found in database`,
        );
      }

      if (!regionData.isActive) {
        throw new Error(
          `Region '${region}' (${regionData.name}) is currently inactive`,
        );
      }

      if (!regionData.apiUrl || !regionData.apiKey) {
        throw new Error(
          `Region '${region}' (${regionData.name}) is not properly configured. Missing API URL or API key.`,
        );
      }
      return {
        name: regionData.name,
        apiUrl: regionData.apiUrl,
        apiKey: regionData.apiKey,
        default: regionData.isDefault,
      };

    } catch (error) {
      this.logger.error(`Failed to get config for region '${region}':`, error);
      throw error;
    }
  }

  /**
   * Connect to a specific region's bash runner service
   */
  private async connectToRegion(
    region: RegionKey = DEFAULT_REGION,
  ): Promise<void> {
    if (this.connectionStatus === 'connected') {
      this.logger.log(
        `Already connected to bash runner service (region: ${region})`,
      );
      return;
    }

    if (this.connectionStatus === 'connecting') {
      this.logger.log('Connection already in progress, waiting...');
      return this.getConnectionPromise();
    }

    this.connectionStatus = 'connecting';
    this.logger.log(
      `Attempting to connect to bash runner service (region: ${region})...`,
    );

    // Clear any existing connection promise
    this.connectionPromise = new Promise<void>((resolve, reject) => {
      this.connectionResolve = resolve;
      this.connectionReject = reject;
    });

    const regionConfig = await this.getConfigForRegion(region);

    this.logger.log(
      `Connecting to runner service at ${regionConfig.apiUrl} (region: ${regionConfig.name})`,
    );

    try {
      this.ws = new WebSocket(`${regionConfig.apiUrl}?apiKey=${regionConfig.apiKey}`);

      this.ws.on('open', () => {
        this.logger.log(
          `✅ Connected to runner service (region: ${regionConfig.name})`,
        );
        this.reconnectAttempts = 0;
        this.connectionStatus = 'connected';

        if (this.connectionResolve) {
          this.connectionResolve();
          this.connectionResolve = null;
          this.connectionReject = null;
        }
      });

      this.ws.on('message', (data: WebSocket.Data) => {
        try {
          const message = JSON.parse(data.toString());
          this.logger.debug(
            `Received message from runner (${regionConfig.name}): ${JSON.stringify(message)}`,
          );

          // Call general message interceptors first
          this.messageInterceptors.forEach((interceptor) => {
            try {
              interceptor(message);
            } catch (error) {
              this.logger.error('Error in message interceptor:', error);
            }
          });

          // Handle system messages
          if (message.type === 'ping') {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
              this.ws.pong();
            }
            return;
          }

          if (message.type === 'pong') {
            this.logger.debug(
              `Received pong from runner service (${regionConfig.name})`,
            );
            return;
          }

          // Handle responses from bash-runner service
          if (message.type === 'result' && message.commandId) {
            // Handle container-specific result messages
            if (
              message.commandId.startsWith('create-') ||
              message.commandId.startsWith('run-') ||
              message.commandId.startsWith('stop-') ||
              message.commandId.startsWith('delete-')
            ) {
              // Emit container-specific result event
              const containerResultEvent = `container-result:${message.commandId}`;
              const handler = this.messageHandlers.get(containerResultEvent);
              if (handler) {
                try {
                  handler(message.data);
                } catch (error) {
                  this.logger.error(
                    `Error handling container result event ${containerResultEvent}:`,
                    error,
                  );
                }
              }
            }

            const resolver = this.commandResolvers.get(message.commandId);
            if (resolver) {
              clearTimeout(resolver.timeout);
              this.commandResolvers.delete(message.commandId);

              // Extract and validate result data
              const resultData = message.data as CommandResultData;

              // Call result message interceptors
              this.resultMessageInterceptors.forEach((interceptor) => {
                try {
                  interceptor(resultData, message.commandId);
                } catch (error) {
                  this.logger.error(
                    'Error in result message interceptor:',
                    error,
                  );
                }
              });

              if (this.validateResultData(resultData)) {
                const executionResult = this.createExecutionResult(
                  message.commandId,
                  resultData,
                  message.commandId, // The action is stored as commandId in the sent message
                );

                this.logger.log(
                  `✅ Command ${message.commandId} completed: success=${executionResult.success}, exitCode=${executionResult.exitCode}`,
                );

                if (executionResult.message) {
                  this.logger.debug(
                    `Command message: ${executionResult.message}`,
                  );
                }

                resolver.resolve(executionResult);
              } else {
                // Handle malformed result data with proper error
                this.logger.error(
                  `❌ Received malformed result data for command ${message.commandId}:`,
                  resultData,
                );

                const error = new Error(
                  `Command ${message.commandId} returned malformed result data`,
                );
                resolver.reject(error);
              }
            } else {
              this.logger.warn(
                `Received result for unknown command: ${message.commandId}`,
              );
            }
          } else if (message.type === 'error' && message.commandId) {
            this.logger.debug(
              `Processing error message for command: ${message.commandId}`,
            );

            const resolver = this.commandResolvers.get(message.commandId);
            if (resolver) {
              clearTimeout(resolver.timeout);
              this.commandResolvers.delete(message.commandId);

              const errorMessage =
                message.data?.error || message.data || 'Command failed';

              this.logger.error(
                `❌ Command ${message.commandId} failed: ${errorMessage}`,
              );

              const error = new Error(
                `Command ${message.commandId} failed: ${errorMessage}`,
              );
              resolver.reject(error);
            } else {
              this.logger.warn(
                `⚠️  Received error for unknown command: ${message.commandId}`,
              );
            }
          } else if (message.type === 'stdout' && message.commandId) {
            // Convert stdout messages to container-status events for container operations
            const eventType = `container-status:${message.commandId}`;
            const handler = this.messageHandlers.get(eventType);
            if (handler) {
              try {
                handler({ status: 'running', data: message.data });
              } catch (error) {
                this.logger.error(
                  `Error handling stdout event ${eventType}:`,
                  error,
                );
              }
            }
          } else if (message.type === 'stderr' && message.commandId) {
            // Convert stderr messages to container error events
            const eventType = `container-stderr:${message.commandId}`;
            const handler = this.messageHandlers.get(eventType);
            if (handler) {
              try {
                handler(message.data);
              } catch (error) {
                this.logger.error(
                  `Error handling stderr event ${eventType}:`,
                  error,
                );
              }
            }
          }
        } catch (error) {
          this.logger.error('Error processing message:', error);
        }
      });

      this.ws.on('error', (error) => {
        this.logger.error(`WebSocket error (${regionConfig.name}):`, error);
        this.handleConnectionError(error);
      });

      this.ws.on('close', (code, reason) => {
        this.logger.warn(
          `WebSocket closed (${regionConfig.name}, code: ${code}, reason: ${reason})`,
        );
        this.handleConnectionClose(code, reason);
      });

      // Set connection timeout
      this.connectionTimeout = setTimeout(() => {
        if (this.connectionStatus !== 'connected') {
          const error = new Error('Connection timeout');
          this.logger.error(error.message);
          this.connectionStatus = 'disconnected';

          if (this.ws) {
            this.ws.terminate();
            this.ws = null;
          }

          if (this.connectionReject) {
            this.connectionReject(error);
            this.connectionResolve = null;
            this.connectionReject = null;
          }

          this.reconnect();
        }
      }, 10000);

      return this.connectionPromise;
    } catch (error) {
      this.logger.error('Connection setup error:', error);
      this.connectionStatus = 'disconnected';

      if (this.connectionReject) {
        this.connectionReject(error);
        this.connectionResolve = null;
        this.connectionReject = null;
      }

      throw error;
    }
  }

  async onModuleInit() {
    this.logger.log('Initializing BashRunnerService...');
    try {
      await this.connectToRegion(); // Connect to default region
      // Set up ping/pong to keep connection alive
      this.setupPingInterval();
    } catch (error) {
      this.logger.error(
        'Failed to connect to bash runner service during initialization:',
        error,
      );
      this.logger.warn(
        'Application will continue in degraded mode. Container operations will not be available.',
      );
      // Don't rethrow - let the application start in degraded mode
    }
  }

  onModuleDestroy() {
    this.logger.log('Cleaning up BashRunnerService...');
    this.clearConnectionTimers();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.connectionStatus = 'disconnected';
  }

  private clearConnectionTimers() {
    if (this.connectionTimeout) {
      clearTimeout(this.connectionTimeout);
      this.connectionTimeout = null;
    }
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  private setupPingInterval() {
    this.clearConnectionTimers();

    this.pingInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        try {
          this.ws.ping();
          this.logger.debug('Sent ping to runner service');
        } catch (error) {
          this.logger.error('Error sending ping:', error);
          this.handleConnectionError(new Error('Ping failed'));
        }
      } else {
        this.logger.warn('Cannot send ping, WebSocket not open');
        this.reconnect();
      }
    }, this.PING_INTERVAL);
  }

  private async connect(): Promise<void> {
    if (this.connectionStatus === 'connected') {
      this.logger.log('Already connected to runner service');
      return;
    }

    if (this.connectionStatus === 'connecting') {
      this.logger.log('Connection already in progress, waiting...');
      return this.getConnectionPromise();
    }

    this.connectionStatus = 'connecting';
    this.logger.log('Attempting to connect to runner service...');

    // Clear any existing connection promise
    this.connectionPromise = new Promise<void>((resolve, reject) => {
      this.connectionResolve = resolve;
      this.connectionReject = reject;
    });

    const runnerApiUrl = this.configService.get('BASH_RUNNER_API_URL');
    const apiKey = this.configService.get('BASH_RUNNER_API_KEY');

    if (!runnerApiUrl) {
      const error = new Error('BASH_RUNNER_API_URL is not configured');
      this.logger.error(error.message);
      this.connectionStatus = 'disconnected';
      if (this.connectionReject) this.connectionReject(error);
      throw error;
    }

    if (!apiKey) {
      const error = new Error('BASH_RUNNER_API_KEY is not configured');
      this.logger.error(error.message);
      this.connectionStatus = 'disconnected';
      if (this.connectionReject) this.connectionReject(error);
      throw error;
    }

    this.logger.log(`Connecting to runner service at ${runnerApiUrl}`);

    try {
      this.ws = new WebSocket(`${runnerApiUrl}?apiKey=${apiKey}`);

      this.ws.on('open', () => {
        this.logger.log('✅ Connected to runner service');
        this.reconnectAttempts = 0;
        this.connectionStatus = 'connected';

        if (this.connectionResolve) {
          this.connectionResolve();
          this.connectionResolve = null;
          this.connectionReject = null;
        }
      });

      this.ws.on('message', (data: WebSocket.Data) => {
        try {
          const message = JSON.parse(data.toString());
          this.logger.debug(
            `Received message from runner: ${JSON.stringify(message)}`,
          );

          // Call general message interceptors first
          this.messageInterceptors.forEach((interceptor) => {
            try {
              interceptor(message);
            } catch (error) {
              this.logger.error('Error in message interceptor:', error);
            }
          });

          // Handle system messages
          if (message.type === 'ping') {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
              this.ws.pong();
            }
            return;
          }

          if (message.type === 'pong') {
            this.logger.debug('Received pong from runner service');
            return;
          }

          // Handle responses from bash-runner service
          if (message.type === 'result' && message.commandId) {
            // Handle container-specific result messages
            if (
              message.commandId.startsWith('create-') ||
              message.commandId.startsWith('run-') ||
              message.commandId.startsWith('stop-') ||
              message.commandId.startsWith('delete-')
            ) {
              // Emit container-specific result event
              const containerResultEvent = `container-result:${message.commandId}`;
              const handler = this.messageHandlers.get(containerResultEvent);
              if (handler) {
                try {
                  handler(message.data);
                } catch (error) {
                  this.logger.error(
                    `Error handling container result event ${containerResultEvent}:`,
                    error,
                  );
                }
              }
            }

            const resolver = this.commandResolvers.get(message.commandId);
            if (resolver) {
              clearTimeout(resolver.timeout);
              this.commandResolvers.delete(message.commandId);

              // Extract and validate result data
              const resultData = message.data as CommandResultData;

              // Call result message interceptors
              this.resultMessageInterceptors.forEach((interceptor) => {
                try {
                  interceptor(resultData, message.commandId);
                } catch (error) {
                  this.logger.error(
                    'Error in result message interceptor:',
                    error,
                  );
                }
              });

              if (this.validateResultData(resultData)) {
                const executionResult = this.createExecutionResult(
                  message.commandId,
                  resultData,
                  message.commandId, // The action is stored as commandId in the sent message
                );

                this.logger.log(
                  `✅ Command ${message.commandId} completed: success=${executionResult.success}, exitCode=${executionResult.exitCode}`,
                );

                if (executionResult.message) {
                  this.logger.debug(
                    `Command message: ${executionResult.message}`,
                  );
                }

                resolver.resolve(executionResult);
              } else {
                // Handle malformed result data with proper error
                this.logger.error(
                  `❌ Received malformed result data for command ${message.commandId}:`,
                  resultData,
                );

                const error = new Error(
                  `Command ${message.commandId} returned malformed result data`,
                );
                resolver.reject(error);
              }
            } else {
              this.logger.warn(
                `Received result for unknown command: ${message.commandId}`,
              );
            }
          } else if (message.type === 'error' && message.commandId) {
            this.logger.debug(
              `Processing error message for command: ${message.commandId}`,
            );

            const resolver = this.commandResolvers.get(message.commandId);
            if (resolver) {
              clearTimeout(resolver.timeout);
              this.commandResolvers.delete(message.commandId);

              const errorMessage =
                message.data?.error || message.data || 'Command failed';

              this.logger.error(
                `❌ Command ${message.commandId} failed: ${errorMessage}`,
              );

              const error = new Error(
                `Command ${message.commandId} failed: ${errorMessage}`,
              );
              resolver.reject(error);
            } else {
              this.logger.warn(
                `⚠️  Received error for unknown command: ${message.commandId}`,
              );
            }
          } else if (message.type === 'stdout' && message.commandId) {
            // Convert stdout messages to container-status events for container operations
            const eventType = `container-status:${message.commandId}`;
            const handler = this.messageHandlers.get(eventType);
            if (handler) {
              try {
                handler({ status: 'running', data: message.data });
              } catch (error) {
                this.logger.error(
                  `Error handling stdout event ${eventType}:`,
                  error,
                );
              }
            }
          } else if (message.type === 'stderr' && message.commandId) {
            // Convert stderr messages to container error events
            const eventType = `container-stderr:${message.commandId}`;
            const handler = this.messageHandlers.get(eventType);
            if (handler) {
              try {
                handler(message.data);
              } catch (error) {
                this.logger.error(
                  `Error handling stderr event ${eventType}:`,
                  error,
                );
              }
            }
          }
        } catch (error) {
          this.logger.error('Error processing message:', error);
        }
      });

      this.ws.on('error', (error) => {
        this.logger.error('WebSocket error:', error);
        this.handleConnectionError(error);
      });

      this.ws.on('close', (code, reason) => {
        this.logger.warn(`WebSocket closed (code: ${code}, reason: ${reason})`);
        this.handleConnectionClose(code, reason);
      });

      // Set connection timeout
      this.connectionTimeout = setTimeout(() => {
        if (this.connectionStatus !== 'connected') {
          const error = new Error('Connection timeout');
          this.logger.error(error.message);
          this.connectionStatus = 'disconnected';

          if (this.ws) {
            this.ws.terminate();
            this.ws = null;
          }

          if (this.connectionReject) {
            this.connectionReject(error);
            this.connectionResolve = null;
            this.connectionReject = null;
          }

          this.reconnect();
        }
      }, 10000);

      return this.connectionPromise;
    } catch (error) {
      this.logger.error('Connection setup error:', error);
      this.connectionStatus = 'disconnected';

      if (this.connectionReject) {
        this.connectionReject(error);
        this.connectionResolve = null;
        this.connectionReject = null;
      }

      throw error;
    }
  }

  private getConnectionPromise(): Promise<void> {
    if (!this.connectionPromise) {
      this.connectionPromise = new Promise<void>((resolve, reject) => {
        this.connectionResolve = resolve;
        this.connectionReject = reject;
      });
    }
    return this.connectionPromise;
  }

  private handleConnectionError(error: Error) {
    this.logger.error('Connection error:', error);

    if (this.connectionReject && this.connectionStatus === 'connecting') {
      this.connectionReject(error);
      this.connectionResolve = null;
      this.connectionReject = null;
    }

    this.reconnect();
  }

  private handleConnectionClose(code: number, reason: Buffer) {
    if (this.connectionReject && this.connectionStatus === 'connecting') {
      const error = new Error(
        `Connection closed (code: ${code}, reason: ${reason.toString()})`,
      );
      this.connectionReject(error);
      this.connectionResolve = null;
      this.connectionReject = null;
    }
    this.connectionStatus = 'disconnected';

    // Don't reconnect for normal closure codes
    if (code !== 1000 && code !== 1001) {
      this.reconnect();
    }
  }

  private reconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.logger.error(
        `Max reconnection attempts (${this.maxReconnectAttempts}) reached. Entering degraded mode.`,
      );
      this.connectionStatus = 'disconnected';
      this.logger.warn(
        'BashRunnerService is in degraded mode. Container operations will fail gracefully.',
      );
      return;
    }

    this.reconnectAttempts++;
    this.connectionStatus = 'disconnected';

    this.logger.log(
      `Attempting to reconnect (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})...`,
    );

    setTimeout(async () => {
      try {
        await this.connect();
        this.logger.log('Reconnection successful');
      } catch (error) {
        this.logger.error('Reconnection failed:', error);
        // Don't throw - let it continue to degraded mode
      }
    }, this.reconnectTimeout * this.reconnectAttempts);
  }

  isConnected(): boolean {
    return (
      this.connectionStatus === 'connected' &&
      this.ws !== null &&
      this.ws.readyState === WebSocket.OPEN
    );
  }

  isAvailable(): boolean {
    return this.isConnected() || this.connectionStatus === 'connecting';
  }

  getConnectionStatus(): string {
    return `Status: ${this.connectionStatus}, WebSocket readyState: ${this.ws ? this.ws.readyState : 'null'}`;
  }

  /**
   * Get health information about the bash runner service
   * Uses fallback pattern: environment variables first, then database
   */
  async getHealthInfo(): Promise<any> {
    try {
      // Add environment-based configuration info (primary source)
      const envConfig = {
        BASH_RUNNER_API_URL: this.configService.get('BASH_RUNNER_API_URL') ? 'configured' : 'not set',
        BASH_RUNNER_API_KEY: this.configService.get('BASH_RUNNER_API_KEY') ? 'configured' : 'not set',
        BASH_RUNNER_API_URL_INDIA: this.configService.get('BASH_RUNNER_API_URL_INDIA') ? 'configured' : 'not set',
        BASH_RUNNER_API_KEY_INDIA: this.configService.get('BASH_RUNNER_API_KEY_INDIA') ? 'configured' : 'not set',
      };

      const healthInfo = {
        service: 'bash-runner',
        timestamp: new Date().toISOString(),
        connection: {
          status: this.connectionStatus,
          isConnected: this.isConnected(),
          isAvailable: this.isAvailable(),
          reconnectAttempts: this.reconnectAttempts,
          maxReconnectAttempts: this.maxReconnectAttempts,
          envConfig: envConfig,
        },
        regions: {},
        activeRegion: null,
      };

      // Try to get region information from database (fallback pattern)
      try {
        const regions = await this.sgtmRegionService.findAll();
        healthInfo.regions = regions.reduce((acc: any, region: any) => {
          acc[region.key] = {
            name: region.name,
            isActive: region.isActive,
            isDefault: region.isDefault,
            hasApiConfig: !!(region.apiUrl && region.apiKey),
          };
          if (region.isDefault && region.isActive) {
            healthInfo.activeRegion = region.key;
          }
          return acc;
        }, {});
      } catch (dbError) {
        this.logger.warn('Could not fetch region data from database:', dbError);
        healthInfo.regions = {
          error: 'Database unavailable',
          fallback: 'Using environment configuration only',
        };
      }

      return healthInfo;
    } catch (error) {
      this.logger.error('Failed to get health info:', error);
      throw new Error('Health check failed');
    }
  }

  /**
   * Retry connection to the bash runner service
   * Uses fallback pattern: tries current region, falls back to default
   */
  async retryConnection(): Promise<boolean> {
    try {
      this.logger.log('Manual retry connection requested');

      // Reset reconnect attempts for manual retry
      this.reconnectAttempts = 0;

      // First try to connect to current/default region
      try {
        await this.connectToRegion();
        if (this.isConnected()) {
          this.logger.log('✅ Manual retry connection successful');
          return true;
        }
      } catch (error) {
        this.logger.warn('Failed to connect to current region, trying fallback:', error);
      }

      // Fallback: try to connect with direct environment configuration
      try {
        const runnerApiUrl = this.configService.get('BASH_RUNNER_API_URL');
        const apiKey = this.configService.get('BASH_RUNNER_API_KEY');

        if (runnerApiUrl && apiKey) {
          await this.connect();
          if (this.isConnected()) {
            this.logger.log('✅ Manual retry connection successful (fallback)');
            return true;
          }
        } else {
          this.logger.warn('Environment configuration not available for fallback');
        }
      } catch (fallbackError) {
        this.logger.error('Fallback connection also failed:', fallbackError);
      }

      this.logger.error('❌ Manual retry connection failed');
      return false;
    } catch (error) {
      this.logger.error('Error during manual retry connection:', error);
      return false;
    }
  }

  /**
   * Validates incoming WebSocket result message data
   */
  private validateResultData(resultData: any): boolean {
    if (!resultData || typeof resultData !== 'object') {
      this.logger.warn('Result data is not a valid object:', resultData);
      return false;
    }

    if (typeof resultData.success !== 'boolean') {
      this.logger.warn(
        'Result data success field is not a boolean:',
        resultData.success,
      );
      return false;
    }

    if (typeof resultData.exitCode !== 'number') {
      this.logger.warn(
        'Result data exitCode is not a number:',
        resultData.exitCode,
      );
      return false;
    }

    return true;
  }

  /**
   * Creates a standardized execution result from WebSocket message data
   */
  private createExecutionResult(
    commandId: string,
    resultData: CommandResultData,
    action: string,
  ): CommandExecutionResult {
    return {
      success: resultData.success,
      exitCode: resultData.exitCode || (resultData.success ? 0 : 1),
      message: resultData.message,
      commandId: commandId,
      action: action,
      executionTime: Date.now(),
      containerId: resultData.containerId,
      ...(resultData as any),
    };
  }

  async sendCommand(
    commandId: string,
    message: CommandMessage,
    region: RegionKey = DEFAULT_REGION,
  ): Promise<void> {
    console.log(
      `[BASH_RUNNER_DEBUG] Preparing to send command with ID: ${commandId}`,
    );
    console.log(`[BASH_RUNNER_DEBUG] Command details:`, {
      action: message.action,
      containerId: message.containerId,
      hasSubdomain: !!message.subdomain,
      hasConfig: !!message.config,
      lines: message.lines,
    });

    try {
      // Check if service is available
      if (!this.isAvailable()) {
        const errorMessage =
          'Bash runner service is currently unavailable. The service may be starting up or experiencing issues. Please try again later.';
        console.log(`[BASH_RUNNER_DEBUG] ${errorMessage}`);
        throw new Error(errorMessage);
      }

      // Ensure we're connected to the correct region before sending
      if (!this.isConnected()) {
        console.log(
          `[BASH_RUNNER_DEBUG] WebSocket not connected, attempting to connect to region ${region}...`,
        );
        await this.connectToRegion(region);

        // Double-check connection after connect attempt
        if (!this.isConnected()) {
          throw new Error(
            `Failed to establish WebSocket connection to region ${region}`,
          );
        }
      }

      console.log(
        `[BASH_RUNNER_DEBUG] Sending command ${commandId} to runner service...`,
      );

      return new Promise((resolve, reject) => {
        // Set up a timeout for the command
        const timeout = setTimeout(() => {
          this.commandResolvers.delete(commandId);
          reject(new Error(`Command ${commandId} timed out`));
        }, 30000); // 30 second timeout

        this.commandResolvers.set(commandId, { resolve, reject, timeout });

        try {
          if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            // Format message according to bash-runner's expected format
            // The bash-runner expects the commandId to be the actual command name, not a unique ID
            const fullMessage = {
              type: 'runCommand',
              commandId: message.action, // Use the action as the commandId
              args: {
                containerId: message.containerId,
                name: message.name,
                subdomain: message.subdomain,
                config: message.config,
                lines: message.lines,
              },
              timeout: 30000,
            };

            this.ws.send(JSON.stringify(fullMessage));
            console.log(
              `[BASH_RUNNER_DEBUG] Command ${commandId} successfully sent to WebSocket`,
            );
            console.log(
              `[BASH_RUNNER_DEBUG] Message format:`,
              JSON.stringify(fullMessage, null, 2),
            );
            resolve();
          } else {
            this.commandResolvers.delete(commandId);
            clearTimeout(timeout);
            reject(new Error('WebSocket is not open'));
          }
        } catch (error) {
          this.commandResolvers.delete(commandId);
          clearTimeout(timeout);
          console.error(
            `[BASH_RUNNER_DEBUG] Error sending command ${commandId}:`,
            error,
          );
          reject(error);
        }
      });
    } catch (error) {
      console.error(
        `[BASH_RUNNER_DEBUG] Failed to prepare command ${commandId}:`,
        error,
      );
      throw error;
    } finally {
      console.log(
        `[BASH_RUNNER_DEBUG] Command ${commandId} processing completed`,
      );
    }
  }

  onMessage(eventType: string, handler: (data: any) => void): () => void {
    console.log(
      `[BASH_RUNNER_DEBUG] Registering handler for event: ${eventType}`,
    );
    this.messageHandlers.set(eventType, handler);

    return () => {
      console.log(
        `[BASH_RUNNER_DEBUG] Removing handler for event: ${eventType}`,
      );
      this.messageHandlers.delete(eventType);
    };
  }

  offMessage(eventType: string) {
    console.log(`[BASH_RUNNER_DEBUG] Removing handler for event: ${eventType}`);
    this.messageHandlers.delete(eventType);
  }

  /**
   * Register a message interceptor that gets called for ALL WebSocket messages
   */
  onAnyMessage(interceptor: (message: any) => void): () => void {
    console.log(`[BASH_RUNNER_DEBUG] Registering general message interceptor`);
    this.messageInterceptors.add(interceptor);

    return () => {
      console.log(`[BASH_RUNNER_DEBUG] Removing general message interceptor`);
      this.messageInterceptors.delete(interceptor);
    };
  }

  /**
   * Register a specific interceptor for result messages
   */
  onResultMessage(
    interceptor: (data: CommandResultData, commandId: string) => void,
  ): () => void {
    console.log(`[BASH_RUNNER_DEBUG] Registering result message interceptor`);
    this.resultMessageInterceptors.add(interceptor);

    return () => {
      console.log(`[BASH_RUNNER_DEBUG] Removing result message interceptor`);
      this.resultMessageInterceptors.delete(interceptor);
    };
  }

  /**
   * Add default console logging for result messages
   */
  private addDefaultResultLogger() {
    this.onResultMessage((data, commandId) => {
      console.log(`🎯 INTERCEPTED RESULT MESSAGE:`);
      console.log(`   Command ID: ${commandId}`);
      console.log(`   Success: ${data.success}`);
      console.log(`   Exit Code: ${data.exitCode}`);
      console.log(`   Message: ${data.message || 'N/A'}`);
      console.log(`   Full Data:`, JSON.stringify(data, null, 2));
      console.log(`   Timestamp: ${new Date().toISOString()}`);
      console.log(`   ---`);
    });
  }

  /**
   * Test method to simulate receiving a result message
   * This can be used for testing the interception system
   */
  testResultMessage(
    data: CommandResultData,
    commandId: string = 'test-command',
  ) {
    console.log('🧪 [TEST] Simulating result message interception...');

    // Trigger all result message interceptors
    this.resultMessageInterceptors.forEach((interceptor) => {
      try {
        interceptor(data, commandId);
      } catch (error) {
        this.logger.error('Error in test result message interceptor:', error);
      }
    });

    console.log('✅ [TEST] Result message interception test completed');
  }
}
