import { Inject, Logger, forwardRef } from '@nestjs/common';
import {
  ConnectedSocket,
  MessageBody,
  OnGatewayConnection,
  OnGatewayDisconnect,
  OnGatewayInit,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { UsersService } from '../users/users.service';
import { BashRunnerService } from './bash-runner.service';

interface RunCommandPayload {
  commandId: string;
  args?: string[];
  timeout?: number;
}

interface AuthenticatedSocket extends Socket {
  user?: any;
  apiKey?: string;
}

@WebSocketGateway({
  path: '/api/bash-runner',
  cors: {
    origin: [
      'http://localhost:5173',
      'http://localhost:4000',
      'http://localhost:3000',
      'https://accounts.google.com',
    ],
    credentials: true,
  },
})
export class BashRunnerGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect
{
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(BashRunnerGateway.name);

  constructor(
    @Inject(forwardRef(() => BashRunnerService))
    private readonly bashRunnerService: BashRunnerService,
    private readonly usersService: UsersService,
  ) {}

  afterInit(server: Server) {
    this.logger.log('Socket.IO server initialized');
  }

  async handleConnection(client: AuthenticatedSocket, ...args: any[]) {
    try {
      // Try API key authentication first (for bash-runner compatibility)
      const apiKey = client.handshake.query.apiKey as string;
      let user: any = null;

      if (apiKey) {
        user = await this.usersService.findByApiKey(apiKey);
      }

      // If API key authentication fails, try JWT token from auth header
      if (!user) {
        const token =
          client.handshake.auth?.token ||
          client.handshake.headers?.authorization?.replace('Bearer ', '');
        if (token) {
          try {
            // Note: JWT verification would need to be implemented based on your auth system
            // For now, we'll skip detailed JWT validation and allow connection for development
            this.logger.warn(
              'JWT authentication not fully implemented - allowing connection for development',
            );
            user = {
              id: 'jwt-user',
              email: 'jwt@example.com',
              name: 'JWT User',
            };
          } catch (error) {
            this.logger.error('Invalid JWT token:', error);
          }
        }
      }

      if (!user) {
        this.logger.error(
          'No valid authentication provided in Socket.IO connection',
        );
        client.disconnect();
        return;
      }

      // Store user info in socket
      client.user = user;
      client.apiKey = apiKey;

      this.logger.log(
        `Socket.IO client connected: ${client.id} (user: ${user.id})`,
      );

      // Send connection confirmation
      client.emit('connected', {
        status: 200,
        message: 'Socket.IO connection established',
        user: { id: user.id, email: user.email },
      });
    } catch (error) {
      this.logger.error('Error during Socket.IO connection:', error);
      client.disconnect();
    }
  }

  handleDisconnect(client: AuthenticatedSocket) {
    this.logger.log(`Socket.IO client disconnected: ${client.id}`);
  }

  @SubscribeMessage('runCommand')
  async handleRunCommand(
    @MessageBody() payload: RunCommandPayload,
    @ConnectedSocket() client: AuthenticatedSocket,
  ) {
    try {
      const { commandId, args, timeout } = payload;

      if (!commandId) {
        client.emit('error', {
          status: 400,
          error: 'commandId is required',
        });
        return;
      }

      this.logger.log(
        `Received Socket.IO command: ${commandId} from user: ${client.user?.id}`,
      );

      // Create a unique command ID for tracking
      const uniqueCommandId = `${commandId}_${Date.now()}_${client.id}`;

      // Set up real-time output streaming for this command
      const outputHandler = this.bashRunnerService.onMessage(
        `stdout:${uniqueCommandId}`,
        (data) => {
          client.emit('output', {
            status: 200,
            type: 'stdout',
            data: data,
            commandId: uniqueCommandId,
          });
        },
      );

      const errorHandler = this.bashRunnerService.onMessage(
        `stderr:${uniqueCommandId}`,
        (data) => {
          client.emit('output', {
            status: 200,
            type: 'stderr',
            data: data,
            commandId: uniqueCommandId,
          });
        },
      );

      try {
        // Execute the command and wait for result
        const result = await this.bashRunnerService.sendCommand(
          uniqueCommandId,
          {
            commandId: commandId, // Add the missing commandId property
            action: commandId,
            containerId: args?.[0], // Assuming first arg is containerId if present
            name: args?.[1], // Second arg as name if present
            user: client.user?.id,
            subdomain: args?.[2],
            config: args?.[3],
            lines: args?.[4] ? parseInt(args[4]) : undefined,
          },
        );

        // Send final result
        client.emit('result', {
          status: 200,
          data: result,
          commandId: uniqueCommandId,
        });
      } catch (error: any) {
        this.logger.error(`Command execution error: ${error.message}`);
        client.emit('error', {
          status: 500,
          error: error.message || 'Command execution failed',
          commandId: uniqueCommandId,
        });
      } finally {
        // Clean up handlers
        outputHandler();
        errorHandler();
      }
    } catch (error: any) {
      this.logger.error('Error handling runCommand:', error);
      client.emit('error', {
        status: 500,
        error: error.message || 'Internal server error',
      });
    }
  }

  @SubscribeMessage('ping')
  handlePing(@ConnectedSocket() client: AuthenticatedSocket) {
    client.emit('pong', { status: 200, timestamp: new Date().toISOString() });
  }

  @SubscribeMessage('getHealth')
  async handleGetHealth(@ConnectedSocket() client: AuthenticatedSocket) {
    try {
      const health = await this.bashRunnerService.getHealthInfo();
      client.emit('health', {
        status: 200,
        data: health,
      });
    } catch (error: any) {
      client.emit('error', {
        status: 500,
        error: error.message || 'Failed to get health info',
      });
    }
  }
}
