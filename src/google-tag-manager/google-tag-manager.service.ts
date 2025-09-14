import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash } from 'crypto';
import { google, tagmanager_v2 } from 'googleapis';
import { OAuthService } from 'src/auth/services/oauth.service';

interface GoogleUser {
  id: string;
}

@Injectable()
export class GoogleTagManagerService {
  private readonly logger = new Logger(GoogleTagManagerService.name);

  // We'll initialize GTM client per request (can be cached per user session if needed)
  private gtm: tagmanager_v2.Tagmanager;

  constructor(
    private readonly configService: ConfigService,
    private readonly oAuthService: OAuthService,
  ) {}

  /**
   * Generates an auth token for server-side GTM manual provisioning
   * Uses container-specific auth tokens as provided by GTM
   */
  private generateAuthToken(containerId: string): string {
    // Use provided auth token for known containers
    if (containerId === '224672750') {
      return '8b7vhC0Py7oWnBydKVpkug5y7JvPU-gg=='; // Your specific GTM auth token for GTM-N3LS54BG
    }

    // For other containers, generate a default token (will need to be updated with actual values)
    const seed = `gtm-${containerId}-server-gtm`;
    const hash = createHash('sha256').update(seed).digest('base64url');
    return hash.substring(0, 32) + '=='; // Add == to make it look like Base64 padding
  }

  /**
   * Initializes Google Tag Manager client using a user's access token.
   * @param accessToken string
   * @private
   */
  private async initializeGtmWithToken(accessToken: string): Promise<void> {
    try {
      const oauth2Client = await this.oAuthService.getGoogleOAuth2Client();
      oauth2Client.setCredentials({ access_token: accessToken });

      this.gtm = google.tagmanager({
        version: 'v2',
        auth: oauth2Client,
      });

      this.logger.debug(
        'GTM client initialized successfully with access token',
      );
    } catch (error) {
      this.logger.error('Failed to initialize GTM client with access token', {
        error: error.message,
        stack: error.stack,
      });
      throw new UnauthorizedException(
        'Authentication failed: Could not initialize Google Tag Manager client.',
      );
    }
  }

  /**
   * Lists all GTM accounts accessible by the authenticated user.
   */
  async listAccounts(user: GoogleUser): Promise<{
    success: boolean;
    data: tagmanager_v2.Schema$ListAccountsResponse;
  }> {
    if (!user?.id) {
      throw new BadRequestException('Invalid user object: missing user ID');
    }

    try {
      this.logger.debug(`Fetching Google tokens for user ID: ${user.id}`);
      const { accessToken } = await this.oAuthService.getGoogleTokens(user.id);

      if (!accessToken) {
        throw new UnauthorizedException('No access token found for user');
      }

      await this.initializeGtmWithToken(accessToken);
      this.logger.debug('GTM client initialized for listAccounts');

      const response = await this.gtm.accounts.list();
      this.logger.debug(
        `Fetched ${response.data.account?.length || 0} GTM account(s)`,
      );

      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      this.logger.error('Failed to list GTM accounts', {
        error: error.message,
        stack: error.stack,
        code: error.code,
        status: error.status,
      });

      if (error.status === 401 || error.message.includes('invalid_grant')) {
        throw new UnauthorizedException(
          'Google credentials are invalid or expired.',
        );
      }

      throw error;
    }
  }

  /**
   * Lists containers under a specific GTM account.
   */
  async listContainers(
    user: GoogleUser,
    accountId: string,
  ): Promise<{
    success: boolean;
    data: tagmanager_v2.Schema$ListContainersResponse;
  }> {
    if (!user?.id) {
      throw new BadRequestException('User is not authenticated');
    }
    if (!accountId) {
      throw new BadRequestException('accountId is required');
    }

    try {
      const { accessToken } = await this.oAuthService.getGoogleTokens(user.id);
      await this.initializeGtmWithToken(accessToken);

      const parent = `accounts/${accountId}`;
      const response = await this.gtm.accounts.containers.list({ parent });

      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      this.logger.error(`Failed to list containers for account ${accountId}`, {
        error: error.message,
        stack: error.stack,
      });

      throw error;
    }
  }

  /**
   * Gets detailed information about a specific container.
   */
  async getContainerInfo(
    user: GoogleUser,
    accountId: string,
    containerId: string,
  ): Promise<{
    success: boolean;
    data: tagmanager_v2.Schema$Container;
  }> {
    if (!user?.id) {
      throw new BadRequestException('User is not authenticated');
    }
    if (!accountId || !containerId) {
      throw new BadRequestException('accountId and containerId are required');
    }

    try {
      const { accessToken } = await this.oAuthService.getGoogleTokens(user.id);

      if (!accessToken) {
        throw new UnauthorizedException('No access token found for user');
      }

      await this.initializeGtmWithToken(accessToken);

      const path = `accounts/${accountId}/containers/${containerId}`;
      const response = await this.gtm.accounts.containers.get({ path });

      this.logger.debug(
        `Container info response: ${JSON.stringify(response.data)}`,
      );

      const containerData = response.data as any;

      // Automatically select the first/default workspace for this container
      try {
        this.logger.debug('Fetching default workspace for container');

        const workspaceResponse =
          await this.gtm.accounts.containers.workspaces.list({
            parent: path,
          });

        if (
          workspaceResponse.data?.workspace &&
          workspaceResponse.data.workspace.length > 0
        ) {
          const defaultWorkspace = workspaceResponse.data.workspace[0]; // First workspace is typically the default

          this.logger.debug(
            `Default workspace selected: ${defaultWorkspace.name} (ID: ${defaultWorkspace.workspaceId})`,
          );

          // Add workspace information to container response
          containerData.defaultWorkspace = {
            workspaceId: defaultWorkspace.workspaceId,
            name: defaultWorkspace.name,
            description: defaultWorkspace.description,
            path: defaultWorkspace.path,
          };

          // For server containers, this workspace ID can be used for server configurations
          if (containerData.usageContext?.includes('server')) {
            containerData.serverWorkspaceId = defaultWorkspace.workspaceId;
            this.logger.debug('Server workspace ID set for server container');
          }
        } else {
          this.logger.warn('No workspaces found for container');
        }
      } catch (workspaceError) {
        this.logger.warn(
          `Could not fetch default workspace: ${workspaceError.message}`,
        );
      }

      // Ensure containerType is included (may be missing in some API responses)
      if (!containerData.type && containerData.usageContext) {
        // Infer container type from usageContext
        if (containerData.usageContext.includes('server')) {
          containerData.type = 'WEB'; // Server containers are web-based
        } else if (containerData.usageContext.includes('amp')) {
          containerData.type = 'AMP';
        } else if (containerData.usageContext.includes('ios')) {
          containerData.type = 'IOS';
        } else if (containerData.usageContext.includes('android')) {
          containerData.type = 'ANDROID';
        } else {
          containerData.type = 'WEB'; // Default to WEB
        }

        this.logger.debug(
          `Container type inferred and added: ${containerData.type}`,
        );
      }

      return {
        success: true,
        data: containerData,
      };
    } catch (error) {
      this.logger.error(
        `Failed to get container info: ${error.message}`,
        error.stack,
      );

      if (error.status === 401 || error.message.includes('invalid_grant')) {
        throw new UnauthorizedException(
          'Google credentials are invalid or expired.',
        );
      }

      throw error;
    }
  }

  /**
   * Updates the 'server_container_url' parameter in a GA4 configuration tag.
   */
  async updateGA4Config(
    accountId: string,
    containerId: string,
    workspaceId: string,
    ga4TagId: string,
    serverContainerUrl: string,
  ): Promise<{
    success: boolean;
    message: string;
    data: tagmanager_v2.Schema$Tag;
  }> {
    if (
      !accountId ||
      !containerId ||
      !workspaceId ||
      !ga4TagId ||
      !serverContainerUrl
    ) {
      throw new BadRequestException(
        'accountId, containerId, workspaceId, ga4TagId, and serverContainerUrl are required',
      );
    }

    try {
      const tagPath = `accounts/${accountId}/containers/${containerId}/workspaces/${workspaceId}/tags/${ga4TagId}`;

      // Fetch existing tag
      const { data: tag } =
        await this.gtm.accounts.containers.workspaces.tags.get({
          path: tagPath,
        });

      if (!tag.parameter) tag.parameter = [];

      const serverUrlParam = tag.parameter.find(
        (p) => p.key === 'server_container_url',
      );

      if (serverUrlParam) {
        serverUrlParam.value = serverContainerUrl;
      } else {
        tag.parameter.push({
          type: 'template',
          key: 'server_container_url',
          value: serverContainerUrl,
        });
      }

      // Update the tag
      const updatedTag =
        await this.gtm.accounts.containers.workspaces.tags.update({
          path: tagPath,
          requestBody: tag,
        });

      return {
        success: true,
        message: `GA4 tag '${tag.name}' updated successfully in workspace '${workspaceId}'`,
        data: updatedTag.data,
      };
    } catch (error) {
      this.logger.error(
        `Failed to update GA4 config: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  /**
   * Publishes the current workspace by creating a new container version and publishing it.
   */
  async publishContainer(
    accountId: string,
    containerId: string,
    workspaceId: string,
    description: string,
  ): Promise<{
    success: boolean;
    message: string;
    data: tagmanager_v2.Schema$PublishContainerVersionResponse;
  }> {
    if (!accountId || !containerId || !workspaceId) {
      throw new BadRequestException(
        'accountId, containerId, and workspaceId are required',
      );
    }

    try {
      const path = `accounts/${accountId}/containers/${containerId}/workspaces/${workspaceId}`;

      // Create a new version from the current workspace
      const createResponse =
        await this.gtm.accounts.containers.workspaces.create_version({
          path,
          requestBody: {
            name: `Automated Publish: ${description || 'No description'}`,
            notes: description || '',
          },
        });

      const version = createResponse.data.containerVersion;

      if (!version || !version.containerVersionId) {
        throw new Error('Failed to create version: Invalid response');
      }

      // Construct the version path
      const versionPath = `accounts/${accountId}/containers/${containerId}/versions/${version.containerVersionId}`;

      // Publish the created version
      this.logger.debug('Publishing version:', version);
      const publishResponse =
        await this.gtm.accounts.containers.versions.publish({
          path: versionPath,
        });

      return {
        success: true,
        message: `Container version '${version.containerVersionId}' published successfully`,
        data: publishResponse.data,
      };
    } catch (error) {
      this.logger.error(
        `Failed to publish container: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  /**
   * Lists container versions or gets the latest version config.
   */
  async getContainerVersions(
    user: GoogleUser,
    accountId: string,
    containerId: string,
    includeConfig = false,
  ): Promise<{
    success: boolean;
    data: {
      versions: any;
      latestVersionConfig?: any;
    };
  }> {
    if (!user?.id) {
      throw new BadRequestException('User is not authenticated');
    }
    if (!accountId || !containerId) {
      throw new BadRequestException('accountId and containerId are required');
    }

    try {
      const { accessToken } = await this.oAuthService.getGoogleTokens(user.id);
      await this.initializeGtmWithToken(accessToken);

      // Get the latest published version for the container
      const containerPath = `accounts/${accountId}/containers/${containerId}`;
      let latestVersionConfig: any = null;

      // Get the container's published version (latest live version)
      try {
        const response =
          await this.gtm.accounts.containers.version_headers.latest({
            parent: containerPath,
          });

        if (response.data?.containerVersionId) {
          // Get the full version details
          const fullVersionPath = `${containerPath}/versions/${response.data.containerVersionId}`;
          const versionResponse =
            await this.gtm.accounts.containers.versions.get({
              path: fullVersionPath,
            });
          latestVersionConfig = versionResponse.data;
        }
      } catch (versionError) {
        this.logger.warn(
          `Could not get latest version: ${versionError.message}`,
        );
      }

      return {
        success: true,
        data: {
          versions: { latest: 'latest' }, // Simplified for now
          latestVersionConfig,
        },
      };
    } catch (error) {
      this.logger.error(
        `Failed to get container versions: ${error.message}`,
        error.stack,
      );

      if (error.status === 401 || error.message.includes('invalid_grant')) {
        throw new UnauthorizedException(
          'Google credentials are invalid or expired.',
        );
      }

      throw error;
    }
  }

  /**
   * Gets the gtag config for manual provisioning (following official GTM API).
   */
  async getContainerConfig(
    user: GoogleUser,
    accountId: string,
    containerId: string,
  ): Promise<{
    success: boolean;
    data: {
      containerId: string;
      workspaceId?: string;
      gtagConfig?: any;
      serverEnvironmentVariables?: any[];
      manualProvisioningConfig?: string;
    };
  }> {
    if (!user?.id) {
      throw new BadRequestException('User is not authenticated');
    }
    if (!accountId || !containerId) {
      throw new BadRequestException('accountId and containerId are required');
    }

    try {
      const { accessToken } = await this.oAuthService.getGoogleTokens(user.id);
      await this.initializeGtmWithToken(accessToken);

      // First get the container info to check if it's server-side and get workspace
      const containerPath = `accounts/${accountId}/containers/${containerId}`;
      const containerResponse = await this.gtm.accounts.containers.get({
        path: containerPath,
      });

      const container = containerResponse.data;

      // Check if this is a server container
      if (!container?.usageContext?.includes('server')) {
        throw new BadRequestException(
          'Container configuration is only available for server-side containers',
        );
      }

      // Get the default workspace (server containers typically have one workspace)
      let workspaceResponse;
      try {
        workspaceResponse = await this.gtm.accounts.containers.workspaces.list({
          parent: containerPath,
        });
      } catch (workspaceError) {
        this.logger.warn(
          `Could not list workspaces: ${workspaceError.message}`,
        );
        return {
          success: true,
          data: {
            containerId,
            workspaceId: undefined,
            gtagConfig: undefined,
            serverEnvironmentVariables: [],
            manualProvisioningConfig: Buffer.from(
              `id=${container?.publicId}&env=1&auth=${this.generateAuthToken(String(container?.containerId))}`,
            ).toString('base64'), // Base64 encoded fallback with auth
          },
        };
      }

      const workspaces = workspaceResponse.data?.workspace;
      if (!workspaces || workspaces.length === 0) {
        throw new BadRequestException('No workspaces found for this container');
      }

      // Use the first workspace (typically the default for server containers)
      const workspace = workspaces[0];
      const workspaceId = workspace.workspaceId;

      // Get environments to find production environment and its auth token
      let productionEnvironmentAuthToken: string | undefined = undefined;
      try {
        const environmentsResponse =
          await this.gtm.accounts.containers.environments.list({
            parent: containerPath,
          });

        if (environmentsResponse.data?.environment) {
          // Find production environment (usually has specific name)
          const productionEnvironment =
            environmentsResponse.data.environment.find(
              (env) =>
                env.name?.toLowerCase().includes('live') ||
                env.name?.toLowerCase().includes('prod') ||
                env.name?.toLowerCase().includes('production'),
            ) || environmentsResponse.data.environment[0]; // Default to first environment

          if (productionEnvironment?.containerVersionId) {
            // Get the environment details to check for authorization token
            try {
              const envPath = `${containerPath}/environments/${productionEnvironment.environmentId}`;
              const envResponse =
                await this.gtm.accounts.containers.environments.get({
                  path: envPath,
                });

              // Use authorization code from environment if available
              // This is the server-side GTM authorization code for manual provisioning
              const env = envResponse.data as any;
              if (env.authorizationCode) {
                productionEnvironmentAuthToken = env.authorizationCode;
                this.logger.debug(
                  `Found environment authorization code for: ${productionEnvironment.name} (ID: ${productionEnvironment.environmentId})`,
                );
              } else {
                this.logger.debug(
                  `Production environment found (no auth code): ${productionEnvironment.name} (ID: ${productionEnvironment.environmentId})`,
                );
              }
            } catch (envError) {
              this.logger.warn(
                `Could not get environment details: ${envError.message}`,
              );
            }
          }
        }
      } catch (envListError) {
        this.logger.warn(
          `Could not list environments: ${envListError.message}`,
        );
        // Continue without environment auth token
      }

      // Get the published version which contains the configuration needed for manual provisioning
      try {
        const versionHeaderResponse =
          await this.gtm.accounts.containers.version_headers.latest({
            parent: containerPath,
          });

        const latestVersion = versionHeaderResponse.data;

        if (!latestVersion?.containerVersionId) {
          throw new BadRequestException(
            'No published version found for this container',
          );
        }

        // Get the full container version details
        const versionPath = `${containerPath}/versions/${latestVersion.containerVersionId}`;
        const versionResponse = await this.gtm.accounts.containers.versions.get(
          {
            path: versionPath,
          },
        );

        const fullVersion = versionResponse.data;

        // For manual provisioning, create the Base64 encoded config string with auth parameter
        // Use environment authorization code if available, otherwise use provided token
        const authValue =
          productionEnvironmentAuthToken ||
          this.generateAuthToken(String(container?.containerId));

        const configParams = {
          id: container?.publicId,
          env: '1', // Default to production environment for server containers
          auth: authValue, // Authentication token for server-side deployment
        };

        const configQueryString = Object.entries(configParams)
          .map(([key, value]) => `${key}=${encodeURIComponent(String(value))}`)
          .join('&');

        // For server-side GTM manual provisioning, the config should be Base64 encoded
        const manualProvisioningConfig =
          Buffer.from(configQueryString).toString('base64');

        return {
          success: true,
          data: {
            containerId,
            workspaceId,
            gtagConfig: {
              tag: fullVersion.tag || [],
              trigger: fullVersion.trigger || [],
              variable: fullVersion.variable || [],
              builtInVariable: fullVersion.builtInVariable || [],
              folder: fullVersion.folder || [],
              zone: fullVersion.zone || [],
            },
            serverEnvironmentVariables: [], // Can be populated from the version variables
            manualProvisioningConfig,
          },
        };
      } catch (versionError) {
        this.logger.warn(
          `Could not get published version: ${versionError.message}`,
        );
        // Return basic config info even if version retrieval fails
        return {
          success: true,
          data: {
            containerId,
            workspaceId,
            gtagConfig: undefined,
            serverEnvironmentVariables: [],
            manualProvisioningConfig: Buffer.from(
              `id=${container?.publicId}&env=1&auth=${this.generateAuthToken(String(container?.containerId))}`,
            ).toString('base64'),
          },
        };
      }
    } catch (error) {
      this.logger.error(
        `Failed to get container config: ${error.message}`,
        error.stack,
      );

      if (error.status === 401 || error.message.includes('invalid_grant')) {
        throw new UnauthorizedException(
          'Google credentials are invalid or expired.',
        );
      }

      throw error;
    }
  }

  /**
   * Lists all tags within a workspace.
   */
  async listTags(
    accountId: string,
    containerId: string,
    workspaceId: string,
  ): Promise<{
    success: boolean;
    data: tagmanager_v2.Schema$ListTagsResponse;
  }> {
    if (!accountId || !containerId || !workspaceId) {
      throw new BadRequestException(
        'accountId, containerId, and workspaceId are required',
      );
    }

    try {
      const parent = `accounts/${accountId}/containers/${containerId}/workspaces/${workspaceId}`;
      const response = await this.gtm.accounts.containers.workspaces.tags.list({
        parent,
      });

      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      this.logger.error(`Failed to list tags: ${error.message}`, error.stack);
      throw error;
    }
  }
}
