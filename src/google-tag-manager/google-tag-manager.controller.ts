import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { User } from '../common/decorators/user.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { PermissionTokenGuard } from '../common/guards/permission-token.guard';
import { UpdateGa4ConfigDto } from './dto/update-ga4-config.dto';
import { GoogleTagManagerService } from './google-tag-manager.service';

@ApiTags('Google Tag Manager')
@Controller('gtm')
@UseGuards(PermissionTokenGuard)
@ApiBearerAuth('permission-token')
export class GoogleTagManagerController {
  constructor(private readonly gtmService: GoogleTagManagerService) {}

  @Get('accounts')
  @ApiOperation({
    summary: 'List GTM accounts',
    description:
      'Lists all GTM accounts accessible to the authenticated user. Requires a valid permission token in the Authorization header.',
  })
  @ApiResponse({
    status: 200,
    description: 'GTM accounts retrieved successfully',
    schema: {
      example: {
        success: true,
        data: {
          account: [
            {
              accountId: '12345',
              name: 'My GTM Account',
              path: 'accounts/12345',
            },
          ],
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing permission token',
  })
  async listAccounts(@User() user: any) {
    return this.gtmService.listAccounts(user);
  }

  @Get('accounts/:accountId/containers')
  @ApiOperation({
    summary: 'List GTM containers',
    description:
      'Lists all GTM containers in the specified account. Requires a valid permission token in the Authorization header.',
  })
  @ApiResponse({
    status: 200,
    description: 'GTM containers retrieved successfully',
    schema: {
      example: {
        success: true,
        data: {
          container: [
            {
              accountId: '12345',
              containerId: '67890',
              name: 'My Container',
              path: 'accounts/12345/containers/67890',
            },
          ],
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing permission token',
  })
  async listContainers(
    @User() user: any,
    @Param('accountId') accountId: string,
  ) {
    return this.gtmService.listContainers(user, accountId);
  }

  @Get('container/:accountId/:containerId')
  @ApiOperation({
    summary: 'Get GTM container information',
    description:
      'Retrieves detailed information about a specific GTM container. Requires a valid permission token.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container information retrieved successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing permission token',
  })
  async getContainerInfo(
    @User() user: any,
    @Param('accountId') accountId: string,
    @Param('containerId') containerId: string,
  ) {
    return this.gtmService.getContainerInfo(user, accountId, containerId);
  }

  @Get('tags/:accountId/:containerId/:workspaceId')
  @ApiOperation({
    summary: 'List GTM tags',
    description: 'Lists all tags in a specific GTM container workspace. Requires a valid permission token.',
  })
  @ApiResponse({
    status: 200,
    description: 'Tags listed successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing permission token',
  })
  async listTags(
    @Param('accountId') accountId: string,
    @Param('containerId') containerId: string,
    @Param('workspaceId') workspaceId: string,
  ) {
    return this.gtmService.listTags(accountId, containerId, workspaceId);
  }

  @Get('container/:accountId/:containerId/config')
  @ApiOperation({
    summary: 'Get GTM container configuration for manual provisioning',
    description:
      'Retrieves the container configuration details needed for server-side GTM manual provisioning. This includes version information and paths needed to configure a tagging server.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container configuration retrieved successfully',
    schema: {
      example: {
        success: true,
        data: {
          containerId: '224672750',
          workspaceId: '21',
          gtagConfig: {
            tag: [{ name: 'GA4 Tag', type: 'sgtmgaaw' }],
            trigger: [{ name: 'All Pageviews', type: 'gtm.js' }],
            variable: [{ name: 'GA4 Measurement ID', type: 'gtm' }],
          },
          serverEnvironmentVariables: [],
          manualProvisioningConfig: 'aWQ9R1RNLU4zTFM1NEJHJmVudj0xJmF1dGg9OGI3dmhDOFB5N29XbkJ5ZEtWcGt1ZzV5N0p2UFUtZ3ZBJTNE',
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing permission token',
  })
  @ApiResponse({
    status: 400,
    description: 'Container is not a server-side container',
  })
  async getContainerConfig(
    @User() user: any,
    @Param('accountId') accountId: string,
    @Param('containerId') containerId: string,
  ) {
    return this.gtmService.getContainerConfig(user, accountId, containerId);
  }

  @Post('update-ga4-config')
  @ApiOperation({
    summary: 'Update GA4 configuration',
    description: 'Updates the GA4 tag configuration and publishes the changes. Requires a valid permission token.',
  })
  @ApiResponse({
    status: 200,
    description: 'GA4 configuration updated and published successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing permission token',
  })
  async updateAndPublishGa4Config(@Body() updateDto: UpdateGa4ConfigDto) {
    // First update the GA4 configuration
    const updateResult = await this.gtmService.updateGA4Config(
      updateDto.accountId,
      updateDto.containerId,
      updateDto.workspaceId,
      updateDto.ga4TagId,
      updateDto.serverContainerUrl,
    );

    // Then publish the container
    const publishResult = await this.gtmService.publishContainer(
      updateDto.accountId,
      updateDto.containerId,
      updateDto.workspaceId,
      'Automated server URL update',
    );

    return {
      success: true,
      update: updateResult,
      publish: publishResult,
    };
  }
}
