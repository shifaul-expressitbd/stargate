import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiExtraModels,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { User } from '../common/decorators/user.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CreateMetaCapiContainerDto } from './dto/meta-capi-container.dto';
import { UpdateMetaCapiContainerConfigDto } from './dto/update-meta-capi-container-config.dto';
import { MetaCapiContainerService } from './meta-capi-container.service';

@ApiTags('meta-capi-containers')
@ApiExtraModels(CreateMetaCapiContainerDto, UpdateMetaCapiContainerConfigDto)
@Controller('api/meta-capi-containers')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT-auth')
export class MetaCapiContainerController {
  constructor(
    private readonly metaCapiContainerService: MetaCapiContainerService,
  ) {}

  @Post()
  @ApiOperation({
    summary: 'Create a new Meta CAPI container',
    description: 'Creates and sets up a new Meta Conversions API container.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          example: 'meta-capi-1',
          minLength: 3,
          maxLength: 50,
          description: 'Container name',
        },
        fbPixelId: {
          type: 'string',
          example: '123456789012345',
          description: 'Facebook Pixel ID',
        },
        accessToken: {
          type: 'string',
          example: 'base64encodedtokenhere',
          description: 'Facebook API Access Token (base64 encoded)',
        },
        testCode: {
          type: 'string',
          example: 'test123',
          description: 'Optional test code for Facebook API',
          nullable: true,
        },
        regionKey: {
          type: 'string',
          example: 'us',
          description: 'Region key',
          nullable: true,
        },
      },
      required: ['name', 'fbPixelId', 'accessToken'],
    },
  })
  @ApiResponse({
    status: 201,
    description: 'Meta CAPI container created successfully',
  })
  async create(
    @User('id') userId: string,
    @Body() createMetaCapiContainerDto: CreateMetaCapiContainerDto,
  ) {
    const result = await this.metaCapiContainerService.create(
      userId,
      createMetaCapiContainerDto,
    );

    if (result.success) {
      return result;
    } else {
      throw new BadRequestException(result);
    }
  }

  @Get()
  @ApiOperation({
    summary: 'Get all Meta CAPI containers for the current user',
  })
  @ApiResponse({
    status: 200,
    description: 'Containers retrieved successfully',
  })
  async findAll(@User('id') userId: string) {
    return this.metaCapiContainerService.findAllByUser(userId);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a specific Meta CAPI container' })
  @ApiResponse({
    status: 200,
    description: 'Container retrieved successfully',
  })
  @ApiResponse({ status: 404, description: 'Container not found' })
  async findOne(@Param('id') id: string, @User('id') userId: string) {
    return this.metaCapiContainerService.findByIdAndUser(id, userId);
  }

  @Put(':id/config')
  @ApiOperation({
    summary: 'Update Meta CAPI container configuration',
    description:
      'Updates the configuration for a specific Meta CAPI container.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        accessToken: {
          type: 'string',
          example: 'base64encodedtokenhere',
          description: 'Facebook API Access Token (base64 encoded)',
        },
        testCode: {
          type: 'string',
          example: 'test123',
          description: 'Optional test code for Facebook API',
          nullable: true,
        },
      },
      required: ['accessToken'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Container configuration updated successfully',
  })
  async updateConfig(
    @Param('id') id: string,
    @User('id') userId: string,
    @Body() updateDto: UpdateMetaCapiContainerConfigDto,
  ) {
    return this.metaCapiContainerService.updateConfig(id, userId, updateDto);
  }

  @Post(':id/stop')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Stop a running Meta CAPI container',
    description: 'Stops a running Meta CAPI container.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container stopped successfully',
  })
  async stop(@Param('id') id: string, @User('id') userId: string) {
    return this.metaCapiContainerService.stop(id, userId);
  }

  @Post(':id/restart')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Restart a Meta CAPI container',
    description: 'Restarts a Meta CAPI container.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container restarted successfully',
  })
  async restart(@Param('id') id: string, @User('id') userId: string) {
    return this.metaCapiContainerService.restart(id, userId);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Delete a Meta CAPI container',
    description: 'Deletes a Meta CAPI container.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container deleted successfully',
  })
  async remove(@Param('id') id: string, @User('id') userId: string) {
    return this.metaCapiContainerService.delete(id, userId);
  }

  @Delete(':id/hard')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Hard delete a Meta CAPI container (permanent deletion)',
    description: 'Permanently deletes a Meta CAPI container from the database.',
  })
  @ApiResponse({
    status: 200,
    description: 'Container hard deleted successfully',
  })
  async hardDelete(@Param('id') id: string, @User('id') userId: string) {
    return this.metaCapiContainerService.hardDelete(id, userId);
  }
}
