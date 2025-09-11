import { ApiProperty } from '@nestjs/swagger';

export class CreateMetaCapiRegionDto {
  @ApiProperty({ example: 'us' })
  key: string;
  @ApiProperty({ example: 'US' })
  name: string;
  @ApiProperty({ example: 'https://graph.facebook.com' })
  baseUrl: string;
  @ApiProperty({ example: '123456789012345' })
  appId: string;
  @ApiProperty({ example: 'your-app-secret' })
  appSecret: string;
  @ApiProperty({ required: false, example: 'v16.0' })
  apiVersion?: string;
  @ApiProperty({ required: false, example: 'A description' })
  description?: string;
}

export class UpdateMetaCapiRegionDto {
  @ApiProperty({ required: false, example: 'US Updated' })
  name?: string;
  @ApiProperty({
    required: false,
    example: 'https://graph.facebook.com/updated',
  })
  baseUrl?: string;
  @ApiProperty({ required: false, example: '123456789012345' })
  appId?: string;
  @ApiProperty({ required: false, example: 'new-app-secret' })
  appSecret?: string;
  @ApiProperty({ required: false, example: 'v17.0' })
  apiVersion?: string;
  @ApiProperty({ required: false, example: true })
  isActive?: boolean;
  @ApiProperty({ required: false, example: 'Updated description' })
  description?: string;
}

export class MetaCapiRegionResponseDto {
  @ApiProperty({ example: 'clhjm8x1214520kgfg30kajlm' })
  id: string;
  @ApiProperty({ example: 'us' })
  key: string;
  @ApiProperty({ example: 'US' })
  name: string;
  @ApiProperty({ example: 'https://graph.facebook.com' })
  baseUrl: string;
  @ApiProperty({ example: '123456789012345' })
  appId: string;
  @ApiProperty({ example: 'your-app-secret' })
  appSecret: string;
  @ApiProperty({ example: 'v16.0' })
  apiVersion: string;
  @ApiProperty({ example: true })
  isActive: boolean;
  @ApiProperty({ example: false })
  isDefault: boolean;
  @ApiProperty({ required: false, example: 'A description' })
  description?: string;
  @ApiProperty({ type: 'string', format: 'date-time' })
  createdAt: Date;
  @ApiProperty({ type: 'string', format: 'date-time' })
  updatedAt: Date;
}

export class AvailableMetaCapiRegionsResponseDto {
  @ApiProperty({
    type: 'array',
    items: {
      type: 'object',
      properties: {
        key: { type: 'string', example: 'us' },
        name: { type: 'string', example: 'US' },
        available: { type: 'boolean', example: true },
        default: { type: 'boolean', example: false },
      },
    },
  })
  regions: Array<{
    key: string;
    name: string;
    available: boolean;
    default: boolean;
  }>;
  @ApiProperty({ example: 'us' })
  defaultRegion: string;
}
