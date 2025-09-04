import { ApiProperty } from '@nestjs/swagger';

export class CreateRegionDto {
  @ApiProperty({ example: 'us-east-1' })
  key: string;
  @ApiProperty({ example: 'US East 1' })
  name: string;
  @ApiProperty({ example: 'https://api.example.com' })
  apiUrl: string;
  @ApiProperty({ example: 'your-api-key' })
  apiKey: string;
  @ApiProperty({ required: false, example: 'A description' })
  description?: string;
}

export class UpdateRegionDto {
  @ApiProperty({ required: false, example: 'US East 1 Updated' })
  name?: string;
  @ApiProperty({ required: false, example: 'https://api.updated.com' })
  apiUrl?: string;
  @ApiProperty({ required: false, example: 'new-api-key' })
  apiKey?: string;
  @ApiProperty({ required: false, example: true })
  isActive?: boolean;
  @ApiProperty({ required: false, example: 'Updated description' })
  description?: string;
}

export class RegionResponseDto {
  @ApiProperty({ example: 'clhjm8x1214520kgfg30kajlm' })
  id: string;
  @ApiProperty({ example: 'us-east-1' })
  key: string;
  @ApiProperty({ example: 'US East 1' })
  name: string;
  @ApiProperty({ example: 'https://api.example.com' })
  apiUrl: string;
  @ApiProperty({ example: 'your-api-key' })
  apiKey: string;
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

export class AvailableRegionsResponseDto {
  @ApiProperty({
    type: 'array',
    items: {
      type: 'object',
      properties: {
        key: { type: 'string', example: 'us-east-1' },
        name: { type: 'string', example: 'US East 1' },
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
  @ApiProperty({ example: 'us-east-1' })
  defaultRegion: string;
}
