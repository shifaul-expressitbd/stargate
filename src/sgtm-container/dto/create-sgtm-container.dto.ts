// src/sgtm-container/dto/create-sgtm-container.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import {
  IsBase64,
  IsFQDN,
  IsIn,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { DEFAULT_REGION, SUPPORTED_REGIONS } from '../../config/region.types';

export class CreateSgtmContainerDto {
  @ApiProperty({ example: 'gtm-unified' })
  @IsString()
  @MinLength(3)
  @MaxLength(50)
  name: string;

  @ApiProperty({ example: 'tags.bikobazaar.xyz' })
  @IsString()
  @IsFQDN()
  subdomain: string;

  @ApiProperty({
    description: 'Container configuration data (base64 encoded)',
    example:
      'aWQ9R1RNLVdGOFc4WERIJmVudj0xJmF1dGg9ZXRJdWpPajNPaWJGN2kxcU52d2hqQQ==',
  })
  @IsString()
  @IsBase64()
  config: string;

  @ApiProperty({
    example: 'india',
    description: 'Region where the container should be deployed',
    enum: SUPPORTED_REGIONS,
    default: DEFAULT_REGION,
    required: false,
  })
  @IsOptional()
  @IsString()
  @IsIn(SUPPORTED_REGIONS)
  region?: string;
}
