// src/sgtm-container/dto/create-sgtm-container.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import {
  IsBase64,
  IsFQDN,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

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

  @ApiProperty({ example: 'aWQ9R1RN...' })
  @IsString()
  @IsBase64()
  config: string;
}
