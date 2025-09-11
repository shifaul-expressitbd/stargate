import { ApiProperty } from '@nestjs/swagger';
import {
  IsBase64,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class CreateMetaCapiContainerDto {
  @ApiProperty({ example: 'meta-capi-container-1' })
  @IsString()
  @MinLength(3)
  @MaxLength(50)
  name: string;

  @ApiProperty({ example: '123456789012345' })
  @IsString()
  fbPixelId: string;

  @ApiProperty({
    description: 'Facebook API Access Token (base64 encoded)',
    example: 'base64encodedtokenhere',
  })
  @IsString()
  @IsBase64()
  accessToken: string;

  @ApiProperty({
    description: 'Optional test code for Facebook API',
    example: 'test123',
    required: false,
  })
  @IsOptional()
  @IsString()
  testCode?: string;

  @ApiProperty({
    example: 'us',
    description: 'Region where the container should be deployed',
    required: false,
  })
  @IsOptional()
  @IsString()
  regionKey?: string;
}
