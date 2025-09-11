import { ApiProperty } from '@nestjs/swagger';
import { IsBase64, IsOptional, IsString } from 'class-validator';

export class UpdateMetaCapiContainerConfigDto {
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
}
