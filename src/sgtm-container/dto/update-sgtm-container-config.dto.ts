import { ApiProperty } from '@nestjs/swagger';
import { IsBase64, IsOptional, IsString } from 'class-validator';

export class UpdateSgtmContainerConfigDto {
  @ApiProperty({
    description: 'Container configuration data (base64 encoded)',
    example:
      'aWQ9R1RNLVdGOFc4WERIJmVudj0xJmF1dGg9ZXRJdWpPajNPaWJGN2kxcU52d2hqQQ==',
  })
  @IsBase64()
  @IsString()
  config: string;

  @ApiProperty({
    description: 'Optional server container URL to update in the configuration',
    example: 'https://container.example.com',
    required: false,
  })
  @IsOptional()
  @IsString()
  serverContainerUrl?: string;
}
