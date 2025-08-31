import { IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class PermissionTokenDto {
  @ApiProperty({
    description: 'User ID',
    example: 'uuid',
    required: true,
  })
  @IsString()
  userId: string;

  @ApiProperty({
    description: 'Optional user context data',
    example: '{ "preferredRegion": "us-east-1" }',
    required: false,
  })
  @IsOptional()
  @IsString()
  context?: string;
}

export class PermissionTokenResponseDto {
  @ApiProperty({
    description: 'Permission token for Google Tag Manager API access',
    example: 'jwt.token.here',
  })
  permissionToken: string;

  @ApiProperty({
    description: 'Token expiration time in milliseconds',
    example: 900000,
  })
  expiresIn: number;

  @ApiProperty({
    description: 'Token issuance timestamp',
    example: 1693963267000,
  })
  issuedAt: number;
}