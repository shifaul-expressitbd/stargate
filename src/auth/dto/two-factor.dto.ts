// src/auth/dto/two-factor.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Matches
} from 'class-validator';

export class EnableTwoFactorDto {
  @ApiProperty({
    example: '123456',
    description: 'TOTP code from authenticator app',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^\d{6}$/, { message: 'Code must be exactly 6 digits' })
  code: string;

  @ApiProperty({
    example: true,
    required: false,
    description: 'Skip backup code generation (for recovery)',
  })
  @IsBoolean()
  @IsOptional()
  skipBackup?: boolean;
}

export class VerifyTwoFactorDto {
  @ApiProperty({
    example: '123456',
    description: 'TOTP code from authenticator app',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^\d{6}$/, { message: 'Code must be 6 digits' })
  code: string;

  @ApiProperty({
    example: 1641785685000,
    required: false,
    description: 'Client-reported timestamp to help debug time sync issues (Unix timestamp in milliseconds)',
  })
  @IsNumber()
  @IsOptional()
  clientTimestamp?: number;
}

export class DisableTwoFactorDto {
  @ApiProperty({
    example: '123456',
    description: 'TOTP code from authenticator app',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^\d{6}$/, { message: 'Code must be 6 digits' })
  code: string;
}

export class LoginWithTwoFactorDto {
  @ApiProperty({
    example: '123456',
    description: 'TOTP code from authenticator app',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^\d{6}$/, { message: 'Code must be 6 digits' })
  code: string;

  @ApiProperty({
    example: 'eyJhbGciOi...',
    description: 'Temporary token from /login',
  })
  @IsString()
  @IsNotEmpty()
  tempToken: string;

  @ApiProperty({
    example: 1641785685000,
    required: false,
    description: 'Client-reported timestamp to help debug time sync issues (Unix timestamp in milliseconds)',
  })
  @IsNumber()
  @IsOptional()
  clientTimestamp?: number;

  @ApiProperty({ example: false, required: false })
  @IsBoolean()
  @IsOptional()
  rememberMe?: boolean;
}
