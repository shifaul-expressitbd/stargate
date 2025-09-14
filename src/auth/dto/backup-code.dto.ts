// src/auth/dto/backup-code.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
} from 'class-validator';

export class GenerateBackupCodesDto {
  @ApiProperty({
    example: '123456',
    description: 'TOTP code from authenticator app to verify identity',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^\d{6}$/, { message: 'Code must be 6 digits' })
  totpCode: string;
}

export class LoginWithBackupCodeDto {
  @ApiProperty({
    example: 'ABCD1234',
    description: 'Backup code (8 characters alphanumeric)',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[A-Z0-9]{8}$/, {
    message: 'Backup code must be exactly 8 uppercase alphanumeric characters',
  })
  backupCode: string;

  @ApiProperty({
    example: 'eyJhbGciOi...',
    description: 'Temporary token from /login',
  })
  @IsString()
  @IsNotEmpty()
  tempToken: string;

  @ApiProperty({ example: false, required: false })
  @IsBoolean()
  @IsOptional()
  rememberMe?: boolean;
}

export class RegenerateBackupCodesDto {
  @ApiProperty({
    example: '123456',
    description: 'Current 2FA TOTP code for verification',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[0-9]{6}$/, {
    message: 'Verification code must be exactly 6 digits',
  })
  totpCode: string;
}

export class BackupCodesStatusDto {
  @ApiProperty({
    example: true,
    description:
      'Whether backup codes have been generated and remain available',
  })
  hasBackupCodes: boolean;

  @ApiProperty({
    example: 8,
    description: 'Number of remaining unused backup codes',
    minimum: 0,
    maximum: 10,
  })
  remainingCount: number;
}
