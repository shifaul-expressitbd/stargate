// src/auth/dto/backup-code.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, Matches } from 'class-validator';

export class LoginWithBackupCodeDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'User email address',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

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
  verificationCode: string;
}
