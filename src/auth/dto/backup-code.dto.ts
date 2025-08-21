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
