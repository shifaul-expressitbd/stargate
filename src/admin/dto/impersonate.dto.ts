// src/admin/dto/impersonate.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsOptional, IsString, IsUUID } from 'class-validator';

export class ImpersonateDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'Email of the user to impersonate (alternative to userId)',
    required: false,
  })
  @IsEmail()
  @IsOptional()
  email?: string;

  @ApiProperty({
    example: 'c3a9b8e1-2c4d-4f5b-a6d8-1e2f3c4d5e6f',
    description: 'ID of the user to impersonate (alternative to email)',
    required: false,
  })
  @IsUUID()
  @IsOptional()
  userId?: string;

  @ApiProperty({
    example: 'Support ticket #12345 - User reported login issues',
    required: false,
    description: 'Reason for impersonation (for audit logs)',
  })
  @IsString()
  @IsOptional()
  reason?: string;
}

export class StopImpersonationDto {
  @ApiProperty({
    example: 'c3a9b8e1-2c4d-4f5b-a6d8-1e2f3c4d5e6f',
    description: 'ID of the user to stop impersonating',
  })
  @IsUUID()
  @IsNotEmpty()
  targetUserId: string;
}