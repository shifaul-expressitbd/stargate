import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class ResendVerificationEmailDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'Email address to resend verification email',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
