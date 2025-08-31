import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class GoogleOAuthCallbackDto {
  @ApiProperty({
    description: 'The authorization code from Google OAuth',
    example: '4/0AY0e-g5...',
  })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({
    description: 'The state parameter passed during authorization',
    example: 'user123',
  })
  @IsString()
  @IsNotEmpty()
  state: string;
}
