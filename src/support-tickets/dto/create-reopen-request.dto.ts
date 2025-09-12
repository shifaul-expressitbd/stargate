import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CreateReopenRequestDto {
    @ApiProperty({ example: 'The issue is still not resolved. I still cannot access the login page.' })
    @IsString()
    @IsNotEmpty()
    reason: string;
}