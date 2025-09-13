import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Priority } from '@prisma/client';
import { IsEnum, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateSupportTicketDto {
    @ApiProperty({ example: 'Issue with login page' })
    @IsString()
    @IsNotEmpty()
    title: string;

    @ApiPropertyOptional({ example: 'I cannot access the login page...' })
    @IsString()
    @IsOptional()
    description?: string;

    @ApiPropertyOptional({ enum: Priority, example: Priority.NORMAL })
    @IsEnum(Priority)
    @IsOptional()
    priority?: Priority;

}