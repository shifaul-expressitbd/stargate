import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Priority } from '@prisma/client';
import { IsArray, IsEnum, IsNotEmpty, IsOptional, IsString, IsUUID } from 'class-validator';

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

    @ApiPropertyOptional({
        description: 'Array of file IDs to attach to this ticket',
        example: ['123e4567-e89b-12d3-a456-426614174000', '987fcdeb-51a2-43d7-8f9e-123456789012'],
        type: [String],
    })
    @IsOptional()
    @IsArray()
    @IsUUID('4', { each: true })
    attachmentIds?: string[];
}