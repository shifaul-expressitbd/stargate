import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsBoolean, IsNotEmpty, IsOptional, IsString, IsUUID } from 'class-validator';

export class CreateTicketReplyDto {
    @ApiProperty({ example: 'This is my reply to the ticket.' })
    @IsString()
    @IsNotEmpty()
    content: string;

    @ApiPropertyOptional({ example: false, description: 'Whether this reply is internal (staff only)' })
    @IsBoolean()
    @IsOptional()
    isInternal?: boolean;

    @ApiPropertyOptional({
        description: 'Array of file IDs to attach to this reply',
        example: ['123e4567-e89b-12d3-a456-426614174000', '987fcdeb-51a2-43d7-8f9e-123456789012'],
        type: [String],
    })
    @IsOptional()
    @IsArray()
    @IsUUID('4', { each: true })
    attachmentIds?: string[];
}