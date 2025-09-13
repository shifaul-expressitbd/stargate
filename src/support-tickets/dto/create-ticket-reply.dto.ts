import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Allow, IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateTicketReplyDto {
    @ApiProperty({ example: 'This is my reply to the ticket.' })
    @IsString()
    @IsNotEmpty()
    content: string;

    @ApiPropertyOptional({ example: false, description: 'Whether this reply is internal (staff only)' })
    @IsBoolean()
    @IsOptional()
    isInternal?: boolean;

    // Allow attachments field for multipart form data compatibility
    @Allow()
    attachments?: any;
}