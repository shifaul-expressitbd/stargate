import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

/**
 * DTO for uploading files to a specific support ticket
 */
export class TicketFileUploadDto {
    @ApiProperty({
        description: 'Ticket ID to associate the uploaded files with',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @IsString()
    ticketId: string;

    @ApiProperty({
        description: 'Optional description for the uploaded files',
        example: 'Screenshots of the error',
        required: false,
    })
    @IsOptional()
    @IsString()
    description?: string;
}