import { ApiPropertyOptional } from '@nestjs/swagger';
import { Priority, TicketStatus } from '@prisma/client';
import { IsEnum, IsOptional, IsString } from 'class-validator';

export class UpdateSupportTicketDto {
    @ApiPropertyOptional({ example: 'Updated issue title' })
    @IsString()
    @IsOptional()
    title?: string;

    @ApiPropertyOptional({ example: 'Updated description...' })
    @IsString()
    @IsOptional()
    description?: string;

    @ApiPropertyOptional({ enum: Priority, example: Priority.HIGH })
    @IsEnum(Priority)
    @IsOptional()
    priority?: Priority;

    @ApiPropertyOptional({ enum: TicketStatus, example: TicketStatus.IN_PROGRESS })
    @IsEnum(TicketStatus)
    @IsOptional()
    status?: TicketStatus;
}