import { ApiPropertyOptional } from '@nestjs/swagger';
import { Priority, TicketStatus } from '@prisma/client';
import { Type } from 'class-transformer';
import { IsEnum, IsInt, IsOptional, IsString, IsUUID, Max, Min } from 'class-validator';

export class TicketQueryDto {
    @ApiPropertyOptional({ enum: TicketStatus, example: TicketStatus.OPEN })
    @IsEnum(TicketStatus)
    @IsOptional()
    status?: TicketStatus;

    @ApiPropertyOptional({ enum: Priority, example: Priority.HIGH })
    @IsEnum(Priority)
    @IsOptional()
    priority?: Priority;

    @ApiPropertyOptional({ example: 'login' })
    @IsString()
    @IsOptional()
    search?: string;

    @ApiPropertyOptional({ example: 'uuid-string' })
    @IsUUID()
    @IsOptional()
    assigneeId?: string;

    @ApiPropertyOptional({ example: 'uuid-string' })
    @IsUUID()
    @IsOptional()
    creatorId?: string;

    @ApiPropertyOptional({ example: 1, minimum: 1 })
    @Type(() => Number)
    @IsInt()
    @Min(1)
    @IsOptional()
    page?: number = 1;

    @ApiPropertyOptional({ example: 10, minimum: 1, maximum: 100 })
    @Type(() => Number)
    @IsInt()
    @Min(1)
    @Max(100)
    @IsOptional()
    limit?: number = 10;

    @ApiPropertyOptional({ example: 'createdAt', enum: ['createdAt', 'updatedAt', 'priority', 'status'] })
    @IsString()
    @IsOptional()
    sortBy?: string = 'createdAt';

    @ApiPropertyOptional({ example: 'desc', enum: ['asc', 'desc'] })
    @IsString()
    @IsOptional()
    sortOrder?: 'asc' | 'desc' = 'desc';
}