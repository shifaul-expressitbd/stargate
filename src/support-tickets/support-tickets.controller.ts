import {
    BadRequestException,
    Body,
    Controller,
    Delete,
    Get,
    Param,
    Post,
    Put,
    Query,
    UploadedFiles,
    UseGuards,
    UseInterceptors
} from '@nestjs/common';
import { FilesInterceptor } from '@nestjs/platform-express';
import {
    ApiBearerAuth,
    ApiBody,
    ApiConsumes,
    ApiOperation,
    ApiParam,
    ApiQuery,
    ApiResponse,
    ApiTags,
} from '@nestjs/swagger';
import { Roles } from '../common/decorators/roles.decorator';
import { User } from '../common/decorators/user.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { CreateReopenRequestDto } from './dto/create-reopen-request.dto';
import { CreateSupportTicketDto } from './dto/create-support-ticket.dto';
import { CreateTicketReplyDto } from './dto/create-ticket-reply.dto';
import { ReplyFileUploadDto } from './dto/reply-file-upload.dto';
import { TicketFileUploadDto } from './dto/ticket-file-upload.dto';
import { TicketQueryDto } from './dto/ticket-query.dto';
import { UpdateSupportTicketDto } from './dto/update-support-ticket.dto';
import { SupportTicketsService } from './support-tickets.service';

interface ApiResponse<T = any> {
    success: boolean;
    message: string;
    data?: T;
    pagination?: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
    };
}

@ApiTags('Support Tickets')
@Controller('support-tickets')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT-auth')
export class SupportTicketsController {
    constructor(private readonly supportTicketsService: SupportTicketsService) { }

    private createSuccessResponse<T>(message: string, data?: T): ApiResponse<T> {
        return { success: true, message, data };
    }

    private createPaginatedResponse<T>(
        message: string,
        data: T,
        pagination: any,
    ): ApiResponse<T> {
        return {
            success: true,
            message,
            data,
            pagination,
        };
    }

    @Post()
    @UseInterceptors(FilesInterceptor('attachments'))
    @ApiOperation({ summary: 'Create a new support ticket' })
    @ApiConsumes('multipart/form-data')
    @ApiBody({
        schema: {
            type: 'object',
            required: ['title'],
            properties: {
                title: {
                    type: 'string',
                    example: 'Issue with login page',
                },
                description: {
                    type: 'string',
                    example: 'I cannot access the login page...',
                },
                priority: {
                    type: 'string',
                    enum: ['LOW', 'NORMAL', 'HIGH', 'URGENT'],
                    example: 'NORMAL',
                },
                attachments: {
                    type: 'array',
                    items: {
                        type: 'string',
                        format: 'binary',
                    },
                    description: 'Files to upload and attach to the ticket',
                    example: ['file1.jpg', 'file2.pdf'],
                },
            },
        },
    })
    @ApiResponse({
        status: 201,
        description: 'Ticket created successfully',
        schema: {
            example: {
                success: true,
                message: 'Support ticket created successfully',
                data: {
                    id: 'ticket-id',
                    title: 'Issue with login',
                    description: 'Cannot access login page',
                    status: 'OPEN',
                    priority: 'NORMAL',
                    createdAt: '2023-01-01T00:00:00.000Z',
                    updatedAt: '2023-01-01T00:00:00.000Z',
                    fileUrls: ['/api/files/id/123e4567-e89b-12d3-a456-426614174000'],
                    createdBy: {
                        id: 'user-id',
                        email: 'user@example.com',
                        name: 'User Name',
                    },
                },
            },
        },
    })
    @ApiResponse({
        status: 400,
        description: 'Bad request',
    })
    async createTicket(
        @User() user: any,
        @Body() dto: CreateSupportTicketDto,
        @UploadedFiles() files: Express.Multer.File[],
    ): Promise<ApiResponse> {
        const ticket = await this.supportTicketsService.createTicket(user.id, dto, files);
        return this.createSuccessResponse('Support ticket created successfully', ticket);
    }

    @Get()
    @ApiOperation({ summary: 'Get support tickets with pagination and filters' })
    @ApiQuery({ name: 'page', required: false, type: Number })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    @ApiQuery({ name: 'status', required: false, enum: ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'] })
    @ApiQuery({ name: 'priority', required: false, enum: ['LOW', 'NORMAL', 'HIGH', 'URGENT'] })
    @ApiQuery({ name: 'search', required: false, type: String })
    @ApiQuery({ name: 'sortBy', required: false, enum: ['createdAt', 'updatedAt', 'priority', 'status'] })
    @ApiQuery({ name: 'sortOrder', required: false, enum: ['asc', 'desc'] })
    @ApiResponse({
        status: 200,
        description: 'Tickets retrieved successfully',
        schema: {
            example: {
                success: true,
                message: 'Support tickets retrieved successfully',
                data: [
                    {
                        id: 'ticket-id',
                        title: 'Issue with login',
                        status: 'OPEN',
                        priority: 'NORMAL',
                        createdAt: '2023-01-01T00:00:00.000Z',
                        createdBy: {
                            id: 'user-id',
                            email: 'user@example.com',
                            name: 'User Name',
                        },
                        assignedTo: null,
                        _count: { replies: 2 },
                    },
                ],
                pagination: {
                    page: 1,
                    limit: 10,
                    total: 25,
                    totalPages: 3,
                },
            },
        },
    })
    async getTickets(
        @User() user: any,
        @Query() query: TicketQueryDto,
    ): Promise<ApiResponse> {
        const result = await this.supportTicketsService.getTickets(user.id, query, user.roles);
        return this.createPaginatedResponse(
            'Support tickets retrieved successfully',
            result.tickets,
            result.pagination,
        );
    }

    @Get('stats')
    @ApiOperation({ summary: 'Get ticket statistics' })
    @ApiResponse({
        status: 200,
        description: 'Statistics retrieved successfully',
        schema: {
            example: {
                success: true,
                message: 'Ticket statistics retrieved successfully',
                data: {
                    total: 25,
                    open: 5,
                    inProgress: 3,
                    resolved: 10,
                    closed: 7,
                },
            },
        },
    })
    async getStats(@User() user: any): Promise<ApiResponse> {
        const stats = await this.supportTicketsService.getStats(user.id, user.roles);
        return this.createSuccessResponse('Ticket statistics retrieved successfully', stats);
    }

    @Get(':id')
    @ApiOperation({ summary: 'Get a specific support ticket by ID' })
    @ApiParam({ name: 'id', description: 'Ticket ID' })
    @ApiResponse({
        status: 200,
        description: 'Ticket retrieved successfully',
        schema: {
            example: {
                success: true,
                message: 'Support ticket retrieved successfully',
                data: {
                    id: 'ticket-id',
                    title: 'Issue with login',
                    description: 'Cannot access login page',
                    status: 'OPEN',
                    priority: 'NORMAL',
                    createdAt: '2023-01-01T00:00:00.000Z',
                    updatedAt: '2023-01-01T00:00:00.000Z',
                    createdBy: {
                        id: 'user-id',
                        email: 'user@example.com',
                        name: 'User Name',
                    },
                    assignedTo: null,
                    replies: [
                        {
                            id: 'reply-id',
                            content: 'Thank you for reporting this issue',
                            isInternal: false,
                            createdAt: '2023-01-01T00:00:00.000Z',
                            author: {
                                id: 'staff-id',
                                email: 'staff@example.com',
                                name: 'Staff Member',
                            },
                        },
                    ],
                    reopenRequests: [],
                },
            },
        },
    })
    @ApiResponse({
        status: 404,
        description: 'Ticket not found',
    })
    @ApiResponse({
        status: 403,
        description: 'Forbidden - cannot view this ticket',
    })
    async getTicketById(
        @Param('id') ticketId: string,
        @User() user: any,
    ): Promise<ApiResponse> {
        const ticket = await this.supportTicketsService.getTicketById(ticketId, user.id, user.roles);
        return this.createSuccessResponse('Support ticket retrieved successfully', ticket);
    }

    @Put(':id')
    @UseGuards(RolesGuard)
    @Roles('admin', 'staff', 'support')
    @ApiOperation({ summary: 'Update a support ticket (Staff only)' })
    @ApiParam({ name: 'id', description: 'Ticket ID' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                title: {
                    type: 'string',
                    example: 'Updated issue title',
                },
                description: {
                    type: 'string',
                    example: 'Updated description...',
                },
                priority: {
                    type: 'string',
                    enum: ['LOW', 'NORMAL', 'HIGH', 'URGENT'],
                    example: 'HIGH',
                },
                status: {
                    type: 'string',
                    enum: ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'],
                    example: 'IN_PROGRESS',
                },
            },
        },
    })
    @ApiResponse({
        status: 200,
        description: 'Ticket updated successfully',
    })
    @ApiResponse({
        status: 403,
        description: 'Forbidden - insufficient permissions',
    })
    @ApiResponse({
        status: 404,
        description: 'Ticket not found',
    })
    async updateTicket(
        @Param('id') ticketId: string,
        @Body() dto: UpdateSupportTicketDto,
        @User() user: any,
    ): Promise<ApiResponse> {
        const ticket = await this.supportTicketsService.updateTicket(ticketId, dto, user.id, user.roles);
        return this.createSuccessResponse('Support ticket updated successfully', ticket);
    }

    @Put(':id/assign')
    @UseGuards(RolesGuard)
    @Roles('admin', 'staff', 'support')
    @ApiOperation({ summary: 'Assign a ticket to a staff member (Staff only)' })
    @ApiParam({ name: 'id', description: 'Ticket ID' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                assigneeId: {
                    type: 'string',
                    format: 'uuid',
                    description: 'Staff member ID to assign the ticket to (null to unassign)',
                    example: '123e4567-e89b-12d3-a456-426614174000',
                },
            },
        },
    })
    @ApiResponse({
        status: 200,
        description: 'Ticket assigned successfully',
    })
    async assignTicket(
        @Param('id') ticketId: string,
        @Body() body: { assigneeId?: string },
        @User() user: any,
    ): Promise<ApiResponse> {
        const ticket = await this.supportTicketsService.assignTicket(
            ticketId,
            body.assigneeId || null,
            user.id,
            user.roles,
        );
        return this.createSuccessResponse('Support ticket assigned successfully', ticket);
    }

    @Post(':id/replies')
    @ApiOperation({ summary: 'Add a reply to a support ticket' })
    @ApiParam({ name: 'id', description: 'Ticket ID' })
    @ApiBody({
        schema: {
            type: 'object',
            required: ['content'],
            properties: {
                content: {
                    type: 'string',
                    example: 'This is my reply to the ticket.',
                },
                isInternal: {
                    type: 'boolean',
                    description: 'Whether this reply is internal (staff only)',
                    example: false,
                }
            },
        },
    })
    @ApiResponse({
        status: 201,
        description: 'Reply added successfully',
        schema: {
            example: {
                success: true,
                message: 'Reply added successfully',
                data: {
                    id: 'reply-id',
                    content: 'Thank you for your patience',
                    isInternal: false,
                    createdAt: '2023-01-01T00:00:00.000Z',
                    author: {
                        id: 'user-id',
                        email: 'user@example.com',
                        name: 'User Name',
                    },
                },
            },
        },
    })
    async createReply(
        @Param('id') ticketId: string,
        @Body() dto: CreateTicketReplyDto,
        @User() user: any,
    ): Promise<ApiResponse> {
        const reply = await this.supportTicketsService.createReply(ticketId, user.id, dto, user.roles);
        return this.createSuccessResponse('Reply added successfully', reply);
    }

    @Post(':id/reopen')
    @ApiOperation({ summary: 'Request to reopen a closed ticket' })
    @ApiParam({ name: 'id', description: 'Ticket ID' })
    @ApiBody({
        schema: {
            type: 'object',
            required: ['reason'],
            properties: {
                reason: {
                    type: 'string',
                    example: 'The issue is still not resolved. I still cannot access the login page.',
                },
            },
        },
    })
    @ApiResponse({
        status: 201,
        description: 'Reopen request created successfully',
    })
    @ApiResponse({
        status: 400,
        description: 'Ticket is not closed or request already exists',
    })
    async createReopenRequest(
        @Param('id') ticketId: string,
        @Body() dto: CreateReopenRequestDto,
        @User() user: any,
    ): Promise<ApiResponse> {
        const request = await this.supportTicketsService.createReopenRequest(ticketId, user.id, dto);
        return this.createSuccessResponse('Reopen request created successfully', request);
    }

    @Put('reopen-requests/:requestId')
    @UseGuards(RolesGuard)
    @Roles('admin', 'staff', 'support')
    @ApiOperation({ summary: 'Process a reopen request (Staff only)' })
    @ApiParam({ name: 'requestId', description: 'Reopen request ID' })
    @ApiBody({
        schema: {
            type: 'object',
            required: ['approve'],
            properties: {
                approve: {
                    type: 'boolean',
                    description: 'Whether to approve the reopen request',
                    example: true,
                },
            },
        },
    })
    @ApiResponse({
        status: 200,
        description: 'Reopen request processed successfully',
    })
    async processReopenRequest(
        @Param('requestId') requestId: string,
        @Body() body: { approve: boolean },
        @User() user: any,
    ): Promise<ApiResponse> {
        if (typeof body.approve !== 'boolean') {
            throw new BadRequestException('approve must be a boolean');
        }

        const request = await this.supportTicketsService.processReopenRequest(
            requestId,
            body.approve,
            user.id,
            user.roles,
        );
        return this.createSuccessResponse('Reopen request processed successfully', request);
    }

    @Post(':id/files')
    @UseInterceptors(FilesInterceptor('files'))
    @ApiOperation({ summary: 'Upload files to an existing support ticket' })
    @ApiParam({ name: 'id', description: 'Ticket ID' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                ticketId: {
                    type: 'string',
                    format: 'uuid',
                    description: 'Ticket ID to associate the uploaded files with',
                    example: '123e4567-e89b-12d3-a456-426614174000',
                },
                description: {
                    type: 'string',
                    description: 'Optional description for the uploaded files',
                    example: 'Screenshots of the error',
                },
            },
        },
    })
    @ApiResponse({
        status: 201,
        description: 'Files uploaded successfully',
        schema: {
            example: {
                success: true,
                message: 'Files uploaded successfully',
                data: {
                    files: [
                        {
                            id: 'file-id',
                            filename: 'document.pdf',
                            originalName: 'my-document.pdf',
                            mimeType: 'application/pdf',
                            size: 1024000,
                            path: 'uploads/2024/01/document.pdf',
                            createdAt: '2024-01-01T00:00:00.000Z',
                        },
                    ],
                    totalSize: 1024000,
                    duration: 1500,
                    success: true,
                },
            },
        },
    })
    async uploadFilesToTicket(
        @Param('id') ticketId: string,
        @Body() dto: TicketFileUploadDto,
        @UploadedFiles() files: Express.Multer.File[],
        @User() user: any,
    ): Promise<ApiResponse> {
        const result = await this.supportTicketsService.uploadFilesToTicket(ticketId, files, user.id);
        return this.createSuccessResponse('Files uploaded successfully', result);
    }

    @Post(':id/replies/:replyId/files')
    @UseInterceptors(FilesInterceptor('files'))
    @ApiOperation({ summary: 'Upload files to an existing ticket reply' })
    @ApiParam({ name: 'id', description: 'Ticket ID' })
    @ApiParam({ name: 'replyId', description: 'Reply ID' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                replyId: {
                    type: 'string',
                    format: 'uuid',
                    description: 'Reply ID to associate the uploaded files with',
                    example: '123e4567-e89b-12d3-a456-426614174000',
                },
                description: {
                    type: 'string',
                    description: 'Optional description for the uploaded files',
                    example: 'Additional documentation',
                },
            },
        },
    })
    @ApiResponse({
        status: 201,
        description: 'Files uploaded successfully',
        schema: {
            example: {
                success: true,
                message: 'Files uploaded successfully',
                data: {
                    files: [
                        {
                            id: 'file-id',
                            filename: 'image.png',
                            originalName: 'screenshot.png',
                            mimeType: 'image/png',
                            size: 512000,
                            path: 'uploads/2024/01/image.png',
                            createdAt: '2024-01-01T00:00:00.000Z',
                        },
                    ],
                    totalSize: 512000,
                    duration: 800,
                    success: true,
                },
            },
        },
    })
    async uploadFilesToReply(
        @Param('id') ticketId: string,
        @Param('replyId') replyId: string,
        @Body() dto: ReplyFileUploadDto,
        @UploadedFiles() files: Express.Multer.File[],
        @User() user: any,
    ): Promise<ApiResponse> {
        const result = await this.supportTicketsService.uploadFilesToReply(replyId, ticketId, files, user.id, user.roles);
        return this.createSuccessResponse('Files uploaded successfully', result);
    }

    @Delete(':id/files/:fileId')
    @ApiOperation({ summary: 'Remove attachment from a support ticket' })
    @ApiParam({ name: 'id', description: 'Ticket ID' })
    @ApiParam({ name: 'fileId', description: 'File ID' })
    @ApiResponse({
        status: 200,
        description: 'File removed successfully',
    })
    @ApiResponse({
        status: 404,
        description: 'File not found or not attached to ticket',
    })
    async removeFileFromTicket(
        @Param('id') ticketId: string,
        @Param('fileId') fileId: string,
        @User() user: any,
        @Query() query: any,
    ): Promise<ApiResponse> {
        await this.supportTicketsService.removeFileFromTicket(ticketId, fileId, user.id, user.roles);
        return this.createSuccessResponse('File removed successfully', null);
    }

    @Delete(':id/replies/:replyId/files/:fileId')
    @ApiOperation({ summary: 'Remove attachment from a ticket reply' })
    @ApiParam({ name: 'id', description: 'Ticket ID' })
    @ApiParam({ name: 'replyId', description: 'Reply ID' })
    @ApiParam({ name: 'fileId', description: 'File ID' })
    @ApiResponse({
        status: 200,
        description: 'File removed successfully',
    })
    @ApiResponse({
        status: 404,
        description: 'File not found or not attached to reply',
    })
    async removeFileFromReply(
        @Param('id') ticketId: string,
        @Param('replyId') replyId: string,
        @Param('fileId') fileId: string,
        @User() user: any,
        @Query() query: any,
    ): Promise<ApiResponse> {
        await this.supportTicketsService.removeFileFromReply(ticketId, replyId, fileId, user.id, user.roles);
        return this.createSuccessResponse('File removed successfully', null);
    }
}