import {
    BadRequestException,
    Body,
    Controller,
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

    @Get('assignee/:assigneeId')
    @ApiOperation({ summary: 'Get support tickets assigned to a specific assignee' })
    @ApiParam({ name: 'assigneeId', description: 'Assignee ID' })
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
                        assignedTo: {
                            id: 'assignee-id',
                            email: 'assignee@example.com',
                            name: 'Assignee Name',
                        },
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
    async getTicketsByAssignee(
        @Param('assigneeId') assigneeId: string,
        @Query() query: TicketQueryDto,
        @User() user: any,
    ): Promise<ApiResponse> {
        const result = await this.supportTicketsService.getTickets(user.id, { ...query, assigneeId }, user.roles);
        return this.createPaginatedResponse(
            'Support tickets retrieved successfully',
            result.tickets,
            result.pagination,
        );
    }

    @Get('user/:userId')
    @ApiOperation({ summary: 'Get support tickets created by a specific user' })
    @ApiParam({ name: 'userId', description: 'User ID' })
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
    async getTicketsByUser(
        @Param('userId') userId: string,
        @Query() query: TicketQueryDto,
        @User() user: any,
    ): Promise<ApiResponse> {
        const result = await this.supportTicketsService.getTickets(user.id, { ...query, creatorId: userId }, user.roles);
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
    @UseInterceptors(FilesInterceptor('attachments'))
    @ApiOperation({ summary: 'Add a reply to a support ticket' })
    @ApiParam({ name: 'id', description: 'Ticket ID' })
    @ApiConsumes('multipart/form-data')
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
                },
                attachments: {
                    type: 'array',
                    items: {
                        type: 'string',
                        format: 'binary',
                    },
                    description: 'Files to upload and attach to the reply',
                    example: ['file1.jpg', 'file2.pdf'],
                },
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
                    fileUrls: ['/api/files/id/123e4567-e89b-12d3-a456-426614174000'],
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
        @UploadedFiles() files: Express.Multer.File[],
    ): Promise<ApiResponse> {
        const reply = await this.supportTicketsService.createReply(ticketId, user.id, dto, user.roles, files);
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
}