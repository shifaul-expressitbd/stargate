import { HttpService } from '@nestjs/axios';
import { BadRequestException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { Priority, ReopenStatus, TicketStatus } from '@prisma/client';
import { PrismaService } from '../database/prisma/prisma.service';
import { FileCleanupService } from '../file/services/file-cleanup.service';
import { FileMetadataService } from '../file/services/file-metadata.service';
import { FileStorageService } from '../file/services/file-storage.service';
import { FileValidationService } from '../file/services/file-validation.service';
import { LoggerService } from '../utils/logger/logger.service';
import { CreateReopenRequestDto } from './dto/create-reopen-request.dto';
import { CreateSupportTicketDto } from './dto/create-support-ticket.dto';
import { CreateTicketReplyDto } from './dto/create-ticket-reply.dto';
import { TicketQueryDto } from './dto/ticket-query.dto';
import { UpdateSupportTicketDto } from './dto/update-support-ticket.dto';

@Injectable()
export class SupportTicketsService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly logger: LoggerService,
        private readonly httpService: HttpService,
        private readonly fileStorageService: FileStorageService,
        private readonly fileMetadataService: FileMetadataService,
        private readonly fileValidationService: FileValidationService,
        private readonly fileCleanupService: FileCleanupService,
    ) {
        this.logger.info('SupportTicketsService constructor called');
        if (!this.httpService) {
            this.logger.error('HttpService is undefined in SupportTicketsService constructor');
        } else {
            this.logger.info('HttpService successfully injected');
        }
    }

    async createTicket(userId: string, dto: CreateSupportTicketDto) {
        try {
            const ticket = await this.prisma.supportTicket.create({
                data: {
                    title: dto.title,
                    description: dto.description,
                    priority: dto.priority || Priority.NORMAL,
                    createdById: userId,
                },
                include: {
                    createdBy: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                    replies: {
                        include: {
                            author: {
                                select: {
                                    id: true,
                                    email: true,
                                    name: true,
                                },
                            },
                        },
                        orderBy: {
                            createdAt: 'asc',
                        },
                    },
                },
            });

            // Handle file attachments if provided
            if (dto.attachmentIds && dto.attachmentIds.length > 0) {
                await this.attachFilesToTicket(ticket.id, dto.attachmentIds, userId);
            }

            this.logger.info(`Support ticket created: ${ticket.id} by user ${userId}`);

            return ticket;
        } catch (error) {
            this.logger.error(`Failed to create support ticket for user ${userId}`, error.message);
            throw error;
        }
    }

    async getTickets(userId: string, query: TicketQueryDto, userRoles: string[] = []) {
        try {
            const { page = 1, limit = 10, status, priority, search, sortBy = 'createdAt', sortOrder = 'desc' } = query;

            // Build where clause
            const where: any = {};

            // Users can only see their own tickets unless they have staff/admin roles
            const isStaff = userRoles.includes('admin') || userRoles.includes('staff') || userRoles.includes('support');
            if (!isStaff) {
                where.createdById = userId;
            } else {
                // Staff can see all tickets, but can filter by status
                if (status) {
                    where.status = status;
                }
            }

            if (priority) {
                where.priority = priority;
            }

            if (search) {
                where.OR = [
                    { title: { contains: search, mode: 'insensitive' } },
                    { description: { contains: search, mode: 'insensitive' } },
                ];
            }

            // Get total count for pagination
            const total = await this.prisma.supportTicket.count({ where });

            // Get tickets with pagination
            const tickets = await this.prisma.supportTicket.findMany({
                where,
                include: {
                    createdBy: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                    assignedTo: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                    replies: {
                        take: 1, // Include only the latest reply for preview
                        orderBy: {
                            createdAt: 'desc',
                        },
                        include: {
                            author: {
                                select: {
                                    id: true,
                                    email: true,
                                    name: true,
                                },
                            },
                        },
                    },
                    _count: {
                        select: {
                            replies: true,
                        },
                    },
                },
                orderBy: {
                    [sortBy]: sortOrder,
                },
                skip: (page - 1) * limit,
                take: limit,
            });

            return {
                tickets,
                pagination: {
                    page,
                    limit,
                    total,
                    totalPages: Math.ceil(total / limit),
                },
            };
        } catch (error) {
            this.logger.error(`Failed to get tickets for user ${userId}`, error.message);
            throw error;
        }
    }

    async getTicketById(ticketId: string, userId: string, userRoles: string[] = []) {
        try {
            const ticket = await this.prisma.supportTicket.findUnique({
                where: { id: ticketId },
                include: {
                    createdBy: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                    assignedTo: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                    replies: {
                        include: {
                            author: {
                                select: {
                                    id: true,
                                    email: true,
                                    name: true,
                                },
                            },
                        },
                        orderBy: {
                            createdAt: 'asc',
                        },
                    },
                    reopenRequests: {
                        include: {
                            requestedBy: {
                                select: {
                                    id: true,
                                    email: true,
                                    name: true,
                                },
                            },
                            reviewedBy: {
                                select: {
                                    id: true,
                                    email: true,
                                    name: true,
                                },
                            },
                        },
                        orderBy: {
                            createdAt: 'desc',
                        },
                    },
                },
            });

            if (!ticket) {
                throw new NotFoundException('Ticket not found');
            }

            // Check permissions
            const isStaff = userRoles.includes('admin') || userRoles.includes('staff') || userRoles.includes('support');
            if (!isStaff && ticket.createdById !== userId) {
                throw new ForbiddenException('You can only view your own tickets');
            }

            return ticket;
        } catch (error) {
            if (error instanceof NotFoundException || error instanceof ForbiddenException) {
                throw error;
            }
            this.logger.error(`Failed to get ticket ${ticketId} for user ${userId}`, error.message);
            throw error;
        }
    }

    async updateTicket(ticketId: string, dto: UpdateSupportTicketDto, userId: string, userRoles: string[] = []) {
        try {
            // Check if ticket exists and user has permission
            const ticket = await this.getTicketById(ticketId, userId, userRoles);

            // Only staff can update tickets
            const isStaff = userRoles.includes('admin') || userRoles.includes('staff') || userRoles.includes('support');
            if (!isStaff) {
                throw new ForbiddenException('Only staff members can update tickets');
            }

            const updateData: any = {};

            if (dto.title !== undefined) updateData.title = dto.title;
            if (dto.description !== undefined) updateData.description = dto.description;
            if (dto.priority !== undefined) updateData.priority = dto.priority;
            if (dto.status !== undefined) {
                updateData.status = dto.status;
                // Set closedAt when status changes to CLOSED or RESOLVED
                if (dto.status === TicketStatus.CLOSED || dto.status === TicketStatus.RESOLVED) {
                    updateData.closedAt = new Date();
                } else if (ticket.status === TicketStatus.CLOSED || ticket.status === TicketStatus.RESOLVED) {
                    updateData.closedAt = null;
                }
            }

            const updatedTicket = await this.prisma.supportTicket.update({
                where: { id: ticketId },
                data: updateData,
                include: {
                    createdBy: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                    assignedTo: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                },
            });

            this.logger.info(`Ticket ${ticketId} updated by user ${userId}`);

            return updatedTicket;
        } catch (error) {
            if (error instanceof ForbiddenException || error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Failed to update ticket ${ticketId} for user ${userId}`, error.message);
            throw error;
        }
    }

    async assignTicket(ticketId: string, assigneeId: string | null, userId: string, userRoles: string[] = []) {
        try {
            // Check permissions
            const isStaff = userRoles.includes('admin') || userRoles.includes('staff') || userRoles.includes('support');
            if (!isStaff) {
                throw new ForbiddenException('Only staff members can assign tickets');
            }

            // Check if ticket exists
            const ticket = await this.prisma.supportTicket.findUnique({
                where: { id: ticketId },
            });

            if (!ticket) {
                throw new NotFoundException('Ticket not found');
            }

            // Check if assignee exists and has staff role
            if (assigneeId) {
                const assignee = await this.prisma.user.findUnique({
                    where: { id: assigneeId },
                });

                if (!assignee) {
                    throw new NotFoundException('Assignee not found');
                }

                const assigneeIsStaff = assignee.roles.includes('admin') || assignee.roles.includes('staff') || assignee.roles.includes('support');
                if (!assigneeIsStaff) {
                    throw new BadRequestException('Assignee must be a staff member');
                }
            }

            const updatedTicket = await this.prisma.supportTicket.update({
                where: { id: ticketId },
                data: {
                    assignedToId: assigneeId || null,
                    status: assigneeId ? TicketStatus.IN_PROGRESS : TicketStatus.OPEN,
                },
                include: {
                    createdBy: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                    assignedTo: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                },
            });

            this.logger.info(`Ticket ${ticketId} assigned to ${assigneeId || 'nobody'} by user ${userId}`);

            return updatedTicket;
        } catch (error) {
            if (error instanceof ForbiddenException || error instanceof NotFoundException || error instanceof BadRequestException) {
                throw error;
            }
            this.logger.error(`Failed to assign ticket ${ticketId} for user ${userId}`, error.message);
            throw error;
        }
    }

    async createReply(ticketId: string, userId: string, dto: CreateTicketReplyDto, userRoles: string[] = []) {
        try {
            // Check if ticket exists and user has permission
            const ticket = await this.getTicketById(ticketId, userId, userRoles);

            // Check if user can reply to this ticket
            const isStaff = userRoles.includes('admin') || userRoles.includes('staff') || userRoles.includes('support');
            const isTicketOwner = ticket.createdById === userId;

            // Internal replies can only be made by staff
            if (dto.isInternal && !isStaff) {
                throw new ForbiddenException('Only staff members can create internal replies');
            }

            // Non-internal replies can be made by ticket owner or staff
            if (!dto.isInternal && !isTicketOwner && !isStaff) {
                throw new ForbiddenException('You can only reply to your own tickets');
            }

            const reply = await this.prisma.ticketReply.create({
                data: {
                    ticketId,
                    authorId: userId,
                    content: dto.content,
                    isInternal: dto.isInternal || false,
                },
                include: {
                    author: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                },
            });

            // Handle file attachments if provided
            if (dto.attachmentIds && dto.attachmentIds.length > 0) {
                await this.attachFilesToReply(reply.id, dto.attachmentIds, userId);
            }

            // Update ticket's updatedAt timestamp
            await this.prisma.supportTicket.update({
                where: { id: ticketId },
                data: { updatedAt: new Date() },
            });

            this.logger.info(`Reply created for ticket ${ticketId} by user ${userId}`);

            return reply;
        } catch (error) {
            if (error instanceof ForbiddenException || error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Failed to create reply for ticket ${ticketId} by user ${userId}`, error.message);
            throw error;
        }
    }

    async createReopenRequest(ticketId: string, userId: string, dto: CreateReopenRequestDto) {
        try {
            // Check if ticket exists and user has permission
            const ticket = await this.getTicketById(ticketId, userId);

            // Only ticket owner can create reopen requests
            if (ticket.createdById !== userId) {
                throw new ForbiddenException('You can only reopen your own tickets');
            }

            // Check if ticket is closed
            if (ticket.status !== TicketStatus.CLOSED) {
                throw new BadRequestException('Only closed tickets can be reopened');
            }

            // Check if there's already a pending reopen request
            const existingRequest = await this.prisma.ticketReopenRequest.findFirst({
                where: {
                    ticketId,
                    status: ReopenStatus.PENDING,
                },
            });

            if (existingRequest) {
                throw new BadRequestException('A reopen request is already pending for this ticket');
            }

            const reopenRequest = await this.prisma.ticketReopenRequest.create({
                data: {
                    ticketId,
                    requestedById: userId,
                    reason: dto.reason,
                },
                include: {
                    requestedBy: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                },
            });

            this.logger.info(`Reopen request created for ticket ${ticketId} by user ${userId}`);

            return reopenRequest;
        } catch (error) {
            if (error instanceof ForbiddenException || error instanceof NotFoundException || error instanceof BadRequestException) {
                throw error;
            }
            this.logger.error(`Failed to create reopen request for ticket ${ticketId} by user ${userId}`, error.message);
            throw error;
        }
    }

    async processReopenRequest(requestId: string, approve: boolean, userId: string, userRoles: string[] = []) {
        try {
            // Check permissions
            const isStaff = userRoles.includes('admin') || userRoles.includes('staff') || userRoles.includes('support');
            if (!isStaff) {
                throw new ForbiddenException('Only staff members can process reopen requests');
            }

            // Get the reopen request
            const reopenRequest = await this.prisma.ticketReopenRequest.findUnique({
                where: { id: requestId },
                include: {
                    ticket: true,
                },
            });

            if (!reopenRequest) {
                throw new NotFoundException('Reopen request not found');
            }

            if (reopenRequest.status !== ReopenStatus.PENDING) {
                throw new BadRequestException('This reopen request has already been processed');
            }

            const newStatus = approve ? ReopenStatus.APPROVED : ReopenStatus.REJECTED;

            // Update the reopen request
            const updatedRequest = await this.prisma.ticketReopenRequest.update({
                where: { id: requestId },
                data: {
                    status: newStatus,
                    reviewedById: userId,
                    reviewedAt: new Date(),
                },
                include: {
                    ticket: true,
                    requestedBy: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                    reviewedBy: {
                        select: {
                            id: true,
                            email: true,
                            name: true,
                        },
                    },
                },
            });

            // If approved, reopen the ticket
            if (approve) {
                await this.prisma.supportTicket.update({
                    where: { id: reopenRequest.ticketId },
                    data: {
                        status: TicketStatus.OPEN,
                        closedAt: null,
                    },
                });

                this.logger.info(`Ticket ${reopenRequest.ticketId} reopened via request ${requestId}`);
            } else {
                this.logger.info(`Reopen request ${requestId} rejected`);
            }

            return updatedRequest;
        } catch (error) {
            if (error instanceof ForbiddenException || error instanceof NotFoundException || error instanceof BadRequestException) {
                throw error;
            }
            this.logger.error(`Failed to process reopen request ${requestId} for user ${userId}`, error.message);
            throw error;
        }
    }

    async getStats(userId: string, userRoles: string[] = []) {
        try {
            const isStaff = userRoles.includes('admin') || userRoles.includes('staff') || userRoles.includes('support');

            const baseWhere = isStaff ? {} : { createdById: userId };

            const [totalTickets, openTickets, inProgressTickets, resolvedTickets, closedTickets] = await Promise.all([
                this.prisma.supportTicket.count({ where: baseWhere }),
                this.prisma.supportTicket.count({ where: { ...baseWhere, status: TicketStatus.OPEN } }),
                this.prisma.supportTicket.count({ where: { ...baseWhere, status: TicketStatus.IN_PROGRESS } }),
                this.prisma.supportTicket.count({ where: { ...baseWhere, status: TicketStatus.RESOLVED } }),
                this.prisma.supportTicket.count({ where: { ...baseWhere, status: TicketStatus.CLOSED } }),
            ]);

            return {
                total: totalTickets,
                open: openTickets,
                inProgress: inProgressTickets,
                resolved: resolvedTickets,
                closed: closedTickets,
            };
        } catch (error) {
            this.logger.error(`Failed to get ticket stats for user ${userId}`, error.message);
            throw error;
        }
    }

    /**
     * Attach existing files to a ticket
     * @param ticketId - Ticket ID
     * @param fileIds - Array of file IDs to attach
     * @param userId - User ID for ownership validation
     */
    private async attachFilesToTicket(ticketId: string, fileIds: string[], userId: string) {
        try {
            // Validate that all files exist and belong to the user
            for (const fileId of fileIds) {
                const file = await this.fileMetadataService.getFileMetadataById(fileId);
                if (file.userId !== userId) {
                    throw new ForbiddenException(`You can only attach your own files to tickets`);
                }
                // Check if file is already attached to another ticket or reply
                if (file.supportTicketId || file.ticketReplyId) {
                    throw new BadRequestException(`File ${fileId} is already attached to another item`);
                }
            }

            // Attach files to the ticket
            await this.prisma.fileMetadata.updateMany({
                where: {
                    id: { in: fileIds },
                    userId: userId,
                },
                data: {
                    supportTicketId: ticketId,
                },
            });

            this.logger.info(`Attached ${fileIds.length} files to ticket ${ticketId}`);
        } catch (error) {
            this.logger.error(`Failed to attach files to ticket ${ticketId}`, error.message);
            throw error;
        }
    }

    /**
     * Attach existing files to a reply
     * @param replyId - Reply ID
     * @param fileIds - Array of file IDs to attach
     * @param userId - User ID for ownership validation
     */
    private async attachFilesToReply(replyId: string, fileIds: string[], userId: string) {
        try {
            // Validate that all files exist and belong to the user
            for (const fileId of fileIds) {
                const file = await this.fileMetadataService.getFileMetadataById(fileId);
                if (file.userId !== userId) {
                    throw new ForbiddenException(`You can only attach your own files to replies`);
                }
                // Check if file is already attached to another ticket or reply
                if (file.supportTicketId || file.ticketReplyId) {
                    throw new BadRequestException(`File ${fileId} is already attached to another item`);
                }
            }

            // Attach files to the reply
            await this.prisma.fileMetadata.updateMany({
                where: {
                    id: { in: fileIds },
                    userId: userId,
                },
                data: {
                    ticketReplyId: replyId,
                },
            });

            this.logger.info(`Attached ${fileIds.length} files to reply ${replyId}`);
        } catch (error) {
            this.logger.error(`Failed to attach files to reply ${replyId}`, error.message);
            throw error;
        }
    }

    /**
     * Upload files to a ticket
     * @param ticketId - Ticket ID
     * @param files - Array of uploaded files
     * @param userId - User ID
     * @returns Upload result
     */
    async uploadFilesToTicket(ticketId: string, files: Express.Multer.File[], userId: string) {
        try {
            // Validate ticket exists and user has access
            await this.getTicketById(ticketId, userId, []);

            // TODO: Check current total file size for the ticket via file service
            // For now, assume no limit check as file service handles it

            // Use HTTP call to file service for upload
            const formData = new FormData();
            files.forEach((file) => {
                formData.append('files', new Blob([file.buffer.buffer as any]), file.originalname);
            });
            formData.append('ticketId', ticketId);
            formData.append('userId', userId);

            const response = await this.httpService.post('http://file-service/files/upload', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                },
            }).toPromise();

            this.logger.info(`Uploaded files to ticket ${ticketId}`);

            return response?.data || { success: true };
        } catch (error) {
            this.logger.error(`Failed to upload files to ticket ${ticketId}`, error.message);
            throw error;
        }
    }

    /**
     * Upload files to a reply
     * @param replyId - Reply ID
     * @param files - Array of uploaded files
     * @param ticketId - Ticket ID for access validation
     * @param userId - User ID
     * @returns Upload result
     */
    async uploadFilesToReply(replyId: string, ticketId: string, files: Express.Multer.File[], userId: string, userRoles: string[] = []) {
        try {
            // Validate ticket and reply exist and user has access
            const ticket = await this.getTicketById(ticketId, userId, userRoles);
            const reply = ticket.replies.find(r => r.id === replyId);
            if (!reply) {
                throw new NotFoundException('Reply not found');
            }

            // Use HTTP call to file service for upload
            const formData = new FormData();
            files.forEach((file) => {
                formData.append('files', new Blob([file.buffer.buffer as any]), file.originalname);
            });
            formData.append('replyId', replyId);
            formData.append('userId', userId);

            const response = await this.httpService.post('http://file-service/files/upload', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                },
            }).toPromise();

            this.logger.info(`Uploaded files to reply ${replyId}`);

            return response?.data || { success: true };
        } catch (error) {
            this.logger.error(`Failed to upload files to reply ${replyId}`, error.message);
            throw error;
        }
    }

    /**
     * Remove file from ticket
     * @param ticketId - Ticket ID
     * @param fileId - File ID
     * @param userId - User ID
     */
    async removeFileFromTicket(ticketId: string, fileId: string, userId: string, userRoles: string[] = []) {
        try {
            // Validate ticket exists and user has access
            await this.getTicketById(ticketId, userId, userRoles);

            // Use HTTP call to file service to delete
            await this.httpService.delete(`http://file-service/files/${fileId}`, {
                data: { userId, ticketId },
            }).toPromise();

            this.logger.info(`Removed file ${fileId} from ticket ${ticketId}`);
        } catch (error) {
            this.logger.error(`Failed to remove file ${fileId} from ticket ${ticketId}`, error.message);
            throw error;
        }
    }

    /**
     * Remove file from reply
     * @param ticketId - Ticket ID
     * @param replyId - Reply ID
     * @param fileId - File ID
     * @param userId - User ID
     * @param userRoles - User roles
     */
    async removeFileFromReply(ticketId: string, replyId: string, fileId: string, userId: string, userRoles: string[] = []) {
        try {
            // Validate ticket and reply exist and user has access
            const ticket = await this.getTicketById(ticketId, userId, userRoles);
            const reply = ticket.replies.find(r => r.id === replyId);
            if (!reply) {
                throw new NotFoundException('Reply not found');
            }

            // Use HTTP call to file service to delete
            await this.httpService.delete(`http://file-service/files/${fileId}`, {
                data: { userId, replyId },
            }).toPromise();

            this.logger.info(`Removed file ${fileId} from reply ${replyId}`);
        } catch (error) {
            this.logger.error(`Failed to remove file ${fileId} from reply ${replyId}`, error.message);
            throw error;
        }
    }
}