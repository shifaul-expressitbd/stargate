import { HttpService } from '@nestjs/axios';
import { BadRequestException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { Priority, ReopenStatus, TicketStatus } from '@prisma/client';
import { PrismaService } from '../database/prisma/prisma.service';
import { FileCleanupService } from '../file/services/file-cleanup.service';
import { FileMetadataService } from '../file/services/file-metadata.service';
import { FileStorageService } from '../file/services/file-storage.service';
import { FileValidationService } from '../file/services/file-validation.service';
import { FileService } from '../file/services/file.service';
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
        private readonly fileService: FileService,
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

    async createTicket(userId: string, dto: CreateSupportTicketDto, files?: Express.Multer.File[]) {
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


            // Handle uploaded files if provided
            if (files && files.length > 0) {
                const uploadedFileUrls = await this.uploadFilesToTicket(ticket.id, files, userId);
                if (uploadedFileUrls && uploadedFileUrls.length > 0) {
                    // Get current fileUrls and append new ones
                    const currentTicket = await this.prisma.supportTicket.findUnique({
                        where: { id: ticket.id },
                        select: { fileUrls: true },
                    });
                    const existingUrls = currentTicket?.fileUrls || [];
                    const combinedUrls = [...existingUrls, ...uploadedFileUrls];

                    await this.prisma.supportTicket.update({
                        where: { id: ticket.id },
                        data: {
                            fileUrls: combinedUrls,
                        } as any,
                    });
                    // Add combined fileUrls to the returned ticket object
                    (ticket as any).fileUrls = combinedUrls;
                }
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
            const { page = 1, limit = 10, status, priority, search, sortBy = 'createdAt', sortOrder = 'desc', assigneeId, creatorId } = query;

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

            if (assigneeId) {
                if (!isStaff && assigneeId !== userId) {
                    throw new ForbiddenException('You can only filter tickets assigned to yourself');
                }
                where.assignedToId = assigneeId;
            }

            if (creatorId) {
                if (!isStaff && creatorId !== userId) {
                    throw new ForbiddenException('You can only filter tickets created by yourself');
                }
                where.createdById = creatorId;
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

    async createReply(ticketId: string, userId: string, dto: CreateTicketReplyDto, userRoles: string[] = [], files?: Express.Multer.File[]) {
        try {
            // Check if ticket exists and user has permission
            const ticket = await this.getTicketById(ticketId, userId, userRoles);

            // Check if user can reply to this ticket
            const isStaff = userRoles.includes('admin') || userRoles.includes('staff') || userRoles.includes('support');
            const isTicketOwner = ticket.createdById === userId;
            const isAssignedStaff = isStaff && ticket.assignedToId === userId;

            // Internal replies can only be made by assigned staff
            if (dto.isInternal && !isAssignedStaff) {
                throw new ForbiddenException('Only assigned staff members can create internal replies');
            }

            // Non-internal replies can be made by ticket owner or assigned staff
            if (!dto.isInternal && !isTicketOwner && !isAssignedStaff) {
                throw new ForbiddenException('You can only reply to your own tickets or tickets assigned to you');
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

            // Handle uploaded files if provided
            if (files && files.length > 0) {
                const uploadedFileUrls = await this.uploadFilesToReply(reply.id, ticketId, files, userId, userRoles);
                if (uploadedFileUrls && uploadedFileUrls.files && uploadedFileUrls.files.length > 0) {
                    // Extract file URLs from the upload result
                    const fileUrls: string[] = [];
                    uploadedFileUrls.files.forEach(file => {
                        if (file.downloadUrl) {
                            fileUrls.push(file.downloadUrl);
                        }
                    });

                    // Update reply with file URLs
                    if (fileUrls.length > 0) {
                        await this.prisma.ticketReply.update({
                            where: { id: reply.id },
                            data: {
                                fileUrls: fileUrls,
                            },
                        });

                        // Add fileUrls to the returned reply object
                        (reply as any).fileUrls = fileUrls;
                    }
                }
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
            // Validate ticket exists and user has access
            await this.getTicketById(ticketId, userId);

            // Get all file metadata to collect download URLs
            const fileUrls: string[] = [];
            for (const fileId of fileIds) {
                const file = await this.fileMetadataService.getFileMetadataById(fileId);
                if (!file.uploader || file.uploader.id !== userId) {
                    throw new ForbiddenException(`You can only attach your own files to tickets`);
                }
                // Check if file is already attached to another ticket or reply
                if (file.relatedTicket?.id || file.relatedReply?.id) {
                    throw new BadRequestException(`File ${fileId} is already attached to another item`);
                }
                if (file.downloadUrl) {
                    fileUrls.push(file.downloadUrl);
                }
            }

            // Append file URLs to the ticket's fileUrls array
            if (fileUrls.length > 0) {
                await this.prisma.supportTicket.update({
                    where: { id: ticketId },
                    data: {
                        fileUrls: {
                            push: fileUrls,
                        },
                    },
                });
            }

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
            // Get the ticket to validate access (reply validation happens in getTicketById)
            const ticket = await this.prisma.supportTicket.findUnique({
                where: { id: (await this.prisma.ticketReply.findUnique({ where: { id: replyId } }))?.ticketId },
                include: { replies: true },
            });
            if (!ticket) {
                throw new NotFoundException('Ticket not found');
            }
            const reply = ticket.replies.find(r => r.id === replyId);
            if (!reply) {
                throw new NotFoundException('Reply not found');
            }
            // Check user permissions (staff or ticket owner)
            const isStaff = false; // We'll handle this in the calling method
            const isTicketOwner = ticket.createdById === userId;
            if (!isStaff && !isTicketOwner) {
                throw new ForbiddenException('You can only attach files to your own ticket replies');
            }

            // Get all file metadata to collect download URLs
            const fileUrls: string[] = [];
            for (const fileId of fileIds) {
                const file = await this.fileMetadataService.getFileMetadataById(fileId);
                if (!file.uploader || file.uploader.id !== userId) {
                    throw new ForbiddenException(`You can only attach your own files to replies`);
                }
                // Check if file is already attached to another ticket or reply
                if (file.relatedTicket?.id || file.relatedReply?.id) {
                    throw new BadRequestException(`File ${fileId} is already attached to another item`);
                }
                if (file.downloadUrl) {
                    fileUrls.push(file.downloadUrl);
                }
            }

            // Append file URLs to the reply's fileUrls array
            if (fileUrls.length > 0) {
                await this.prisma.ticketReply.update({
                    where: { id: replyId },
                    data: {
                        fileUrls: {
                            push: fileUrls,
                        },
                    },
                });
            }

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
     * @returns Array of uploaded file URLs
     */
    async uploadFilesToTicket(ticketId: string, files: Express.Multer.File[], userId: string): Promise<string[]> {
        try {
            this.logger.info(`DEBUG: uploadFilesToTicket called with ticketId: ${ticketId}, userId: ${userId}, files length: ${files?.length || 0}`);
            if (files && files.length > 0) {
                files.forEach((file, index) => {
                    this.logger.info(`DEBUG: File ${index}: originalname=${file.originalname}, mimetype=${file.mimetype}, size=${file.size}`);
                });
            }

            // Validate ticket exists and user has access
            await this.getTicketById(ticketId, userId, []);

            this.logger.info(`DEBUG: Ticket validation passed for ticketId: ${ticketId}`);

            // Use local file service for upload
            this.logger.info(`DEBUG: Calling fileService.uploadFiles with ${files.length} files`);
            const uploadResult = await this.fileService.uploadFiles(files);
            this.logger.info(`DEBUG: uploadResult: ${JSON.stringify(uploadResult)}`);

            // Extract file URLs from the upload result
            const fileUrls: string[] = [];
            if (uploadResult.files && uploadResult.files.length > 0) {
                this.logger.info(`DEBUG: Processing ${uploadResult.files.length} files from upload result`);
                uploadResult.files.forEach((file, index) => {
                    this.logger.info(`DEBUG: File ${index} from result: downloadUrl=${file.downloadUrl}, id=${file.id}`);
                    if (file.downloadUrl) {
                        fileUrls.push(file.downloadUrl);
                        this.logger.info(`DEBUG: Added downloadUrl to fileUrls: ${file.downloadUrl}`);
                    } else {
                        this.logger.error(`DEBUG: File ${index} missing downloadUrl`);
                    }
                });
            } else {
                this.logger.error(`DEBUG: uploadResult.files is empty or null`);
            }

            this.logger.info(`DEBUG: Final fileUrls length: ${fileUrls.length}, values: ${JSON.stringify(fileUrls)}`);
            this.logger.info(`Uploaded ${files.length} files to ticket ${ticketId}`);

            return fileUrls;
        } catch (error) {
            this.logger.error(`DEBUG: Exception in uploadFilesToTicket: ${error.message}`, error.stack);
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
     * @returns Upload result with file URLs
     */
    async uploadFilesToReply(replyId: string, ticketId: string, files: Express.Multer.File[], userId: string, userRoles: string[] = []) {
        try {
            // Validate ticket and reply exist and user has access
            const ticket = await this.getTicketById(ticketId, userId, userRoles);
            const reply = ticket.replies.find(r => r.id === replyId);
            if (!reply) {
                throw new NotFoundException('Reply not found');
            }

            // Use local file service for upload
            const uploadResult = await this.fileService.uploadFiles(files);

            this.logger.info(`Uploaded ${files.length} files to reply ${replyId}`);

            return uploadResult;
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
            const ticket = await this.getTicketById(ticketId, userId, userRoles);

            // Get file metadata to validate ownership
            const file = await this.fileMetadataService.getFileMetadataById(fileId);
            if (!file.uploader || file.uploader.id !== userId) {
                throw new ForbiddenException('You can only delete your own files');
            }

            // Check if file is attached to this ticket using fileUrls array
            if (!ticket.fileUrls || !ticket.fileUrls.includes(file.downloadUrl || '')) {
                throw new BadRequestException('File is not attached to this ticket');
            }

            // Use local file service to delete
            await this.fileService.deleteFile(fileId);

            // Remove file URL from ticket's fileUrls array
            const updatedFileUrls = ticket.fileUrls.filter(url => url !== file.downloadUrl);
            await this.prisma.supportTicket.update({
                where: { id: ticketId },
                data: {
                    fileUrls: updatedFileUrls,
                },
            });

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

            // Get file metadata to validate ownership
            const file = await this.fileMetadataService.getFileMetadataById(fileId);
            if (!file.uploader || file.uploader.id !== userId) {
                throw new ForbiddenException('You can only delete your own files');
            }

            // Check if file is attached to this reply using fileUrls array
            if (!reply.fileUrls || !reply.fileUrls.includes(file.downloadUrl || '')) {
                throw new BadRequestException('File is not attached to this reply');
            }

            // Use local file service to delete
            await this.fileService.deleteFile(fileId);

            // Remove file URL from reply's fileUrls array
            const updatedFileUrls = reply.fileUrls.filter(url => url !== file.downloadUrl);
            await this.prisma.ticketReply.update({
                where: { id: replyId },
                data: {
                    fileUrls: updatedFileUrls,
                },
            });

            this.logger.info(`Removed file ${fileId} from reply ${replyId}`);
        } catch (error) {
            this.logger.error(`Failed to remove file ${fileId} from reply ${replyId}`, error.message);
            throw error;
        }
    }
}