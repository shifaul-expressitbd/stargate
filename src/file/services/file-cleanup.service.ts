/**
 * File cleanup service for managing file cleanup operations
 * Handles scheduled cleanup of old files and orphaned metadata
 */

import {
    Inject,
    Injectable,
    Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';
import { PrismaService } from '../../database/prisma/prisma.service';
import { FileConfig } from '../config/file.config';
import { FileCleanupResult } from '../interfaces/file-metadata.interface';
import { FileCleanupCriteria, FileCleanupOptions } from '../interfaces/file-options.interface';
import { FileStorageService } from './file-storage.service';

/**
 * File cleanup service
 * Manages automatic cleanup of old and orphaned files
 */
@Injectable()
export class FileCleanupService {
    private readonly logger = new Logger(FileCleanupService.name);
    private readonly fileConfig: FileConfig;

    constructor(
        private configService: ConfigService,
        @Inject(PrismaService) private prisma: PrismaService,
        private fileStorageService: FileStorageService,
        private schedulerRegistry: SchedulerRegistry,
    ) {
        this.fileConfig = this.configService.get<FileConfig>('file')!;
        this.setupScheduledCleanup();
    }

    /**
     * Set up the scheduled cleanup job
     */
    private setupScheduledCleanup(): void {
        const cronJob = new CronJob(this.fileConfig.cleanup.cronSchedule, () => {
            this.scheduledCleanup();
        });

        this.schedulerRegistry.addCronJob('scheduledCleanup', cronJob);
        cronJob.start();
    }

    /**
     * Scheduled cleanup job
     * Runs based on cron schedule from configuration
     */
    async scheduledCleanup(): Promise<void> {
        if (!this.fileConfig.cleanup.enabled) {
            this.logger.debug('File cleanup is disabled');
            return;
        }

        try {
            this.logger.log('Starting scheduled file cleanup');
            const result = await this.cleanupFiles({
                maxAgeDays: this.fileConfig.cleanup.maxAgeDays,
                dryRun: false,
            });

            this.logger.log(
                `Scheduled cleanup completed: ${result.deleted} files deleted, ${result.failed} failed, ${result.formattedSpaceFreed} freed from ${result.processed} total files processed`,
            );
        } catch (error) {
            this.logger.error(`Scheduled cleanup failed: ${error.message}`, {
                error: error.message,
                stack: error.stack,
                cleanupConfig: {
                    enabled: this.fileConfig.cleanup.enabled,
                    maxAgeDays: this.fileConfig.cleanup.maxAgeDays,
                    cronSchedule: this.fileConfig.cleanup.cronSchedule,
                },
            });
        }
    }

    /**
     * Cleanup files based on criteria
     * @param options - Cleanup options
     * @returns Cleanup result
     */
    async cleanupFiles(options: FileCleanupOptions = {}): Promise<FileCleanupResult> {
        const result: FileCleanupResult = {
            processed: 0,
            deleted: 0,
            failed: 0,
            spaceFreed: 0,
            formattedSpaceFreed: '0 B',
            errors: [],
            dryRun: options.dryRun || false,
        };

        try {
            const criteria: FileCleanupCriteria = {
                olderThan: options.maxAgeDays ? options.maxAgeDays * 24 * 60 * 60 * 1000 : undefined,
                ...options.criteria,
            };

            // Find files matching cleanup criteria
            const filesToCleanup = await this.findFilesForCleanup(criteria);

            result.processed = filesToCleanup.length;
            this.logger.log(`Found ${filesToCleanup.length} files for cleanup`);

            // Process each file
            for (const file of filesToCleanup) {
                try {
                    const fileSize = file.size;

                    if (!options.dryRun) {
                        // Delete physical file
                        const deleted = await this.fileStorageService.deleteFile(file.path);

                        if (deleted) {
                            // Delete metadata from database
                            await this.prisma.fileMetadata.delete({
                                where: { id: file.id },
                            });

                            result.deleted++;
                            result.spaceFreed += fileSize;
                        } else {
                            result.failed++;
                            result.errors.push({
                                fileId: file.id,
                                filename: file.filename,
                                error: 'Failed to delete physical file',
                            });
                        }
                    } else {
                        // Dry run - just count
                        result.deleted++;
                        result.spaceFreed += fileSize;
                    }
                } catch (error) {
                    result.failed++;
                    result.errors.push({
                        fileId: file.id,
                        filename: file.filename,
                        error: error.message,
                    });
                    this.logger.warn(`Failed to cleanup file ${file.id}: ${error.message}`);
                }
            }

            result.formattedSpaceFreed = this.fileStorageService.formatFileSize(result.spaceFreed);

            this.logger.log(
                `Cleanup completed: ${result.deleted} deleted, ${result.failed} failed, ${result.formattedSpaceFreed} freed`,
            );

            return result;
        } catch (error) {
            this.logger.error(`File cleanup failed: ${error.message}`, error.stack);
            throw error;
        }
    }

    /**
     * Find orphaned metadata (files that exist in DB but not on disk)
     * @returns Array of orphaned file metadata
     */
    async findOrphanedMetadata(): Promise<Array<{ id: string; filename: string; path: string }>> {
        try {
            const allFiles = await this.prisma.fileMetadata.findMany({
                select: {
                    id: true,
                    filename: true,
                    path: true,
                },
            });

            const orphaned: Array<{ id: string; filename: string; path: string }> = [];

            for (const file of allFiles) {
                const exists = await this.fileStorageService.fileExists(file.path);
                if (!exists) {
                    orphaned.push(file);
                }
            }

            this.logger.log(`Found ${orphaned.length} orphaned metadata records`);
            return orphaned;
        } catch (error) {
            this.logger.error(`Failed to find orphaned metadata: ${error.message}`, error.stack);
            throw error;
        }
    }

    /**
     * Clean up orphaned metadata
     * @param dryRun - Whether to perform dry run
     * @returns Cleanup result
     */
    async cleanupOrphanedMetadata(dryRun: boolean = false): Promise<{
        processed: number;
        deleted: number;
        errors: Array<{ fileId: string; filename: string; error: string }>;
    }> {
        try {
            const orphaned = await this.findOrphanedMetadata();
            const result = {
                processed: orphaned.length,
                deleted: 0,
                errors: [] as Array<{ fileId: string; filename: string; error: string }>,
            };

            for (const file of orphaned) {
                try {
                    if (!dryRun) {
                        await this.prisma.fileMetadata.delete({
                            where: { id: file.id },
                        });
                    }
                    result.deleted++;
                } catch (error) {
                    result.errors.push({
                        fileId: file.id,
                        filename: file.filename,
                        error: error.message,
                    });
                }
            }

            this.logger.log(`Orphaned metadata cleanup: ${result.deleted} deleted, ${result.errors.length} errors`);
            return result;
        } catch (error) {
            this.logger.error(`Orphaned metadata cleanup failed: ${error.message}`, error.stack);
            throw error;
        }
    }

    /**
     * Find files matching cleanup criteria
     * @param criteria - Cleanup criteria
     * @returns Array of files to cleanup
     */
    private async findFilesForCleanup(criteria: FileCleanupCriteria): Promise<Array<{
        id: string;
        filename: string;
        path: string;
        size: number;
        createdAt: Date;
    }>> {
        const where: any = {};

        // Age criteria
        if (criteria.olderThan) {
            where.createdAt = {
                lt: new Date(Date.now() - criteria.olderThan),
            };
        }

        // File type criteria
        if (criteria.fileTypes && criteria.fileTypes.length > 0) {
            where.mimeType = {
                in: criteria.fileTypes,
            };
        }

        // Directory criteria
        if (criteria.includeDirs && criteria.includeDirs.length > 0) {
            where.path = {
                startsWith: criteria.includeDirs.map(dir => dir.replace(/\/$/, '')),
            };
        }

        if (criteria.excludeDirs && criteria.excludeDirs.length > 0) {
            where.NOT = where.NOT || {};
            where.NOT.path = {
                startsWith: criteria.excludeDirs.map(dir => dir.replace(/\/$/, '')),
            };
        }

        // Exclude files matching patterns
        if (criteria.excludePatterns && criteria.excludePatterns.length > 0) {
            where.NOT = where.NOT || {};
            where.NOT.OR = criteria.excludePatterns.map(pattern => ({
                filename: { regex: pattern.source },
            }));
        }

        return await this.prisma.fileMetadata.findMany({
            where,
            select: {
                id: true,
                filename: true,
                path: true,
                size: true,
                createdAt: true,
            },
            orderBy: {
                createdAt: 'asc', // Oldest first
            },
        });
    }

    /**
     * Get cleanup statistics
     * @returns Cleanup statistics
     */
    async getCleanupStatistics(): Promise<{
        eligibleForCleanup: number;
        totalSize: number;
        oldestFile: Date | null;
        byAge: {
            '30days': number;
            '90days': number;
            '1year': number;
        };
    }> {
        try {
            const now = new Date();
            const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
            const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
            const oneYearAgo = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);

            // Files eligible for cleanup (older than configured max age)
            const eligibleFiles = await this.prisma.fileMetadata.findMany({
                where: {
                    createdAt: {
                        lt: new Date(Date.now() - this.fileConfig.cleanup.maxAgeDays * 24 * 60 * 60 * 1000),
                    },
                },
                select: {
                    size: true,
                    createdAt: true,
                },
            });

            // Age distribution
            const [thirtyDays, ninetyDays, oneYear] = await Promise.all([
                this.prisma.fileMetadata.count({ where: { createdAt: { lt: thirtyDaysAgo } } }),
                this.prisma.fileMetadata.count({ where: { createdAt: { lt: ninetyDaysAgo } } }),
                this.prisma.fileMetadata.count({ where: { createdAt: { lt: oneYearAgo } } }),
            ]);

            const totalSize = eligibleFiles.reduce((sum, file) => sum + file.size, 0);
            const oldestFile = eligibleFiles.length > 0
                ? eligibleFiles.reduce((oldest, file) =>
                    file.createdAt < oldest ? file.createdAt : oldest,
                    eligibleFiles[0].createdAt
                )
                : null;

            return {
                eligibleForCleanup: eligibleFiles.length,
                totalSize,
                oldestFile,
                byAge: {
                    '30days': thirtyDays,
                    '90days': ninetyDays,
                    '1year': oneYear,
                },
            };
        } catch (error) {
            this.logger.error(`Failed to get cleanup statistics: ${error.message}`, error.stack);
            throw error;
        }
    }
}