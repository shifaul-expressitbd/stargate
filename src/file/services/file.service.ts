/**
 * File Service
 * Orchestrates file operations using StorageManagerService
 * Focuses on file upload, storage selection, and metadata management
 */

import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FileMetadataDto } from '../dto/file-metadata.dto';
import { MulterFile } from '../interfaces/file-options.interface';
import { StorageProvider } from '../interfaces/storage.interface';
import { FileMetadataService } from './file-metadata.service';
import { FileValidationService } from './file-validation.service';
import { StorageManagerService } from './storage-manager.service';

/**
 * Utility function to convert string storage provider to enum
 */
function parseStorageProvider(provider: string): StorageProvider | undefined {
    const validProviders = Object.values(StorageProvider) as string[];
    if (validProviders.includes(provider)) {
        return provider as StorageProvider;
    }
    return undefined;
}

/**
 * Infer storage provider from upload result
 */
function inferProviderFromResult(result: any): StorageProvider {
    const url = result.url || '';

    // Check URL patterns to determine provider
    if (url.includes('cloudinary.com') || url.includes('res.cloudinary.com')) {
        return StorageProvider.CLOUDINARY;
    }
    if (url.includes('s3.') || url.includes('amazonaws.com')) {
        return StorageProvider.S3;
    }
    if (url.startsWith('http://localhost') || url.startsWith('http://127.0.0.1')) {
        return StorageProvider.LOCAL;
    }

    // Default fallback
    return StorageProvider.LOCAL;
}

@Injectable()
export class FileService {
    private readonly logger = new Logger(FileService.name);

    constructor(
        private configService: ConfigService,
        private storageManagerService: StorageManagerService,
        private fileMetadataService: FileMetadataService,
        private fileValidationService: FileValidationService,
    ) { }

    /**
     * Upload a single file with automatic storage selection
     */
    async uploadFile(
        file: MulterFile,
        metadata?: {
            originalName?: string;
            category?: string;
            storageProvider?: string;
        }
    ): Promise<FileMetadataDto> {
        let uploadResult: any = null;
        let selectedProvider: StorageProvider | undefined;

        try {
            this.logger.log(`Starting file upload for: ${file.originalname}`, {
                filename: file.filename,
                mimetype: file.mimetype,
                size: file.size,
                hasBuffer: !!file.buffer,
                hasPath: !!file.path,
            });

            // Upload file using storage manager with explicit provider if specified
            const uploadOptions: any = {
                mimeType: file.mimetype,
                metadata: {
                    category: metadata?.category,
                }
            };

            // If storage provider is explicitly specified, use it
            if (metadata?.storageProvider) {
                const preferredProvider = parseStorageProvider(metadata.storageProvider);
                if (preferredProvider) {
                    uploadOptions.preferredProvider = preferredProvider;
                    selectedProvider = preferredProvider;
                    this.logger.log(`Using specified storage provider: ${preferredProvider}`);
                } else {
                    this.logger.warn(`Invalid storage provider specified: ${metadata.storageProvider}`);
                }
            }

            // Attempt file upload to storage
            uploadResult = await this.storageManagerService.uploadFile(file, uploadOptions);
            this.logger.log(`File storage upload successful: ${uploadResult.key}`);

            // Determine which provider was actually used (fallback if preferred wasn't set)
            if (!selectedProvider) {
                // We need to determine the provider from the upload result
                // Since the storage manager doesn't return the provider, we'll infer it
                selectedProvider = inferProviderFromResult(uploadResult);
                this.logger.log(`Inferred storage provider: ${selectedProvider}`);
            }

            // Validate upload result before creating metadata
            if (!uploadResult.success) {
                this.logger.error(`Storage upload failed:`, uploadResult);
                throw new Error(`Storage upload failed: ${uploadResult.error || 'Unknown error'}`);
            }

            if (!uploadResult.key) {
                this.logger.error(`Storage upload returned no key:`, uploadResult);
                throw new Error('Storage upload failed: No storage key returned');
            }

            // Create metadata record
            const fileMetadata = await this.fileMetadataService.createFileMetadata({
                filename: uploadResult.metadata.filename,
                originalName: metadata?.originalName || file.originalname,
                mimeType: file.mimetype,
                size: file.size,
                storageProvider: selectedProvider as string,
                storageKey: uploadResult.key,
                storageUrl: uploadResult.url,
                category: metadata?.category,
            });

            this.logger.log(`File upload completed successfully: ${fileMetadata.id}`, {
                storageKey: uploadResult.key,
                storageProvider: selectedProvider,
                processingStatus: fileMetadata.processingStatus,
            });

            return fileMetadata as unknown as FileMetadataDto;

        } catch (error) {
            this.logger.error(`File upload failed: ${error.message}`, {
                error: error.message,
                stack: error.stack,
                filename: file.originalname,
                selectedProvider,
                uploadResultKey: uploadResult?.key,
                uploadResultSuccess: uploadResult?.success,
            });

            // Cleanup: If storage upload succeeded but metadata creation failed, delete the uploaded file
            if (uploadResult && uploadResult.success && uploadResult.key && selectedProvider) {
                try {
                    this.logger.log(`Attempting cleanup of uploaded file due to metadata creation failure: ${uploadResult.key}`);
                    await this.storageManagerService.deleteFile(uploadResult.key, selectedProvider);
                    this.logger.log(`Successfully cleaned up uploaded file: ${uploadResult.key}`);
                } catch (cleanupError) {
                    this.logger.error(`Failed to cleanup uploaded file ${uploadResult.key}: ${cleanupError.message}`, cleanupError.stack);
                    // Don't throw cleanup errors as they shouldn't mask the original error
                }
            }

            throw error;
        }
    }

    /**
     * Upload multiple files with automatic storage selection
     */
    async uploadFiles(
        files: MulterFile[],
        options?: {
            maxSize?: number;
            allowedTypes?: string[];
            storageProvider?: string;
            category?: string;
        }
    ): Promise<{
        files: FileMetadataDto[];
        failed: Array<{ originalName: string; error: string }>;
        totalSize: number;
        success: boolean;
    }> {
        const uploadedFiles: FileMetadataDto[] = [];
        const failedFiles: Array<{ originalName: string; error: string }> = [];
        let totalSize = 0;

        try {
            this.logger.log(`Starting batch upload of ${files.length} files`, {
                maxSize: options?.maxSize,
                allowedTypes: options?.allowedTypes,
                storageProvider: options?.storageProvider,
                category: options?.category,
            });

            // Validate files
            const validationOptions = {
                maxSize: options?.maxSize || 10 * 1024 * 1024, // 10MB default
                ...(options?.allowedTypes && options.allowedTypes.length > 0 && {
                    allowedTypes: options.allowedTypes
                }),
            };

            const { valid, invalid } = await this.fileValidationService.validateFiles(
                files,
                validationOptions,
            );

            // Add validation failures to failed list
            failedFiles.push(...invalid.map(f => ({
                originalName: f.file.originalname,
                error: f.error,
            })));

            if (valid.length === 0) {
                this.logger.warn(`No valid files to upload after validation`);
                return {
                    files: [],
                    failed: failedFiles,
                    totalSize: 0,
                    success: false,
                };
            }

            this.logger.log(`Processing ${valid.length} valid files for upload`);

            // Process valid files sequentially to maintain order and proper error handling
            for (const file of valid) {
                try {
                    this.logger.debug(`Uploading file: ${file.originalname}`);
                    const fileMetadata = await this.uploadFile(file, {
                        storageProvider: options?.storageProvider,
                        category: options?.category,
                    });
                    uploadedFiles.push(fileMetadata);
                    totalSize += file.size;
                    this.logger.debug(`Successfully uploaded: ${file.originalname} -> ${fileMetadata.id}`);
                } catch (error) {
                    const errorMsg = error.message || 'Unknown upload error';
                    this.logger.error(`Failed to upload file ${file.originalname}: ${errorMsg}`, {
                        error: errorMsg,
                        stack: error.stack,
                        filename: file.filename,
                        originalname: file.originalname,
                        mimetype: file.mimetype,
                        size: file.size,
                    });
                    failedFiles.push({
                        originalName: file.originalname,
                        error: errorMsg,
                    });
                }
            }

            const success = failedFiles.length === 0;
            this.logger.log(`Batch upload completed`, {
                totalFiles: files.length,
                uploadedCount: uploadedFiles.length,
                failedCount: failedFiles.length,
                totalSize,
                success,
            });

            return {
                files: uploadedFiles,
                failed: failedFiles,
                totalSize,
                success,
            };
        } catch (error) {
            this.logger.error(`Batch file upload failed: ${error.message}`, {
                error: error.message,
                stack: error.stack,
                totalFiles: files.length,
                uploadedSoFar: uploadedFiles.length,
                failedSoFar: failedFiles.length,
            });
            throw error;
        }
    }

    /**
     * Get file by ID with download stream
     */
    async getFileById(id: string): Promise<{
        metadata: FileMetadataDto;
        stream: NodeJS.ReadableStream;
        stats: { size: number };
        mimeType: string;
    }> {
        try {
            // Get metadata
            const metadata = await this.fileMetadataService.getFileMetadataById(id);

            // Check if file has a valid storage key (not failed upload)
            if (!metadata.storageKey) {
                this.logger.error(`File ${id} has no storage key (failed upload) - cannot download`, {
                    filename: metadata.filename,
                    originalName: metadata.originalName,
                    processingStatus: metadata.processingStatus,
                });
                throw new Error('File upload failed previously - file is not available for download');
            }

            // Get file stream from storage
            const downloadResult = await this.storageManagerService.downloadFile(
                metadata.storageKey,
                metadata.storageProvider as StorageProvider
            );

            if (!downloadResult.stream) {
                throw new Error('File stream not available');
            }

            return {
                metadata: metadata as unknown as FileMetadataDto,
                stream: downloadResult.stream as NodeJS.ReadableStream,
                stats: {
                    size: downloadResult.metadata?.size || metadata.size
                },
                mimeType: downloadResult.metadata?.mimeType || metadata.mimeType,
            };
        } catch (error) {
            this.logger.error(`Failed to get file ${id}: ${error.message}`, error.stack);
            throw error;
        }
    }

    /**
     * Get all files with pagination and filtering
     */
    async getAllFiles(options?: {
        page?: number;
        limit?: number;
        storageProvider?: string;
        category?: string;
        query?: string;
        mimeType?: string;
        uploaderId?: string;
        ticketId?: string;
        minSize?: number;
        maxSize?: number;
        dateFrom?: Date;
        dateTo?: Date;
        securityStatus?: string;
        processingStatus?: string;
        sortBy?: string;
        sortOrder?: string;
        include?: string[];
    }): Promise<{
        files: FileMetadataDto[];
        pagination: {
            page: number;
            limit: number;
            total: number;
            totalPages: number;
            hasNext: boolean;
            hasPrev: boolean;
        };
    }> {
        try {
            const page = options?.page || 1;
            const limit = options?.limit || 20;

            // Use the enhanced search method that supports all filters
            const searchCriteria = {
                query: options?.query,
                uploaderId: options?.uploaderId,
                mimeType: options?.mimeType,
                sizeRange: options?.minSize || options?.maxSize ? {
                    min: options?.minSize,
                    max: options?.maxSize,
                } : undefined,
                dateRange: options?.dateFrom || options?.dateTo ? {
                    from: options?.dateFrom,
                    to: options?.dateTo,
                } : undefined,
                relatedTo: options?.ticketId ? {
                    ticketId: options?.ticketId,
                } : undefined,
            };

            // Filter out undefined values
            Object.keys(searchCriteria).forEach(key => {
                if (searchCriteria[key] === undefined) {
                    delete searchCriteria[key];
                }
            });

            const result = await this.fileMetadataService.searchFiles(
                searchCriteria,
                { page, limit }
            );

            return {
                files: result.files as unknown as FileMetadataDto[],
                pagination: {
                    page: result.page,
                    limit: result.limit,
                    total: result.total,
                    totalPages: result.totalPages,
                    hasNext: result.page < result.totalPages,
                    hasPrev: result.page > 1,
                },
            };
        } catch (error) {
            this.logger.error(`Failed to get all files: ${error.message}`, error.stack);
            throw error;
        }
    }

    /**
     * Delete file by ID
     */
    async deleteFile(id: string): Promise<FileMetadataDto> {
        try {
            // Get metadata first
            const metadata = await this.fileMetadataService.getFileMetadataById(id);

            // Delete from storage if file has a valid storage key
            if (metadata.storageKey) {
                try {
                    await this.storageManagerService.deleteFile(
                        metadata.storageKey,
                        metadata.storageProvider as StorageProvider
                    );
                    this.logger.log(`File deleted from storage: ${metadata.storageKey}`);
                } catch (storageError) {
                    this.logger.warn(`Failed to delete file from storage ${metadata.storageKey}: ${storageError.message}`, {
                        storageProvider: metadata.storageProvider,
                        filename: metadata.filename,
                    });
                    // Continue with metadata deletion even if storage deletion fails
                }
            } else {
                this.logger.warn(`File ${id} has no storage key (failed upload) - skipping storage deletion`, {
                    filename: metadata.filename,
                    originalName: metadata.originalName,
                    processingStatus: metadata.processingStatus,
                });
            }

            // Delete metadata
            const deletedMetadata = await this.fileMetadataService.deleteFileMetadata(id);

            this.logger.log(`File metadata deleted successfully: ${id}`);
            return deletedMetadata as unknown as FileMetadataDto;
        } catch (error) {
            this.logger.error(`Failed to delete file ${id}: ${error.message}`, error.stack);
            throw error;
        }
    }

    /**
     * Get file by filename with download stream
     */
    async getFileByFilename(filename: string): Promise<{
        metadata: FileMetadataDto;
        stream: NodeJS.ReadableStream;
        stats: { size: number };
        mimeType: string;
    }> {
        try {
            // Get metadata by filename
            const metadata = await this.fileMetadataService.getFileMetadataByFilename(filename);

            // Check if file has a valid storage key (not failed upload)
            if (!metadata.storageKey) {
                this.logger.error(`File ${filename} has no storage key (failed upload) - cannot download`, {
                    filename: metadata.filename,
                    originalName: metadata.originalName,
                    processingStatus: metadata.processingStatus,
                });
                throw new Error('File upload failed previously - file is not available for download');
            }

            // Get file stream from storage
            const downloadResult = await this.storageManagerService.downloadFile(
                metadata.storageKey,
                metadata.storageProvider as StorageProvider
            );

            if (!downloadResult.stream) {
                throw new Error('File stream not available');
            }

            return {
                metadata: metadata as unknown as FileMetadataDto,
                stream: downloadResult.stream as NodeJS.ReadableStream,
                stats: {
                    size: downloadResult.metadata?.size || metadata.size
                },
                mimeType: downloadResult.metadata?.mimeType || metadata.mimeType,
            };
        } catch (error) {
            this.logger.error(`Failed to get file ${filename}: ${error.message}`, error.stack);
            throw error;
        }
    }

    /**
     * Get file statistics
     */
    async getFileStatistics(): Promise<{
        totalCount: number;
        totalSize: number;
        byStorageProvider: Record<string, number>;
        byCategory: Record<string, number>;
    }> {
        const stats = await this.fileMetadataService.getFileStatistics();
        return {
            totalCount: stats.totalCount,
            totalSize: stats.totalSize,
            byStorageProvider: {}, // Will be implemented in FileMetadataService
            byCategory: stats.byCategory,
        };
    }
}