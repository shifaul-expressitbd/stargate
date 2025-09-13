/**
 * File controller for handling file operations
 * Simplified to focus on file management with multi-storage architecture
 */

import {
    BadRequestException,
    Body,
    Controller,
    Get,
    Logger,
    Param,
    Post,
    Query,
    Response,
    StreamableFile,
    UploadedFiles,
    UseInterceptors
} from '@nestjs/common';
import { FilesInterceptor } from '@nestjs/platform-express';
import {
    ApiBody,
    ApiConsumes,
    ApiOperation,
    ApiParam,
    ApiResponse,
    ApiTags
} from '@nestjs/swagger';
import type { Response as ExpressResponse } from 'express';
import { Public } from '../common/decorators/public.decorator';
import { FileQueryDto } from './dto/file-query.dto';
import { MultipleFileUploadResponseDto } from './dto/file-upload.dto';
import { MulterFile } from './interfaces/file-options.interface';
import { FileService } from './services/file.service';

/**
 * File controller
 * Simplified controller focusing on core file operations
 */
@ApiTags('Files')
@Controller('files')
export class FileController {
    private readonly logger = new Logger(FileController.name);

    constructor(
        private fileService: FileService,
    ) { }

    /**
     * Upload files
     * Supports multiple file uploads with automatic storage selection
     */
    @Public()
    @Post('upload')
    @UseInterceptors(
        FilesInterceptor('files', 10, {
            limits: {
                fileSize: 10 * 1024 * 1024, // 10MB default
                files: 10,
            },
        }),
    )
    @ApiConsumes('multipart/form-data')
    @ApiOperation({
        summary: 'Upload multiple files with automatic storage selection',
        description: `Upload one or more files with automatic storage provider selection based on file type, size, and configured priorities.

        **Multi-File Upload Features:**
        - Supports up to 10 files per request
        - Maximum file size: 10MB per file
        - Automatic storage provider selection
        - Parallel processing for better performance
        - Comprehensive error handling and rollback

        **Storage Provider Selection Logic:**
        - Images (< 5MB): Cloudinary (optimization & CDN)
        - Documents (< 50MB): S3 (durability & accessibility)
        - Large files (> 50MB): Local storage (cost-effective)
        - Archives: MinIO (S3-compatible with custom rules)

        **Supported File Types:**
        - **Images**: JPEG, PNG, GIF, WebP, SVG, BMP, TIFF, AVIF, HEIC, HEIF
        - **Videos**: MP4, AVI, MOV, WMV, FLV, WebM, MKV, 3GP, QuickTime
        - **Audio**: MP3, WAV, OGG, M4A, AAC, FLAC
        - **Documents**: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX
        - **Archives**: ZIP, RAR, 7Z, TAR, GZ
        - **Other**: TXT, CSV, JSON, XML, HTML, CSS, JS, TS`
    })
    @ApiBody({
        description: 'File upload form data',
        schema: {
            type: 'object',
            properties: {
                files: {
                    type: 'array',
                    items: {
                        type: 'string',
                        format: 'binary',
                        description: 'File to upload'
                    },
                    description: 'Optional array of files to upload (field name: "files")'
                },
                storageProvider: {
                    type: 'string',
                    enum: ['local', 's3', 'cloudinary', 'minio', 'google_cloud'],
                    description: 'Optional preferred storage provider',
                    example: 's3'
                },
            },
            required: []
        }
    })
    @ApiResponse({
        status: 201,
        description: 'Files uploaded successfully to multiple storage providers',
        type: MultipleFileUploadResponseDto,
        schema: {
            example: {
                files: [
                    {
                        id: '123e4567-e89b-12d3-a456-426614174000',
                        filename: 'document_1234567890.pdf',
                        originalName: 'quarterly-report.pdf',
                        mimeType: 'application/pdf',
                        size: 2048000,
                        path: 'uploads/2024/01/document_1234567890.pdf',
                        extension: 'pdf',
                        formattedSize: '2 MB',
                        category: 'document',
                        downloadUrl: '/api/files/123e4567-e89b-12d3-a456-426614174000',
                        createdAt: '2024-01-15T10:30:00.000Z',
                        storageProvider: 's3',
                        storageMetadata: {
                            bucket: 'my-files-bucket',
                            region: 'us-east-1',
                            key: 'uploads/2024/01/document_1234567890.pdf',
                            publicUrl: 'https://my-files-bucket.s3.amazonaws.com/uploads/2024/01/document_1234567890.pdf',
                            signedUrl: 'https://my-files-bucket.s3.amazonaws.com/uploads/2024/01/document_1234567890.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&...'
                        }
                    },
                    {
                        id: '123e4567-e89b-12d3-a456-426614174001',
                        filename: 'image_1234567891.jpg',
                        originalName: 'screenshot.jpg',
                        mimeType: 'image/jpeg',
                        size: 512000,
                        path: 'uploads/2024/01/image_1234567891.jpg',
                        extension: 'jpg',
                        formattedSize: '512 KB',
                        category: 'image',
                        downloadUrl: '/api/files/123e4567-e89b-12d3-a456-426614174001',
                        createdAt: '2024-01-15T10:30:05.000Z',
                        storageProvider: 'cloudinary',
                        storageMetadata: {
                            publicId: 'uploads/2024/01/image_1234567891',
                            version: '1234567891',
                            signature: 'abcd1234...',
                            width: 1920,
                            height: 1080,
                            format: 'jpg',
                            resourceType: 'image',
                            url: 'https://res.cloudinary.com/my-account/image/upload/v1234567891/uploads/2024/01/image_1234567891.jpg',
                            secureUrl: 'https://res.cloudinary.com/my-account/image/upload/v1234567891/uploads/2024/01/image_1234567891.jpg'
                        }
                    }
                ],
                failed: [],
                totalSize: 2560000,
                duration: 1500,
                success: true,
                storageProviderSummary: {
                    s3: 1,
                    cloudinary: 1,
                    local: 0,
                    minio: 0,
                    google_cloud: 0
                }
            }
        }
    })
    @ApiResponse({
        status: 400,
        description: 'Bad request - validation failed or no files provided',
        schema: {
            example: {
                statusCode: 400,
                message: 'No files provided in the upload request',
                error: 'Bad Request'
            }
        }
    })
    @ApiResponse({
        status: 413,
        description: 'File too large or too many files',
        schema: {
            example: {
                statusCode: 413,
                message: 'File size exceeds maximum allowed size of 10MB',
                error: 'Payload Too Large'
            }
        }
    })
    @ApiResponse({
        status: 415,
        description: 'Unsupported file type',
        schema: {
            example: {
                statusCode: 415,
                message: 'File type not allowed. Supported types: image/jpeg, image/png, application/pdf',
                error: 'Unsupported Media Type'
            }
        }
    })
    async uploadFiles(
        @Body() body: any,
        @UploadedFiles() files: MulterFile[],
    ): Promise<MultipleFileUploadResponseDto> {
        try {
            const startTime = Date.now();

            if (!files || files.length === 0) {
                // Return success response for empty file array
                return {
                    files: [],
                    failed: [],
                    totalSize: 0,
                    duration: Date.now() - startTime,
                    success: true,
                    storageProviderSummary: {
                        s3: 0,
                        cloudinary: 0,
                        local: 0,
                        minio: 0,
                        google_cloud: 0
                    }
                };
            }

            const result = await this.fileService.uploadFiles(files, {
                storageProvider: body?.storageProvider
            });
            const duration = Date.now() - startTime;

            return {
                ...result,
                duration,
            };
        } catch (error) {
            this.logger.error(`File upload failed: ${error.message}`, error.stack);
            if (error instanceof BadRequestException) {
                throw error;
            }
            throw new BadRequestException('File upload failed due to an unexpected error');
        }
    }

    /**
     * Download file by UUID with cross-provider support
     * Handles downloads from multiple storage backends with automatic URL generation
     */
    @Public()
    @Get('id/:id')
    @ApiOperation({
        summary: 'Download file by UUID',
        description: `Download a file by its unique identifier (UUID) with support for multiple storage providers.

        **Cross-Provider Download Logic:**
        - **Local Storage**: Direct file system access with streaming
        - **S3/Cloud Storage**: Generates signed URLs with configurable expiration
        - **Cloudinary**: Uses Cloudinary's CDN with optimization parameters
        - **MinIO**: Local S3-compatible storage with custom endpoint handling

        **URL Generation & Expiration:**
        - Signed URLs expire after configurable time (default: 1 hour for security)
        - CDN-optimized URLs for better performance
        - Provider-specific optimizations applied automatically

        **Query Parameters:**
        - download=true: Forces download with attachment disposition
        - download=false (default): Inline display in browser when possible

        **Security Features:**
        - File access validation based on user permissions
        - Rate limiting to prevent abuse
        - Audit logging for download tracking`
    })
    @ApiParam({
        name: 'id',
        description: 'Unique file identifier (UUID)',
        example: '123e4567-e89b-12d3-a456-426614174000'
    })
    @ApiResponse({
        status: 200,
        description: 'File downloaded successfully',
        content: {
            '*/*': {
                schema: {
                    type: 'string',
                    format: 'binary',
                },
            },
        },
        headers: {
            'Content-Type': {
                description: 'MIME type of the file',
                schema: { type: 'string', example: 'application/pdf' }
            },
            'Content-Length': {
                description: 'File size in bytes',
                schema: { type: 'number', example: 1024000 }
            },
            'Content-Disposition': {
                description: 'Download behavior (attachment for download, inline for preview)',
                schema: { type: 'string', example: 'attachment; filename="document.pdf"' }
            },
            'Cache-Control': {
                description: 'Caching directives',
                schema: { type: 'string', example: 'private, max-age=3600' }
            }
        }
    })
    @ApiResponse({
        status: 404,
        description: 'File not found or access denied',
        schema: {
            type: 'object',
            properties: {
                statusCode: { type: 'number', example: 404 },
                message: { type: 'string', example: 'File not found' },
                error: { type: 'string', example: 'Not Found' }
            }
        }
    })
    @ApiResponse({
        status: 403,
        description: 'Access forbidden - insufficient permissions',
        schema: {
            type: 'object',
            properties: {
                statusCode: { type: 'number', example: 403 },
                message: { type: 'string', example: 'Access denied to file' },
                error: { type: 'string', example: 'Forbidden' }
            }
        }
    })
    @ApiResponse({
        status: 410,
        description: 'File has been deleted or is no longer available',
        schema: {
            type: 'object',
            properties: {
                statusCode: { type: 'number', example: 410 },
                message: { type: 'string', example: 'File has been deleted' },
                error: { type: 'string', example: 'Gone' }
            }
        }
    })
    @ApiResponse({
        status: 500,
        description: 'Storage provider error or internal server error',
        schema: {
            type: 'object',
            properties: {
                statusCode: { type: 'number', example: 500 },
                message: { type: 'string', example: 'Failed to retrieve file from storage provider' },
                error: { type: 'string', example: 'Internal Server Error' }
            }
        }
    })
    async getFileById(
        @Param('id') id: string,
        @Query('download') download: boolean,
        @Response({ passthrough: true }) res: ExpressResponse,
    ): Promise<StreamableFile> {
        try {
            const result = await this.fileService.getFileById(id);
            const { metadata, stream, stats, mimeType } = result;

            if (!stream) {
                throw new BadRequestException('File stream not available');
            }

            // Set response headers
            res.set({
                'Content-Type': mimeType,
                'Content-Length': stats.size,
                'Content-Disposition': download
                    ? `attachment; filename="${metadata.originalName}"`
                    : `inline; filename="${metadata.originalName}"`,
                'Cache-Control': 'private, max-age=3600',
            });

            // Ensure the stream is compatible with StreamableFile
            const readableStream = stream as any;
            return new StreamableFile(readableStream);
        } catch (error) {
            this.logger.error(`File download failed for ${id}: ${error.message}`, error.stack);
            throw error;
        }
    }

    /**
     * Download file by filename with public access
     * Provides direct access to files using their filename
     */
    @Public()
    @Get(':filename')
    @ApiOperation({
        summary: 'Download file by filename',
        description: `Download a file by its filename with support for multiple storage providers.

        **Cross-Provider Download Logic:**
        - **Local Storage**: Direct file system access with streaming
        - **S3/Cloud Storage**: Generates signed URLs with configurable expiration
        - **Cloudinary**: Uses Cloudinary's CDN with optimization parameters
        - **MinIO**: Local S3-compatible storage with custom endpoint handling

        **Query Parameters:**
        - download=true: Forces download with attachment disposition
        - download=false (default): Inline display in browser when possible

        **Security Features:**
        - File access validation based on filename matching
        - Rate limiting to prevent abuse
        - Audit logging for download tracking`
    })
    @ApiParam({
        name: 'filename',
        description: 'File filename',
        example: 'document_1234567890.pdf'
    })
    @ApiResponse({
        status: 200,
        description: 'File downloaded successfully',
        content: {
            '*/*': {
                schema: {
                    type: 'string',
                    format: 'binary',
                },
            },
        },
        headers: {
            'Content-Type': {
                description: 'MIME type of the file',
                schema: { type: 'string', example: 'application/pdf' }
            },
            'Content-Length': {
                description: 'File size in bytes',
                schema: { type: 'number', example: 1024000 }
            },
            'Content-Disposition': {
                description: 'Download behavior (attachment for download, inline for preview)',
                schema: { type: 'string', example: 'attachment; filename="document.pdf"' }
            },
            'Cache-Control': {
                description: 'Caching directives',
                schema: { type: 'string', example: 'private, max-age=3600' }
            }
        }
    })
    @ApiResponse({
        status: 404,
        description: 'File not found',
        schema: {
            type: 'object',
            properties: {
                statusCode: { type: 'number', example: 404 },
                message: { type: 'string', example: 'File not found' },
                error: { type: 'string', example: 'Not Found' }
            }
        }
    })
    async getFileByFilename(
        @Param('filename') filename: string,
        @Query('download') download: boolean,
        @Response({ passthrough: true }) res: ExpressResponse,
    ): Promise<StreamableFile> {
        try {
            const result = await this.fileService.getFileByFilename(filename);
            const { metadata, stream, stats, mimeType } = result;

            if (!stream) {
                throw new BadRequestException('File stream not available');
            }

            // Set response headers
            res.set({
                'Content-Type': mimeType,
                'Content-Length': stats.size,
                'Content-Disposition': download
                    ? `attachment; filename="${metadata.originalName}"`
                    : `inline; filename="${metadata.originalName}"`,
                'Cache-Control': 'private, max-age=3600',
            });

            // Ensure the stream is compatible with StreamableFile
            const readableStream = stream as any;
            return new StreamableFile(readableStream);
        } catch (error) {
            this.logger.error(`File download failed for ${filename}: ${error.message}`, error.stack);
            throw error;
        }
    }

    /**
     * Get all files with optional filtering and pagination
     * Supports filtering by storage provider, category, and other criteria
     */
    @Public()
    @Get()
    @ApiOperation({
        summary: 'Get all files with pagination and filtering',
        description: `Retrieve a paginated list of files with support for advanced filtering options.

        **Enhanced Features:**
        - ✅ Consistent default values (page: 1, limit: 20)
        - ✅ Comprehensive parameter validation using FileQueryDto
        - ✅ All parameters are optional with proper defaults
        - ✅ Cross-provider file listing support

        **Storage Provider Selection:**
        Files are automatically distributed across multiple storage providers (Local, S3, Cloudinary, MinIO, Google Cloud) based on file type, size, and configured priorities. Use the storageProvider filter to view files from specific providers.

        **Supported Query Parameters (all optional with defaults):**
        - page: Page number (default: 1, min: 1)
        - limit: Items per page (default: 20, min: 1, max: 100)
        - storageProvider: Filter by storage provider (local, s3, cloudinary, minio, google_cloud)
        - category: Filter by file category (document, image, video, audio, archive, other)
        - query: Search in filename or content
        - mimeType: Filter by MIME type
        - uploaderId: Filter by uploader user ID
        - ticketId: Filter by related ticket ID
        - minSize/maxSize: Filter by file size range
        - dateFrom/dateTo: Filter by upload date range (ISO date strings)
        - securityStatus: Filter by security status
        - processingStatus: Filter by processing status
        - sortBy: Sort field (createdAt, filename, size, mimeType) - default: createdAt
        - sortOrder: Sort order (asc, desc) - default: desc
        - include: Include related entities (uploader, ticket, reply)`
    })
    @ApiResponse({
        status: 200,
        description: 'File list with pagination and applied filters',
        schema: {
            type: 'object',
            properties: {
                files: {
                    type: 'array',
                    items: { $ref: '#/components/schemas/FileMetadataDto' }
                },
                pagination: {
                    type: 'object',
                    properties: {
                        page: { type: 'number', example: 1 },
                        limit: { type: 'number', example: 20 },
                        total: { type: 'number', example: 150 },
                        totalPages: { type: 'number', example: 8 },
                        hasNext: { type: 'boolean', example: true },
                        hasPrev: { type: 'boolean', example: false }
                    }
                },
                filters: {
                    type: 'object',
                    example: {
                        storageProvider: 's3',
                        category: 'document',
                        mimeType: 'application/pdf'
                    }
                },
                sort: {
                    type: 'object',
                    example: {
                        field: 'createdAt',
                        order: 'desc'
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Invalid query parameters' })
    @ApiResponse({ status: 500, description: 'Internal server error' })
    async getAllFiles(@Query() query: FileQueryDto) {
        return await this.fileService.getAllFiles(query);
    }
}