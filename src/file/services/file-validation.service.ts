/**
 * File validation service for validating uploaded files
 * Performs security checks, type validation, and size validation
 */

import {
    BadRequestException,
    Injectable,
    Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import { FILE_CONFIG_DEFAULTS, FileConfig } from '../config/file.config';
import { FileValidationOptions, MulterFile } from '../interfaces/file-options.interface';

/**
 * File validation service
 * Handles file validation including security checks and type validation
 */
@Injectable()
export class FileValidationService {
    private readonly logger = new Logger(FileValidationService.name);

    // Dangerous file extensions that should be blocked
    private readonly dangerousExtensions = [
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
        '.php', '.asp', '.jsp', '.cgi', '.pl', '.py', '.sh', '.dll', '.so',
    ];

    // MIME type to extension mapping for validation
    private readonly mimeTypeExtensions: Record<string, string[]> = {
        // Images
        'image/jpeg': ['.jpg', '.jpeg'],
        'image/png': ['.png'],
        'image/gif': ['.gif'],
        'image/webp': ['.webp'],
        'image/svg+xml': ['.svg'],
        'image/bmp': ['.bmp'],
        'image/tiff': ['.tiff', '.tif'],
        'image/avif': ['.avif'],
        'image/heic': ['.heic'],
        'image/heif': ['.heif'],

        // Videos
        'video/mp4': ['.mp4'],
        'video/avi': ['.avi'],
        'video/mov': ['.mov'],
        'video/wmv': ['.wmv'],
        'video/flv': ['.flv'],
        'video/webm': ['.webm'],
        'video/mkv': ['.mkv'],
        'video/3gp': ['.3gp'],
        'video/quicktime': ['.mov', '.qt'],

        // Audio
        'audio/mp3': ['.mp3'],
        'audio/wav': ['.wav'],
        'audio/ogg': ['.ogg'],
        'audio/m4a': ['.m4a'],
        'audio/aac': ['.aac'],
        'audio/flac': ['.flac'],

        // Documents
        'application/pdf': ['.pdf'],
        'text/plain': ['.txt'],
        'application/msword': ['.doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
        'application/vnd.ms-excel': ['.xls'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
        'application/vnd.ms-powerpoint': ['.ppt'],
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],

        // Archives
        'application/zip': ['.zip'],
        'application/x-rar-compressed': ['.rar'],
        'application/x-7z-compressed': ['.7z'],
        'application/x-tar': ['.tar'],
        'application/gzip': ['.gz'],

        // Other
        'application/json': ['.json'],
        'application/xml': ['.xml'],
        'text/csv': ['.csv'],
        'text/html': ['.html'],
        'text/css': ['.css'],
        'application/javascript': ['.js'],
        'application/typescript': ['.ts'],
    };

    constructor(private configService: ConfigService) {
        // Load configuration lazily to avoid initialization issues
    }

    private get fileConfig(): FileConfig {
        if (!this._fileConfig) {
            this._fileConfig = this.configService.get<FileConfig>('file') || FILE_CONFIG_DEFAULTS;
        }
        return this._fileConfig!;
    }

    private _fileConfig: FileConfig | undefined;

    /**
     * Validate single file
     * @param file - Multer file object
     * @param options - Validation options
     * @throws BadRequestException if validation fails
     */
    async validateFile(file: MulterFile, options: FileValidationOptions = {}): Promise<void> {
        try {
            // Size validation
            this.validateFileSize(file.size, options.maxSize);

            // Type validation
            if (options.checkMimeType !== false) {
                this.validateMimeType(file.mimetype, options);
            }

            // Extension validation
            if (options.checkExtension !== false) {
                this.validateFileExtension(file.originalname, file.mimetype);
            }

            // Security checks
            if (options.securityCheck !== false) {
                await this.performSecurityChecks(file);
            }

            // Filename validation
            this.validateFilename(file.originalname, options.maxFilenameLength);

            // Forbidden patterns
            if (options.forbiddenPatterns) {
                this.checkForbiddenPatterns(file.originalname, options.forbiddenPatterns);
            }

            this.logger.debug(`File validation passed: ${file.originalname}`);
        } catch (error) {
            this.logger.warn(`File validation failed for ${file.originalname}: ${error.message}`);
            throw error;
        }
    }

    /**
     * Validate multiple files
     * @param files - Array of Multer file objects
     * @param options - Validation options
     * @returns Validation results
     */
    async validateFiles(
        files: MulterFile[],
        options: FileValidationOptions = {},
    ): Promise<{
        valid: MulterFile[];
        invalid: Array<{ file: MulterFile; error: string }>;
    }> {
        const valid: MulterFile[] = [];
        const invalid: Array<{ file: MulterFile; error: string }> = [];

        for (const file of files) {
            try {
                await this.validateFile(file, options);
                valid.push(file);
            } catch (error) {
                invalid.push({
                    file,
                    error: error.message,
                });
            }
        }

        return { valid, invalid };
    }

    /**
     * Validate file size
     * @param size - File size in bytes
     * @param maxSize - Maximum allowed size
     */
    private validateFileSize(size: number, maxSize?: number): void {
        const limit = maxSize || this.fileConfig.maxSize;

        if (size > limit) {
            throw new BadRequestException(
                `File size ${this.formatBytes(size)} exceeds maximum allowed size of ${this.formatBytes(limit)}`,
            );
        }
    }

    /**
     * Validate MIME type
     * @param mimeType - File MIME type
     * @param options - Validation options
     */
    private validateMimeType(mimeType: string, options: FileValidationOptions): void {
        const allowedTypes = options.allowedTypes || this.fileConfig.allowedTypes;

        if (!allowedTypes.includes(mimeType)) {
            throw new BadRequestException(
                `File type '${mimeType}' is not allowed. Allowed types: ${allowedTypes.join(', ')}`,
            );
        }
    }

    /**
     * Validate file extension against MIME type
     * @param filename - Original filename
     * @param mimeType - MIME type
     */
    private validateFileExtension(filename: string, mimeType: string): void {
        const extension = path.extname(filename).toLowerCase();

        // Check if extension is dangerous
        if (this.dangerousExtensions.includes(extension)) {
            throw new BadRequestException(`File extension '${extension}' is not allowed for security reasons`);
        }

        // Check if extension matches MIME type
        const expectedExtensions = this.mimeTypeExtensions[mimeType];
        if (expectedExtensions && !expectedExtensions.includes(extension)) {
            throw new BadRequestException(
                `File extension '${extension}' does not match MIME type '${mimeType}'`,
            );
        }
    }

    /**
     * Perform security checks on file
     * @param file - Multer file object
     */
    private async performSecurityChecks(file: MulterFile): Promise<void> {
        // Check file header/magic numbers for common file types
        await this.validateFileHeader(file);

        // Additional security checks can be added here
        // - Virus scanning integration
        // - Content analysis
        // - Metadata validation
    }

    /**
     * Validate file header/magic numbers
     * @param file - Multer file object
     */
    private async validateFileHeader(file: MulterFile): Promise<void> {
        try {
            const buffer = await this.readFileHeader(file.path, 64);
            const header = buffer.toString('hex').toUpperCase();

            // Check for executable file signatures
            const executableSignatures = [
                '4D5A', // MZ (Windows executable)
                '7F454C46', // ELF (Linux executable)
                'CAFEBABE', // Java class file
                '23212F62696E2F62617368', // #!/bin/bash (shell script)
                '23212F62696E2F7368', // #!/bin/sh (shell script)
            ];

            for (const signature of executableSignatures) {
                if (header.startsWith(signature)) {
                    throw new BadRequestException('File appears to be an executable or script, which is not allowed');
                }
            }

            // Validate image file headers
            if (file.mimetype.startsWith('image/')) {
                this.validateImageHeader(buffer, file.mimetype);
            }

            // Validate PDF header
            if (file.mimetype === 'application/pdf') {
                if (!header.startsWith('255044462D')) { // %PDF-
                    throw new BadRequestException('Invalid PDF file format');
                }
            }
        } catch (error) {
            if (error instanceof BadRequestException) {
                throw error;
            }
            this.logger.warn(`Failed to validate file header for ${file.originalname}: ${error.message}`);
            // Don't throw error for header validation failures in production
            // as it might be too restrictive
        }
    }

    /**
     * Validate image file headers
     * @param buffer - File header buffer
     * @param mimeType - MIME type
     */
    private validateImageHeader(buffer: Buffer, mimeType: string): void {
        const header = buffer.toString('hex').toUpperCase();

        const signatures: Record<string, string> = {
            'image/jpeg': 'FFD8FF',
            'image/png': '89504E47',
            'image/gif': '47494638',
            'image/webp': '52494646', // RIFF
        };

        const expectedSignature = signatures[mimeType];
        if (expectedSignature && !header.startsWith(expectedSignature)) {
            throw new BadRequestException(`Invalid ${mimeType} file format`);
        }
    }

    /**
     * Validate filename
     * @param filename - Filename to validate
     * @param maxLength - Maximum filename length
     */
    private validateFilename(filename: string, maxLength?: number): void {
        const maxLen = maxLength || 255;

        if (filename.length > maxLen) {
            throw new BadRequestException(`Filename is too long. Maximum length is ${maxLen} characters`);
        }

        // Check for null bytes and other dangerous characters
        if (filename.includes('\0') || filename.includes('..') || filename.includes('/')) {
            throw new BadRequestException('Filename contains invalid characters');
        }

        // Check for hidden files (starting with dot, except for extensions)
        if (filename.startsWith('.') && !filename.includes('.', 1)) {
            throw new BadRequestException('Hidden files are not allowed');
        }
    }

    /**
     * Check for forbidden filename patterns
     * @param filename - Filename to check
     * @param patterns - Forbidden regex patterns
     */
    private checkForbiddenPatterns(filename: string, patterns: RegExp[]): void {
        for (const pattern of patterns) {
            if (pattern.test(filename)) {
                throw new BadRequestException(`Filename matches forbidden pattern: ${pattern}`);
            }
        }
    }

    /**
     * Read file header
     * @param filePath - Path to file
     * @param bytes - Number of bytes to read
     * @returns Buffer with file header
     */
    private async readFileHeader(filePath: string, bytes: number): Promise<Buffer> {
        const buffer = Buffer.alloc(bytes);
        const fd = await fs.promises.open(filePath, 'r');
        try {
            await fd.read(buffer, 0, bytes, 0);
            return buffer;
        } finally {
            await fd.close();
        }
    }

    /**
     * Format bytes to human readable format
     * @param bytes - Bytes to format
     * @returns Formatted string
     */
    private formatBytes(bytes: number): string {
        const units = ['B', 'KB', 'MB', 'GB'];
        let size = bytes;
        let unitIndex = 0;

        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }

        return `${size.toFixed(1)} ${units[unitIndex]}`;
    }
}