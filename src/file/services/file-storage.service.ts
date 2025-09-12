/**
 * File storage service for handling file upload, storage, and retrieval operations
 * Manages file system operations with organized directory structure
 */

import {
    BadRequestException,
    Injectable,
    InternalServerErrorException,
    Logger,
    NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { FileConfig } from '../config/file.config';
import { FileStorageOptions, MulterFile } from '../interfaces/file-options.interface';

/**
 * File storage service
 * Handles all file system operations for uploaded files
 */
@Injectable()
export class FileStorageService {
    private readonly logger = new Logger(FileStorageService.name);
    private readonly fileConfig: FileConfig;

    constructor(private configService: ConfigService) {
        this.fileConfig = this.configService.get<FileConfig>('file')!;
    }

    /**
     * Save uploaded file to storage with organized directory structure
     * @param file - Multer file object
     * @param options - Storage options
     * @returns Promise with file path and metadata
     */
    async saveFile(
        file: MulterFile,
        options: FileStorageOptions = {},
    ): Promise<{ path: string; filename: string; directory: string }> {
        try {
            const { directory, filename } = await this.generateFilePath(file, options);

            // Ensure directory exists
            await this.ensureDirectoryExists(directory);

            // Move file from temp location to final destination
            const finalPath = path.join(directory, filename);
            await this.moveFile(file.path, finalPath);

            this.logger.log(`File saved successfully: ${finalPath}`);

            return {
                path: finalPath,
                filename,
                directory,
            };
        } catch (error) {
            this.logger.error(`Failed to save file ${file.originalname}: ${error.message}`, error.stack);
            throw new InternalServerErrorException('Failed to save file');
        }
    }

    /**
     * Delete file from storage
     * @param filePath - Path to the file to delete
     * @returns Promise<boolean> - Success status
     */
    async deleteFile(filePath: string): Promise<boolean> {
        try {
            if (!await this.fileExists(filePath)) {
                this.logger.warn(`File not found for deletion: ${filePath}`);
                return false;
            }

            await fs.promises.unlink(filePath);

            // Try to remove empty directories
            await this.cleanupEmptyDirectories(path.dirname(filePath));

            this.logger.log(`File deleted successfully: ${filePath}`);
            return true;
        } catch (error) {
            this.logger.error(`Failed to delete file ${filePath}: ${error.message}`, error.stack);
            throw new InternalServerErrorException('Failed to delete file');
        }
    }

    /**
     * Get file stream for reading/downloading
     * @param filePath - Path to the file
     * @returns Promise with file stream and stats
     */
    async getFileStream(filePath: string): Promise<{
        stream: fs.ReadStream;
        stats: fs.Stats;
        mimeType: string;
    }> {
        try {
            if (!await this.fileExists(filePath)) {
                throw new NotFoundException('File not found');
            }

            const stats = await fs.promises.stat(filePath);
            const mimeType = this.getMimeType(filePath);

            const stream = fs.createReadStream(filePath, {
                highWaterMark: 64 * 1024, // 64KB chunks
            });

            return { stream, stats, mimeType };
        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Failed to create file stream for ${filePath}: ${error.message}`, error.stack);
            throw new InternalServerErrorException('Failed to read file');
        }
    }

    /**
     * Get file statistics
     * @param filePath - Path to the file
     * @returns Promise with file stats
     */
    async getFileStats(filePath: string): Promise<fs.Stats> {
        try {
            if (!await this.fileExists(filePath)) {
                throw new NotFoundException('File not found');
            }

            return await fs.promises.stat(filePath);
        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Failed to get file stats for ${filePath}: ${error.message}`, error.stack);
            throw new InternalServerErrorException('Failed to get file information');
        }
    }

    /**
     * Check if file exists
     * @param filePath - Path to check
     * @returns Promise<boolean>
     */
    async fileExists(filePath: string): Promise<boolean> {
        try {
            await fs.promises.access(filePath, fs.constants.F_OK);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generate unique filename
     * @param originalName - Original filename
     * @param extension - File extension
     * @returns Unique filename
     */
    generateUniqueFilename(originalName: string, extension?: string): string {
        const ext = extension || path.extname(originalName);
        const baseName = path.basename(originalName, ext);
        const timestamp = Date.now();
        const random = crypto.randomBytes(4).toString('hex');

        return `${baseName}_${timestamp}_${random}${ext}`;
    }

    /**
     * Get MIME type from file path
     * @param filePath - File path
     * @returns MIME type string
     */
    getMimeType(filePath: string): string {
        const ext = path.extname(filePath).toLowerCase();

        const mimeTypes: Record<string, string> = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp',
            '.pdf': 'application/pdf',
            '.txt': 'text/plain',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.ppt': 'application/vnd.ms-powerpoint',
            '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            '.zip': 'application/zip',
            '.rar': 'application/x-rar-compressed',
            '.7z': 'application/x-7z-compressed',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
        };

        return mimeTypes[ext] || 'application/octet-stream';
    }

    /**
     * Get file size formatted as human-readable string
     * @param bytes - File size in bytes
     * @returns Formatted size string
     */
    formatFileSize(bytes: number): string {
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let size = bytes;
        let unitIndex = 0;

        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }

        return `${size.toFixed(1)} ${units[unitIndex]}`;
    }

    /**
     * Generate organized file path based on strategy
     * @param file - Multer file object
     * @param options - Storage options
     * @returns Directory and filename
     */
    private async generateFilePath(
        file: MulterFile,
        options: FileStorageOptions,
    ): Promise<{ directory: string; filename: string }> {
        const baseDir = options.baseDir || this.fileConfig.uploadDest;
        const strategy = options.directoryStrategy || 'date';

        let directory: string;

        switch (strategy) {
            case 'flat':
                directory = baseDir;
                break;

            case 'date':
                const now = new Date();
                const year = now.getFullYear();
                const month = String(now.getMonth() + 1).padStart(2, '0');
                directory = path.join(baseDir, year.toString(), month);
                break;

            case 'user':
                if (!options.directoryGenerator) {
                    throw new BadRequestException('User directory strategy requires directoryGenerator');
                }
                directory = options.directoryGenerator(file, undefined);
                break;

            case 'custom':
                if (!options.directoryGenerator) {
                    throw new BadRequestException('Custom directory strategy requires directoryGenerator');
                }
                directory = options.directoryGenerator(file, undefined);
                break;

            default:
                directory = baseDir;
        }

        const filename = this.generateUniqueFilename(file.originalname);

        return { directory, filename };
    }

    /**
     * Ensure directory exists, creating it if necessary
     * @param directory - Directory path
     */
    private async ensureDirectoryExists(directory: string): Promise<void> {
        try {
            await fs.promises.mkdir(directory, { recursive: true });
        } catch (error) {
            if (error.code !== 'EEXIST') {
                throw new InternalServerErrorException(`Failed to create directory: ${directory}`);
            }
        }
    }

    /**
     * Move file from source to destination
     * @param sourcePath - Source file path
     * @param destPath - Destination file path
     */
    private async moveFile(sourcePath: string, destPath: string): Promise<void> {
        try {
            await fs.promises.rename(sourcePath, destPath);
        } catch (error) {
            // If rename fails (e.g., cross-device), try copy + delete
            try {
                await fs.promises.copyFile(sourcePath, destPath);
                await fs.promises.unlink(sourcePath);
            } catch (copyError) {
                throw new InternalServerErrorException('Failed to move file');
            }
        }
    }

    /**
     * Clean up empty directories recursively
     * @param directory - Directory to check
     */
    private async cleanupEmptyDirectories(directory: string): Promise<void> {
        try {
            const items = await fs.promises.readdir(directory);

            if (items.length === 0) {
                await fs.promises.rmdir(directory);

                // Recursively check parent directory
                const parentDir = path.dirname(directory);
                if (parentDir !== directory) { // Avoid infinite loop at root
                    await this.cleanupEmptyDirectories(parentDir);
                }
            }
        } catch (error) {
            // Ignore errors during cleanup
            this.logger.debug(`Failed to cleanup directory ${directory}: ${error.message}`);
        }
    }
}