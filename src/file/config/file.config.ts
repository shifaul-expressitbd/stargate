/**
 * File upload configuration module
 * Provides centralized configuration for file operations
 */

import { registerAs } from '@nestjs/config';
import { IsBoolean, IsNumber, IsOptional, IsString } from 'class-validator';

/**
 * Environment variables validation class for file configuration
 */
export class FileConfigEnv {
    @IsString()
    @IsOptional()
    FILE_UPLOAD_DEST?: string;

    @IsNumber()
    @IsOptional()
    FILE_MAX_SIZE?: number;

    @IsString()
    @IsOptional()
    FILE_ALLOWED_TYPES?: string;

    @IsNumber()
    @IsOptional()
    FILE_MAX_FILES_COUNT?: number;

    @IsBoolean()
    @IsOptional()
    FILE_CLEANUP_ENABLED?: boolean;

    @IsNumber()
    @IsOptional()
    FILE_CLEANUP_MAX_AGE_DAYS?: number;

    @IsString()
    @IsOptional()
    FILE_CLEANUP_CRON_SCHEDULE?: string;
}

/**
 * File configuration interface
 */
export interface FileConfig {
    uploadDest: string;
    maxSize: number;
    allowedTypes: string[];
    maxFilesCount: number;
    cleanup: {
        enabled: boolean;
        maxAgeDays: number;
        cronSchedule: string;
    };
}

/**
 * Default file configuration values
 */
export const FILE_CONFIG_DEFAULTS: FileConfig = {
    uploadDest: 'uploads',
    maxSize: 10 * 1024 * 1024, // 10MB
    allowedTypes: [
        // Images
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'image/svg+xml',
        'image/bmp',
        'image/tiff',
        'image/avif',
        'image/heic',
        'image/heif',

        // Videos
        'video/mp4',
        'video/avi',
        'video/mov',
        'video/wmv',
        'video/flv',
        'video/webm',
        'video/mkv',
        'video/3gp',
        'video/quicktime',

        // Audio
        'audio/mp3',
        'audio/wav',
        'audio/ogg',
        'audio/m4a',
        'audio/aac',
        'audio/flac',

        // Documents
        'application/pdf',
        'text/plain',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',

        // Archives
        'application/zip',
        'application/x-rar-compressed',
        'application/x-7z-compressed',
        'application/x-tar',
        'application/gzip',

        // Other
        'application/json',
        'application/xml',
        'text/csv',
        'text/html',
        'text/css',
        'application/javascript',
        'application/typescript',
    ],
    maxFilesCount: 10,
    cleanup: {
        enabled: true,
        maxAgeDays: 30,
        cronSchedule: '0 2 * * *', // Daily at 2 AM
    },
};

/**
 * File configuration factory function
 * Registers configuration with NestJS ConfigModule
 */
export const fileConfig = registerAs('file', (): FileConfig => {
    const config: FileConfig = { ...FILE_CONFIG_DEFAULTS };

    // Override defaults with environment variables if provided
    if (process.env.FILE_UPLOAD_DEST) {
        config.uploadDest = process.env.FILE_UPLOAD_DEST;
    }

    if (process.env.FILE_MAX_SIZE) {
        const maxSize = parseInt(process.env.FILE_MAX_SIZE, 10);
        if (!isNaN(maxSize)) {
            config.maxSize = maxSize;
        }
    }

    if (process.env.FILE_ALLOWED_TYPES) {
        config.allowedTypes = process.env.FILE_ALLOWED_TYPES.split(',');
    }

    if (process.env.FILE_MAX_FILES_COUNT) {
        const maxFilesCount = parseInt(process.env.FILE_MAX_FILES_COUNT, 10);
        if (!isNaN(maxFilesCount)) {
            config.maxFilesCount = maxFilesCount;
        }
    }

    if (process.env.FILE_CLEANUP_ENABLED) {
        config.cleanup.enabled = process.env.FILE_CLEANUP_ENABLED === 'true';
    }

    if (process.env.FILE_CLEANUP_MAX_AGE_DAYS) {
        const maxAgeDays = parseInt(process.env.FILE_CLEANUP_MAX_AGE_DAYS, 10);
        if (!isNaN(maxAgeDays)) {
            config.cleanup.maxAgeDays = maxAgeDays;
        }
    }

    if (process.env.FILE_CLEANUP_CRON_SCHEDULE) {
        config.cleanup.cronSchedule = process.env.FILE_CLEANUP_CRON_SCHEDULE;
    }

    return config;
});

/**
 * Helper function to get file configuration from ConfigService
 * @param configService - NestJS ConfigService instance
 * @returns File configuration object
 */
export const getFileConfig = (configService: any): FileConfig => {
    return configService.get('file') || FILE_CONFIG_DEFAULTS;
};