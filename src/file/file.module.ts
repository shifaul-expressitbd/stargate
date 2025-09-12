/**
 * File module for comprehensive file management
 * Provides file upload, storage, validation, and access control
 */

import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MulterModule } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import * as path from 'path';
import { DatabaseModule } from '../database/database.module';
import { fileConfig } from './config/file.config';
import { StorageConfigService } from './config/storage.config';
import { FileController } from './file.controller';
import { PublicFileController } from './public-file.controller';
import { FileCleanupService } from './services/file-cleanup.service';
import { FileMetadataService } from './services/file-metadata.service';
import { FileStorageService } from './services/file-storage.service';
import { FileValidationService } from './services/file-validation.service';
import { FileService } from './services/file.service';
import { StorageManagerService } from './services/storage-manager.service';
import { StorageSelectorService } from './services/storage-selector.service';

/**
 * File module
 * Provides complete file management functionality
 */
@Module({
    imports: [
        // Configuration module with file config
        ConfigModule.forFeature(fileConfig),

        // Database access
        DatabaseModule,

        // Multer configuration for file uploads
        MulterModule.registerAsync({
            useFactory: (configService: ConfigService) => {
                const fileConfig = configService.get('file');

                return {
                    dest: fileConfig.uploadDest || 'uploads',
                    limits: {
                        fileSize: fileConfig.maxSize || 10 * 1024 * 1024, // 10MB default
                        files: fileConfig.maxFilesCount || 10,
                    },
                    fileFilter: (req, file, callback) => {
                        // Basic file filter - detailed validation happens in service
                        const allowedTypes = fileConfig.allowedTypes || [];
                        if (allowedTypes.length === 0 || allowedTypes.includes(file.mimetype)) {
                            callback(null, true);
                        } else {
                            callback(new Error(`File type ${file.mimetype} is not allowed`), false);
                        }
                    },
                    storage: diskStorage({
                        destination: (req, file, callback) => {
                            // Use temp directory for initial upload
                            // FileStorageService will handle final organization
                            const tempDir = path.join(fileConfig.uploadDest || 'uploads', 'temp');
                            callback(null, tempDir);
                        },
                        filename: (req, file, callback) => {
                            // Generate unique filename for temp storage
                            const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`;
                            callback(null, uniqueName);
                        },
                    }),
                };
            },
            inject: [ConfigService],
        }),
    ],
    controllers: [FileController, PublicFileController],
    providers: [
        // Core file services
        FileService,
        FileMetadataService,
        FileValidationService,
        FileCleanupService,

        // Storage architecture services
        StorageManagerService,
        StorageSelectorService,
        StorageConfigService,

        // Keep legacy service for compatibility
        FileStorageService,
    ],
    exports: [
        // Export core services
        FileService,
        FileMetadataService,
        FileValidationService,
        FileCleanupService,

        // Export storage architecture services
        StorageManagerService,
        StorageSelectorService,
        StorageConfigService,

        // Keep legacy exports for compatibility
        FileStorageService,

        // Export module for dynamic imports
        FileModule,
    ],
})
export class FileModule { }