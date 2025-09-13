/**
 * Public File controller for serving files without authentication
 * Bypasses the global API prefix to allow direct file access
 */

import {
    BadRequestException,
    Controller,
    Get,
    Logger,
    NotFoundException,
    Param,
    Query,
    Response,
    StreamableFile
} from '@nestjs/common';
import type { Response as ExpressResponse } from 'express';
import { FileService } from './services/file.service';

/**
 * Public file controller
 * Provides direct access to files without the /api prefix
 */
@Controller()
export class PublicFileController {
    private readonly logger = new Logger(PublicFileController.name);

    constructor(
        private fileService: FileService,
    ) { }

    /**
     * Download file by filename with public access
     * Allows direct access to files using their filename
     * Searches through organized directory structure if needed
     */
    @Get('files/:filename')
    async getFileByFilename(
        @Param('filename') filename: string,
        @Query('download') download: boolean,
        @Response({ passthrough: true }) res: ExpressResponse,
    ): Promise<StreamableFile> {
        // Decode URL-encoded filename parameter
        const decodedFilename = decodeURIComponent(filename);

        try {
            let result;

            try {
                // First try to get file by exact filename match
                result = await this.fileService.getFileByFilename(decodedFilename);
            } catch (error) {
                // If not found by exact match, try to find file in organized directories
                result = await this.findFileInOrganizedStructure(decodedFilename);
            }

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
            this.logger.error(`File download failed for ${decodedFilename}: ${error.message}`, error.stack);
            throw error;
        }
    }

    /**
     * Find file in organized directory structure
     * Searches through year/month directories for the requested file
     */
    private async findFileInOrganizedStructure(filename: string): Promise<{
        metadata: any;
        stream: NodeJS.ReadableStream;
        stats: { size: number };
        mimeType: string;
    }> {
        // This is a fallback method - in a real implementation,
        // you might want to search through possible directory structures
        // or maintain an index of file locations

        // For now, we'll try to get all files and find matches
        const allFiles = await this.fileService.getAllFiles({ limit: 1000 });

        // Look for files with matching filename
        const matchingFile = allFiles.files.find(file =>
            file.filename === filename ||
            file.originalName === filename
        );

        if (!matchingFile) {
            throw new NotFoundException(`File ${filename} not found`);
        }

        // Get the file using its ID
        return await this.fileService.getFileById(matchingFile.id);
    }
}