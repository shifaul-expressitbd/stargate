/**
 * AWS SDK S3 Client Mock
 * Provides mocked implementations for AWS S3 operations
 */

// Mock enums
export enum StorageClass {
    STANDARD = 'STANDARD',
    STANDARD_IA = 'STANDARD_IA',
    ONEZONE_IA = 'ONEZONE_IA',
    GLACIER = 'GLACIER',
    DEEP_ARCHIVE = 'DEEP_ARCHIVE',
    INTELLIGENT_TIERING = 'INTELLIGENT_TIERING',
}

export enum ServerSideEncryption {
    AES256 = 'AES256',
    AWS_KMS = 'aws:kms',
}

export class PutObjectCommand {
    constructor(public input: any) { }
}

export class GetObjectCommand {
    constructor(public input: any) { }
}

export class DeleteObjectCommand {
    constructor(public input: any) { }
}

export class HeadObjectCommand {
    constructor(public input: any) { }
}

export class ListObjectsV2Command {
    constructor(public input: any) { }
}

export class CopyObjectCommand {
    constructor(public input: any) { }
}

export class S3Client {
    constructor(public config?: any) { }

    send = jest.fn().mockImplementation((command) => {
        if (command instanceof PutObjectCommand) {
            return Promise.resolve({
                ETag: '"mock-etag"',
                VersionId: 'mock-version-id',
            });
        }

        if (command instanceof GetObjectCommand) {
            return Promise.resolve({
                Body: {
                    transformToByteArray: jest.fn().mockResolvedValue(Buffer.from('mock file content')),
                    transformToString: jest.fn().mockResolvedValue('mock file content'),
                },
                ContentLength: 1024000,
                ContentType: 'application/octet-stream',
                LastModified: new Date(),
                Metadata: {},
            });
        }

        if (command instanceof DeleteObjectCommand) {
            return Promise.resolve({});
        }

        if (command instanceof HeadObjectCommand) {
            return Promise.resolve({
                ContentLength: 1024000,
                ContentType: 'application/octet-stream',
                LastModified: new Date(),
                Metadata: {},
                ETag: '"mock-etag"',
            });
        }

        if (command instanceof ListObjectsV2Command) {
            return Promise.resolve({
                Contents: [
                    {
                        Key: 'test-file.txt',
                        Size: 1024,
                        LastModified: new Date(),
                        ETag: '"mock-etag"',
                    },
                ],
                IsTruncated: false,
            });
        }

        if (command instanceof CopyObjectCommand) {
            return Promise.resolve({
                CopyObjectResult: {
                    ETag: '"mock-etag"',
                    LastModified: new Date(),
                },
            });
        }

        return Promise.resolve({});
    });
}