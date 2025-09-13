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

export const PutObjectCommand = jest.fn().mockImplementation((input: any) => ({ type: 'PutObject', input }));

export const GetObjectCommand = jest.fn().mockImplementation((input: any) => ({ type: 'GetObject', input }));

export const DeleteObjectCommand = jest.fn().mockImplementation((input: any) => ({ type: 'DeleteObject', input }));

export const HeadObjectCommand = jest.fn().mockImplementation((input: any) => ({ type: 'HeadObject', input }));

export const ListObjectsV2Command = jest.fn().mockImplementation((input: any) => ({ type: 'ListObjectsV2', input }));

export const CopyObjectCommand = jest.fn().mockImplementation((input: any) => ({ type: 'CopyObject', input }));

export const S3Client = jest.fn().mockImplementation((config?: any) => {
    const instance = {
        send: jest.fn().mockImplementation((command) => {
            if (command.type === 'PutObject') {
                return Promise.resolve({
                    ETag: '"mock-etag"',
                    VersionId: 'mock-version-id',
                });
            }

            if (command.type === 'GetObject') {
                return Promise.resolve({
                    Body: 'mock file content',
                    ContentLength: 1024000,
                    ContentType: 'application/octet-stream',
                    LastModified: new Date(),
                    Metadata: {},
                });
            }

            if (command.type === 'HeadObject') {
                return Promise.resolve({
                    ContentLength: 1024000,
                    ContentType: 'application/octet-stream',
                    LastModified: new Date(),
                    Metadata: {},
                    ETag: '"mock-etag"',
                });
            }

            if (command.type === 'DeleteObject') {
                return Promise.resolve({});
            }

            if (command.type === 'CopyObject') {
                return Promise.resolve({
                    CopyObjectResult: {
                        ETag: '"mock-etag"',
                        LastModified: new Date(),
                    },
                });
            }

            if (command.type === 'ListObjectsV2') {
                if (command.input.MaxKeys === 1) {
                    return Promise.resolve({
                        Contents: [],
                    });
                }
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

            return Promise.resolve({});
        }),
    };
    return instance;
});