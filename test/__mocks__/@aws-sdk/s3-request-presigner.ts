/**
 * AWS SDK S3 Request Presigner Mock
 * Provides mocked implementation for S3 signed URLs
 */

export const getSignedUrl = jest.fn().mockResolvedValue('https://mock-s3-bucket.s3.amazonaws.com/test-file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&signed-params');