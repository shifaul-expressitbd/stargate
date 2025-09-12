/**
 * Node.js crypto module mock
 * Provides mocked implementations for cryptographic operations
 */

export const randomUUID = jest.fn().mockReturnValue('123e4567-e89b-12d3-a456-426614174000');

export const randomBytes = jest.fn().mockReturnValue({
    toString: jest.fn().mockReturnValue('mock-random-bytes'),
});

export const createHash = jest.fn().mockReturnValue({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn().mockReturnValue('mock-hash'),
});

export const createHmac = jest.fn().mockReturnValue({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn().mockReturnValue('mock-hmac'),
});

export default {
    randomUUID,
    randomBytes,
    createHash,
    createHmac,
};