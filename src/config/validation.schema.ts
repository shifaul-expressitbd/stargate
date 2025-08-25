// src/config/validation.schema.ts (Updated)
import * as Joi from 'joi';

export const validationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  PORT: Joi.number().default(5555),
  DATABASE_URL: Joi.string().required(),

  // JWT Configuration - More strict validation
  JWT_SECRET: Joi.string().min(32).required().messages({
    'string.min': 'JWT_SECRET must be at least 32 characters long',
    'any.required': 'JWT_SECRET is required',
  }),
  JWT_EXPIRES_IN: Joi.string()
    .pattern(/^(?:\d+)(?:s|m|h|d)$/)
    .default('15m'),
  JWT_REMEMBER_ME_EXPIRES_IN: Joi.string()
    .pattern(/^(?:\d+)(?:s|m|h|d)$/)
    .default('7d'),
  JWT_REFRESH_SECRET: Joi.string().min(32).required().messages({
    'string.min': 'JWT_REFRESH_SECRET must be at least 32 characters long',
    'any.required': 'JWT_REFRESH_SECRET is required',
  }),
  JWT_REFRESH_EXPIRES_IN: Joi.string()
    .pattern(/^(?:\d+)(?:s|m|h|d)$/)
    .default('7d'),
  JWT_REFRESH_REMEMBER_ME_EXPIRES_IN: Joi.string()
    .pattern(/^(?:\d+)(?:s|m|h|d)$/)
    .default('30d'),

  // Google OAuth
  GOOGLE_CLIENT_ID: Joi.string().optional(),
  GOOGLE_CLIENT_SECRET: Joi.string().optional(),
  GOOGLE_CALLBACK_URL: Joi.string().uri().optional(),

  // Facebook OAuth
  FACEBOOK_APP_ID: Joi.string().optional(),
  FACEBOOK_APP_SECRET: Joi.string().optional(),
  FACEBOOK_CALLBACK_URL: Joi.string().uri().optional(),

  // App URLs
  FRONTEND_URL: Joi.string().uri().default('http://localhost:5173'),
  CORS_ORIGIN: Joi.string().default('http://localhost:5173'),

  // Rate limiting
  THROTTLE_TTL: Joi.number().default(60000),
  THROTTLE_LIMIT: Joi.number().default(100),

  // External services
  RUNNER_API_URL: Joi.string().uri().required().messages({
    'any.required': 'RUNNER_API_URL is required',
    'string.uri': 'RUNNER_API_URL must be a valid URL',
  }),
  BASH_RUNNER_API_KEY: Joi.string().length(128).required().messages({
    'any.required': 'BASH_RUNNER_API_KEY is required',
    'string.length': 'BASH_RUNNER_API_KEY must be 128 characters long',
  }),

  // SMTP Configuration
  SMTP_HOST: Joi.string().default('smtp.gmail.com'),
  SMTP_PORT: Joi.number().default(587),
  SMTP_USER: Joi.string().email().optional(),
  SMTP_PASS: Joi.string().optional(),
});
