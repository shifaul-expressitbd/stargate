// src/config/validation.schema.ts (Updated)
import * as Joi from 'joi';

export const validationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('production'),

  // Google Configuration (OAuth & Tag Manager)
  GOOGLE_CLIENT_ID: Joi.string().required(),
  GOOGLE_CLIENT_SECRET: Joi.string().required(),
  GOOGLE_CALLBACK_URL: Joi.string().uri().required(),
  // GTM ONLY (optional for backward compatibility)
  GOOGLE_GTM_CLIENT_ID: Joi.string().optional(),
  GOOGLE_GTM_CLIENT_SECRET: Joi.string().optional(),
  GOOGLE_GTM_CALLBACK_URL: Joi.string().uri().optional(),
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
  BASH_RUNNER_API_URL: Joi.string().uri().required().messages({
    'any.required': 'BASH_RUNNER_API_URL is required',
    'string.uri': 'BASH_RUNNER_API_URL must be a valid URL',
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

  // Logging Configuration
  LOG_LEVEL: Joi.string()
    .valid('error', 'warn', 'info', 'debug')
    .default('info'),
  LOG_CONSOLE: Joi.string().valid('true', 'false').default('true'),
  LOG_DIR: Joi.string().default('logs'),

  // Impersonation Configuration
  IMPERSONATION_ALLOWED_ROLES: Joi.string().default(
    'admin,crm_agent,developer',
  ),
  IMPERSONATION_TIMEOUT_MINUTES: Joi.number().min(1).max(1440).default(60),

  // Multi-region API configurations
  BASH_RUNNER_API_URL_INDIA: Joi.string().uri().optional(),
  BASH_RUNNER_API_KEY_INDIA: Joi.string().length(128).optional(),
  BASH_RUNNER_API_URL_US_EAST: Joi.string().uri().optional(),
  BASH_RUNNER_API_KEY_US_EAST: Joi.string().length(128).optional(),
  BASH_RUNNER_API_URL_US_WEST: Joi.string().uri().optional(),
  BASH_RUNNER_API_KEY_US_WEST: Joi.string().length(128).optional(),
  BASH_RUNNER_API_URL_EUROPE: Joi.string().uri().optional(),
  BASH_RUNNER_API_KEY_EUROPE: Joi.string().length(128).optional(),

  // Secret rotation configuration
  SECRET_ROTATION_ENABLED: Joi.string().valid('true', 'false').default('false'),
  SECRET_ROTATION_INTERVAL_HOURS: Joi.number().min(1).max(8760).default(168), // 7 days
  SECRET_ROTATION_GRACE_PERIOD_MINUTES: Joi.number()
    .min(1)
    .max(1440)
    .default(60),

  // Audit logging configuration
  AUDIT_LOG_ENABLED: Joi.string().valid('true', 'false').default('true'),
  AUDIT_LOG_LEVEL: Joi.string()
    .valid('error', 'warn', 'info', 'debug')
    .default('info'),

  // Session security configuration
  MAX_CONCURRENT_SESSIONS: Joi.number().min(1).max(50).default(5),
  SESSION_RISK_THRESHOLD: Joi.number().min(0).max(1).default(0.7),
  ENABLE_DEVICE_FINGERPRINTING: Joi.string()
    .valid('true', 'false')
    .default('true'),
  ENABLE_GEOLOCATION_TRACKING: Joi.string()
    .valid('true', 'false')
    .default('true'),
});
