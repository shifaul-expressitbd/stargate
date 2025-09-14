// src/config/app.config.ts

/**
 * Configuration factory function that validates environment variables
 * and returns the application configuration.
 *
 * @returns The application configuration object
 * @throws Error if required environment variables are missing or invalid
 */
export const appConfig = () => {
  // Validate required environment variables
  const requiredEnvVars = ['DATABASE_URL', 'JWT_SECRET', 'JWT_REFRESH_SECRET'];
  const missingVars = requiredEnvVars.filter(
    (varName) => !process.env[varName],
  );

  if (missingVars.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missingVars.join(', ')}\n` +
      'Please check your .env file and ensure these variables are set.',
    );
  }

  // Validate JWT secret lengths
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }

  if (
    process.env.JWT_REFRESH_SECRET &&
    process.env.JWT_REFRESH_SECRET.length < 32
  ) {
    throw new Error('JWT_REFRESH_SECRET must be at least 32 characters long');
  }

  // Validate region configurations
  const regions = {
    india: {
      name: 'India',
      apiUrl:
        process.env.BASH_RUNNER_API_URL_INDIA ||
        process.env.BASH_RUNNER_API_URL,
      apiKey:
        process.env.BASH_RUNNER_API_KEY_INDIA ||
        process.env.BASH_RUNNER_API_KEY,
      default: true,
    },
    'us-east': {
      name: 'US East',
      apiUrl: process.env.BASH_RUNNER_API_URL_US_EAST,
      apiKey: process.env.BASH_RUNNER_API_KEY_US_EAST,
    },
    'us-west': {
      name: 'US West',
      apiUrl: process.env.BASH_RUNNER_API_URL_US_WEST,
      apiKey: process.env.BASH_RUNNER_API_KEY_US_WEST,
    },
    europe: {
      name: 'Europe',
      apiUrl: process.env.BASH_RUNNER_API_URL_EUROPE,
      apiKey: process.env.BASH_RUNNER_API_KEY_EUROPE,
    },
  };

  // Validate default region (India) has required configuration
  if (!regions.india.apiUrl || !regions.india.apiKey) {
    throw new Error(
      `Default region (india) must have both BASH_RUNNER_API_URL and BASH_RUNNER_API_KEY configured`,
    );
  }

  // Note: Regions without complete configuration will be handled gracefully

  return {
    // Server configuration
    port: parseInt(process.env.PORT ?? '5555', 10),
    environment: process.env.NODE_ENV ?? 'development',

    // Database configuration
    database: {
      url: process.env.DATABASE_URL,
    },

    // JWT configuration - Exposed at root level for easier access
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN ?? '15m',

    // JWT configuration object
    jwt: {
      secret: process.env.JWT_SECRET,
      expiresIn: process.env.JWT_EXPIRES_IN ?? '60m',
      rememberMeExpiresIn: process.env.JWT_REMEMBER_ME_EXPIRES_IN ?? '7d',
      refreshSecret: process.env.JWT_REFRESH_SECRET,
      refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? '7d',
      refreshRememberMeExpiresIn:
        process.env.JWT_REFRESH_REMEMBER_ME_EXPIRES_IN ?? '30d',
    },

    // Google OAuth configuration
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID ?? '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
      callbackUrl:
        process.env.GOOGLE_CALLBACK_URL ??
        `${process.env.BACKEND_URL ?? 'http://localhost:5555'}/api/auth/google/callback`,
    },
    // Facebook OAuth configuration
    facebook: {
      appId: process.env.FACEBOOK_APP_ID ?? '',
      appSecret: process.env.FACEBOOK_APP_SECRET ?? '',
      callbackUrl:
        process.env.FACEBOOK_CALLBACK_URL ??
        `${process.env.BACKEND_URL ?? 'http://localhost:5555'}/api/auth/facebook/callback`,
    },

    // Frontend configuration
    frontend: {
      url: process.env.FRONTEND_URL ?? 'http://localhost:4173',
    },

    // CORS configuration
    cors: {
      origin:
        process.env.CORS_ORIGIN ??
        process.env.FRONTEND_URL ??
        'http://localhost:4173',
      credentials: true,
    },

    // Rate limiting configuration
    throttle: {
      ttl: parseInt(process.env.THROTTLE_TTL ?? '60000', 10),
      limit: parseInt(process.env.THROTTLE_LIMIT ?? '100', 10),
    },

    // Runner configuration with region support
    runner: {
      // Legacy single-region configuration (for backward compatibility)
      apiUrl: process.env.BASH_RUNNER_API_URL,
      apiKey: process.env.BASH_RUNNER_API_KEY,

      // Region-based configuration
      regions: {
        india: {
          name: 'India',
          apiUrl:
            process.env.BASH_RUNNER_API_URL_INDIA ||
            process.env.BASH_RUNNER_API_URL,
          apiKey:
            process.env.BASH_RUNNER_API_KEY_INDIA ||
            process.env.BASH_RUNNER_API_KEY,
          default: true,
        },
        'us-east': {
          name: 'US East',
          apiUrl: process.env.BASH_RUNNER_API_URL_US_EAST,
          apiKey: process.env.BASH_RUNNER_API_KEY_US_EAST,
        },
        'us-west': {
          name: 'US West',
          apiUrl: process.env.BASH_RUNNER_API_URL_US_WEST,
          apiKey: process.env.BASH_RUNNER_API_KEY_US_WEST,
        },
        europe: {
          name: 'Europe',
          apiUrl: process.env.BASH_RUNNER_API_URL_EUROPE,
          apiKey: process.env.BASH_RUNNER_API_KEY_EUROPE,
        },
      },

      // Default region (fallback)
      defaultRegion: 'india',
    },

    // SMTP configuration
    smtp: {
      host: process.env.SMTP_HOST ?? 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT ?? '587', 10),
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },

    // Impersonation configuration
    IMPERSONATION_ALLOWED_ROLES: (
      process.env.IMPERSONATION_ALLOWED_ROLES || 'admin,crm_agent,developer'
    )
      .split(',')
      .map((role) => role.trim()),
    IMPERSONATION_TIMEOUT_MINUTES: parseInt(
      process.env.IMPERSONATION_TIMEOUT_MINUTES || '60',
      10,
    ),
  };
};
