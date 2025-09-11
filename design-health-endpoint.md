# Enhanced /api/health Endpoint Architecture Design

## Overview

This document outlines the architectural design for an enhanced `/api/health` endpoint that provides comprehensive health checks for the StarGate NestJS API. The system will include checks for API status, database connectivity, webhook functionality, and multiregion status for both SGTM and Meta CAPI services.

## Current State Analysis

### Existing Health Check

- Basic implementation in `AppService.getHealth()` returning:
  - status: 'ok'
  - timestamp
  - uptime
  - environment
  - version

### Region Management Systems

- **SgtmRegion**: Manages Server-Side Google Tag Manager regions
  - Properties: key, name, apiUrl, apiKey, isActive, isDefault
  - Regions: india, us-east, us-west, europe
- **MetaCapiRegion**: Manages Meta Conversions API regions
  - Properties: key, name, baseUrl, appId, appSecret, apiVersion, isActive, isDefault
  - Regions: us, eu, asia

### Database Infrastructure

- PostgreSQL with Prisma ORM
- Connection management via `PrismaService`
- Models: Users, Sessions, Containers, Regions, Access Logs

### Observed Patterns

- Both region services have `getAvailableRegionsForApi()` methods
- Region availability determined by: isActive + valid credentials + valid URLs
- Database connectivity checked via Prisma's `$connect()` method
- No existing webhook functionality in codebase

## Proposed Architecture

### 1. Overall Architecture

```
HealthModule
├── HealthController (/api/health)
├── HealthService (orchestrator)
├── HealthCheckAggregator
├── Individual Health Checkers:
│   ├── ApiHealthChecker
│   ├── DatabaseHealthChecker
│   ├── SgtmRegionHealthChecker
│   ├── MetaCapiRegionHealthChecker
│   ├── WebhookHealthChecker
│   └── ContainerHealthChecker
└── Common Components:
    ├── HealthCheckResult DTO
    ├── HealthStatus Enum
    └── Timeout/Circuit Breaker
```

### 2. Module Structure

#### HealthModule

```typescript
@Module({
  imports: [DatabaseModule, SgtmRegionModule, MetaCapiRegionModule],
  controllers: [HealthController],
  providers: [
    HealthService,
    HealthCheckAggregator,
    ApiHealthChecker,
    DatabaseHealthChecker,
    SgtmRegionHealthChecker,
    MetaCapiRegionHealthChecker,
    WebhookHealthChecker,
    ContainerHealthChecker,
    HealthTimeoutService,
  ],
  exports: [HealthService],
})
export class HealthModule {}
```

#### HealthController

```typescript
@Controller('health')
export class HealthController {
  @Get()
  async getHealth(
    @Query() options: HealthQueryDto,
  ): Promise<HealthResponseDto> {
    // Enhanced health endpoint with optional detailed checks
  }

  @Get('detailed')
  async getDetailedHealth(): Promise<DetailedHealthResponseDto> {
    // Comprehensive health check with all components
  }

  @Get('regions')
  async getRegionHealth(): Promise<RegionHealthResponseDto> {
    // Region-specific health checks
  }
}
```

### 3. Health Check Components

#### Base Health Checker Interface

```typescript
export interface IHealthChecker {
  name: string;
  check(options?: HealthCheckOptions): Promise<HealthCheckResult>;
  isEnabled(): boolean;
  getTimeout(): number;
}

export interface HealthCheckResult {
  status: HealthStatus;
  component: string;
  details?: any;
  duration: number;
  error?: string;
  timestamp: Date;
}

export enum HealthStatus {
  UP = 'UP',
  DOWN = 'DOWN',
  DEGRADED = 'DEGRADED',
  UNKNOWN = 'UNKNOWN',
}
```

#### Individual Checkers

**ApiHealthChecker**

- Checks: Application responsiveness, memory usage, response time
- Uses: Process information, Node.js performance metrics

**DatabaseHealthChecker**

- Checks: Connection status, query execution time, connection pool health
- Uses: PrismaService.$connect(), simple SELECT query

**SgtmRegionHealthChecker**

- Checks: Region availability, API endpoint responsiveness, credential validation
- Uses: SgtmRegionService.getAvailableRegionsForApi(), HTTP ping to apiUrl
- Multiregion: Tests all active regions concurrently

**MetaCapiRegionHealthChecker**

- Checks: Region availability, API endpoint responsiveness, app credentials
- Uses: MetaCapiRegionService.getAvailableRegionsForApi(), HTTP ping to baseUrl
- Multiregion: Tests all active regions concurrently

**WebhookHealthChecker** (New Component)

- Checks: Webhook endpoint availability, response format validation
- Uses: Configured webhook URLs, HTTP GET/HEAD requests
- Status: Initially DOWN until webhook URLs are configured

**ContainerHealthChecker**

- Checks: Docker container status, resource usage
- Uses: Docker API or container orchestrator APIs
- Scope: SGTM containers and Meta CAPI containers

### 4. Response Format and Data Structure

#### HealthResponseDto

```typescript
export class HealthResponseDto {
  status: HealthStatus;
  timestamp: Date;
  uptime: number;
  environment: string;
  version: string;
  components: {
    api: ComponentHealthDto;
    database: ComponentHealthDto;
    sgtmRegions: RegionHealthDto;
    metaCapiRegions: RegionHealthDto;
    webhooks: ComponentHealthDto;
    containers: ComponentHealthDto;
  };
  overallDuration: number;
}
```

#### ComponentHealthDto

```typescript
export class ComponentHealthDto {
  status: HealthStatus;
  details?: any;
  duration: number;
  error?: string;
  lastChecked: Date;
}
```

#### RegionHealthDto

```typescript
export class RegionHealthDto {
  overallStatus: HealthStatus;
  regions: {
    [regionKey: string]: {
      status: HealthStatus;
      available: boolean;
      default: boolean;
      responseTime?: number;
      error?: string;
    };
  };
  totalRegions: number;
  availableRegions: number;
  duration: number;
}
```

### 5. Integration Points

#### With Existing Services

- **DatabaseModule**: Reuse PrismaService for connection checks
- **SgtmRegionService**: Leverage getAvailableRegionsForApi() method
- **MetaCapiRegionService**: Leverage getAvailableRegionsForApi() method
- **ConfigService**: Access application configuration and environment variables
- **Logger**: Comprehensive logging for health check operations

#### Configuration Integration

```typescript
export interface HealthConfig {
  enabled: boolean;
  timeout: number;
  cache: {
    enabled: boolean;
    ttl: number; // Time-to-live for cached results
  };
  regions: {
    concurrentChecks: number; // Max concurrent region checks
    timeout: number; // Timeout per region check
  };
  webhooks: {
    urls: string[]; // Configured webhook URLs for health checks
    timeout: number;
  };
}
```

### 6. Error Handling and Timeout Strategies

#### Timeout Management

```typescript
export class HealthTimeoutService {
  async withTimeout<T>(
    operation: Promise<T>,
    timeoutMs: number,
    componentName: string,
  ): Promise<T> {
    // Race between operation and timeout
    // Log timeout events
    // Return timeout error result
  }
}
```

#### Circuit Breaker Pattern

```typescript
export class HealthCircuitBreaker {
  private failures: Map<string, number> = new Map();
  private lastFailureTime: Map<string, Date> = new Map();

  async execute<T>(
    componentName: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    if (this.isOpen(componentName)) {
      throw new HealthCheckCircuitOpenError(componentName);
    }

    try {
      const result = await operation();
      this.onSuccess(componentName);
      return result;
    } catch (error) {
      this.onFailure(componentName);
      throw error;
    }
  }
}
```

#### Error Classification

- **Connectivity Errors**: Database connection failures, API timeouts
- **Configuration Errors**: Missing credentials, invalid URLs
- **Authentication Errors**: Invalid API keys, expired tokens
- **Resource Errors**: Memory issues, connection pool exhaustion
- **External Service Errors**: Third-party API failures

### 7. Performance Considerations

#### Parallel Execution

- Health checks run concurrently where possible
- Configurable concurrency limits for region checks
- Non-blocking I/O operations

#### Caching Strategy

```typescript
export class HealthCacheService {
  private cache = new Map<string, CachedHealthResult>();

  async getOrExecute<T>(
    key: string,
    operation: () => Promise<T>,
    ttlMs: number,
  ): Promise<T> {
    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.timestamp < ttlMs) {
      return cached.result;
    }

    const result = await operation();
    this.cache.set(key, {
      result,
      timestamp: Date.now(),
    });

    return result;
  }
}
```

#### Resource Management

- Connection pooling reuse
- Memory-efficient result structures
- Configurable timeouts to prevent resource exhaustion
- Graceful degradation when components are slow/unresponsive

#### Monitoring and Metrics

- Health check duration tracking
- Success/failure rate monitoring
- Performance degradation detection
- Alert thresholds for response times

### 8. Implementation Roadmap

#### Phase 1: Core Infrastructure

1. Create HealthModule and basic structure
2. Implement ApiHealthChecker and DatabaseHealthChecker
3. Add timeout and error handling services
4. Basic response format

#### Phase 2: Region Health Checks

1. Implement SgtmRegionHealthChecker
2. Implement MetaCapiRegionHealthChecker
3. Add concurrent region checking
4. Enhanced region response format

#### Phase 3: Advanced Features

1. Implement WebhookHealthChecker
2. Add ContainerHealthChecker
3. Implement caching and circuit breaker
4. Add detailed health endpoint

#### Phase 4: Monitoring and Optimization

1. Add performance metrics
2. Implement alerting
3. Add configuration management
4. Comprehensive testing

### 9. Security Considerations

#### Information Disclosure

- Avoid exposing sensitive configuration details
- Sanitize error messages for production
- Rate limiting for health endpoint access

#### Authentication

- Consider authentication requirements for detailed health checks
- API key validation for external health monitoring

#### Network Security

- Validate webhook URLs to prevent SSRF attacks
- Use HTTPS for all external health check requests
- Certificate validation for region endpoints

### 10. Testing Strategy

#### Unit Tests

- Mock external dependencies (database, HTTP clients)
- Test individual health checkers
- Validate timeout and error handling

#### Integration Tests

- Test with real database connections
- Validate region API calls
- End-to-end health check flows

#### Performance Tests

- Load testing with concurrent requests
- Memory usage monitoring
- Timeout behavior validation

#### Monitoring Tests

- Alert threshold validation
- Circuit breaker behavior
- Cache effectiveness

This design provides a scalable, maintainable, and comprehensive health check system that can evolve with the application's needs while maintaining backward compatibility with the existing simple health endpoint.
