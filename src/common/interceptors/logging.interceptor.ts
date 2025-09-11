import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  constructor(private configService: ConfigService) {}

  private safeStringify(obj: any): string {
    const seen = new WeakSet();
    return JSON.stringify(obj, (key, value) => {
      if (typeof value === 'object' && value !== null) {
        if (seen.has(value)) {
          return '[Circular Reference]';
        }
        seen.add(value);
      }
      return value;
    });
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url, body, user } = request;
    const userAgent = request.get('User-Agent') || '';

    const now = Date.now();

    this.logger.log(
      `➡️  ${method} ${url} - User: ${user?.id || 'anonymous'} - ${userAgent}`,
    );

    if (body && Object.keys(body).length > 0) {
      this.logger.debug(`Request Body: ${JSON.stringify(body)}`);
    }

    return next.handle().pipe(
      tap({
        next: (data) => {
          const responseTime = Date.now() - now;
          this.logger.log(
            `⬅️  ${method} ${url} - ${responseTime}ms - User: ${user?.id || 'anonymous'}`,
          );
          if (this.configService.get<string>('NODE_ENV') === 'development') {
            // Use safe stringify to handle circular references
            this.logger.debug(`Response: ${this.safeStringify(data)}`);
          }
        },
        error: (error) => {
          const responseTime = Date.now() - now;
          this.logger.error(
            `❌ ${method} ${url} - ${responseTime}ms - Error: ${error.message} - User: ${user?.id || 'anonymous'}`,
          );
        },
      }),
    );
  }
}
