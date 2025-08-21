import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const Impersonate = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.headers['x-impersonate-user'];
  },
);
