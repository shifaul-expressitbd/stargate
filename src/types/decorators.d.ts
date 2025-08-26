declare global {
  // Override MethodDecorator to be compatible with NestJS
  type MethodDecorator = <T>(
    target: Object,
    propertyKey: string | symbol,
    descriptor: TypedPropertyDescriptor<T>
  ) => TypedPropertyDescriptor<T> | void;
}

export {};