import type { ExecutionContext } from '@nestjs/common'

export const userFromContext = (context: ExecutionContext): Express.User | undefined => {
  // TODO: add support for more contexts, like GraphQL and Websocket
  if (context.getType() === 'http') {
    const httpContext = context.switchToHttp()
    const request = httpContext.getRequest<Express.Request>()
    return request.user
  }
  return undefined
}
