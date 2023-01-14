import type { ExecutionContext } from '@nestjs/common'
import { createParamDecorator } from '@nestjs/common'
import { userFromContext } from './context.utils.js'

export const Jwt = createParamDecorator(
  (data: unknown, context: ExecutionContext) => {
    return userFromContext(context)?.jwt
  }
)
