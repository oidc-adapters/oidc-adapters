import type { NextFunction, Request, Response } from 'express'

export default function setup (request: Request, response: Response, next: NextFunction) {
  request.kauth = {}
  next()
}
