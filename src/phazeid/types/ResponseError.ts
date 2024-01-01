import { Static, Type } from '@sinclair/typebox'

export const ResponseError = Type.Object({
  ok: Type.Boolean(),
  error: Type.String(),
})

export type ResponseErrorType = Static<typeof ResponseError>