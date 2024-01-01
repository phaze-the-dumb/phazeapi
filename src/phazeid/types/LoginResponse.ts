import { Static, Type } from '@sinclair/typebox'

export const LoginResponse = Type.Object({
  ok: Type.Boolean(),
  session: Type.String(),
  requiresMfa: Type.Boolean()
})

export type LoginResponseType = Static<typeof LoginResponse>