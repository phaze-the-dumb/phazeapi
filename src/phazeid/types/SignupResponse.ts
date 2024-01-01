import { Static, Type } from '@sinclair/typebox'

export const SignupResponse = Type.Object({
  ok: Type.Boolean(),
  session: Type.String()
})

export type SignupResponseType = Static<typeof SignupResponse>