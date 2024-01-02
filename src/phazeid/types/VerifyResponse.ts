import { Static, Type } from '@sinclair/typebox'

export const VerifyResponse = Type.Object({
  ok: Type.Boolean()
})

export type VerifyResponseType = Static<typeof VerifyResponse>