import { Static, Type } from '@sinclair/typebox'

export const VerifyRequestBody = Type.Object({
  code: Type.String()
})

export type VerifyRequestBodyType = Static<typeof VerifyRequestBody>