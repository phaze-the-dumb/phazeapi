import { Static, Type } from '@sinclair/typebox'

export const LoginRequestBody = Type.Object({
  username: Type.String(),
  password: Type.String()
})

export type LoginRequestBodyType = Static<typeof LoginRequestBody>