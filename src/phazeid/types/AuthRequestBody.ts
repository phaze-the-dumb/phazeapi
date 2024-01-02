import { Static, Type } from '@sinclair/typebox'

export const AuthRequestBody = Type.Object({
  username: Type.String(),
  password: Type.String(),
  email: Type.String(),
})

export type AuthRequestBodyType = Static<typeof AuthRequestBody>