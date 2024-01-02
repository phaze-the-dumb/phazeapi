import { Static, Type } from '@sinclair/typebox'

export const SignupRequestBody = Type.Object({
  username: Type.String(),
  password: Type.String(),
  email: Type.String(),
})

export type SignupRequestBodyType = Static<typeof SignupRequestBody>