import { FastifyInstance } from "fastify";

import { ResponseError } from "../types/ResponseError";

// OAuth flow
/*
  Client sends appid to server with verification request
  Client sends returned token and id to 3rd party server
  3rd party server sends client tokenid and app token to main server to verify the token
*/

export let main = async ( fastify: FastifyInstance ) => {
  fastify.get<{ Querystring: { token: string, appid: string } }>(
    '/id/v1/oauth/accept',
    {
      schema: {
        summary: 'Accepts an oauth request',
        tags: [ 'PhazeID (OAuth)' ],
        querystring: {
          token: { type: 'string' },
          appid: { type: 'string' }
        },
        response: {
          400: ResponseError,
          401: ResponseError,
          403: ResponseError,
          409: ResponseError,
          200: { 
            ok: { type: 'boolean' },
            token: { type: 'string' }
          }
        }
      }
    },
    ( req, reply ) => {
      
    }
  )
}