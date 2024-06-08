import { FastifyInstance } from "fastify";

import { findUserFromToken } from "../sessionUtils";

import { ResponseError } from "../types/ResponseError";

import apps from "../db/app";
import users from "../db/users";

export let main = async ( fastify: FastifyInstance ) => {
  // V1 Auth flow
  /*
    Client sends appid to server with verification request
    Client sends returned token and id to 3rd party server
    3rd party server sends client tokenid and app token to main server to verify the token
  */

  fastify.get<{ Querystring: { token: string, appid: string } }>(
    '/id/v1/oauth/accept',
    {
      schema: {
        summary: 'Accepts an auth request',
        tags: [ 'PhazeID (External Auth)' ],
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
            url: { type: 'string' }
          }
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');
      reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');

      let { user, session } = await findUserFromToken(req, reply);
      if(!user || !session)return;

      if(!req.query.appid)
        return reply.code(400).send({ ok: false, error: 'Bad Request' });

      let app = await apps.findById(req.query.appid);
      if(!app)
        return reply.code(400).send({ ok: false, error: 'Bad Request' });

      reply.send({ ok: true, url: app.redirectUri + '?token=' + session.token });
    }
  )

  fastify.get<{ Querystring: { token: string, appid: string } }>(
    '/id/v1/oauth/app',
    {
      schema: {
        summary: 'Get an auth app info',
        tags: [ 'PhazeID (External Auth)' ],
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
            appname: { type: 'string' },
            appuri: { type: 'string' }
          }
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');
      reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');

      let { user } = await findUserFromToken(req, reply);
      if(!user)return;

      if(!req.query.appid)
        return reply.code(400).send({ ok: false, error: 'Bad Request' });

      let app = await apps.findById(req.query.appid);
      if(!app)
        return reply.code(400).send({ ok: false, error: 'Bad Request' });

      reply.send({ ok: true, appname: app.name, appuri: app.redirectUri })
    }
  )

  fastify.delete<{ Querystring: { apptoken: string, userid: string } }>(
    '/id/v1/oauth/app',
    {
      schema: {
        summary: 'Deauthorizes an auth app',
        tags: [ 'PhazeID (External Auth)' ],
        querystring: {
          apptoken: { type: 'string' },
          userid: { type: 'string' },
        },
        response: {
          401: ResponseError,
          200: { ok: { type: 'boolean' } }
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');
      reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');

      let app = await apps.findOne({ token: req.query.apptoken });
      if(!app)
        return reply.code(401).send({ ok: false, error: 'Unauthorized' });

      let user = await users.findById(req.query.userid);
      if(!user)
        return reply.code(401).send({ ok: false, error: 'Invalid UserID' });

      user.allowedApps = user.allowedApps.filter(x => x !== app!._id!);
      await user.save();

      reply.send({ ok: true });
    }
  )
}