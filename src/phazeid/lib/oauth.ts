import { FastifyInstance } from "fastify";
import crypto from 'node:crypto';

import { findUserFromToken } from "../sessionUtils";

import { ResponseError } from "../types/ResponseError";

import apps from "../db/app";
import oauthsessions from "../db/oauthsession";

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
            url: { type: 'string' }
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

      let osession = await oauthsessions.create({
        _id: crypto.randomUUID(),
        token: crypto.randomBytes(32).toString('hex'),
        appID: app._id,
        valid: false,
        userID: user._id
      })

      reply.send({ ok: true, url: app.redirectUri + '?token=' + osession.token + '&id=' + osession._id });
    }
  )

  fastify.get<{ Querystring: { token: string, appid: string } }>(
    '/id/v1/oauth/app',
    {
      schema: {
        summary: 'Get an OAuth app info',
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

  fastify.put<{ Querystring: { apptoken: string, sesid: string } }>(
    '/id/v1/oauth/enable',
    {
      schema: {
        summary: 'Enables an OAuth token',
        tags: [ 'PhazeID (OAuth)' ],
        querystring: {
          apptoken: { type: 'string' },
          sesid: { type: 'string' }
        },
        response: {
          400: ResponseError,
          401: ResponseError,
          403: ResponseError,
          409: ResponseError,
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

      let ses = await oauthsessions.findById(req.query.sesid);
      if(!ses)
        return reply.code(400).send({ ok: false, error: 'Invalid Session ID' });

      if(ses.appID !== app._id)
        return reply.code(403).send({ ok: false, error: 'Invalid Session & App' });

      ses.valid = true;
      await ses.save();

      reply.send({ ok: true });
    }
  )

  fastify.delete<{ Querystring: { token: string } }>(
    '/id/v1/oauth',
    {
      schema: {
        summary: 'Destroys an OAuth token',
        tags: [ 'PhazeID (OAuth)' ],
        querystring: {
          token: { type: 'string' }
        },
        response: {
          400: ResponseError,
          200: { ok: { type: 'boolean' } }
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');
      reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');

      let ses = await oauthsessions.findOne({ token: req.query.token });
      if(!ses)
        return reply.code(400).send({ ok: false, error: 'Invalid Session' });

      await ses.deleteOne();
      reply.send({ ok: true });
    }
  )
}