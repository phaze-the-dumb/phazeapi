import { FastifyInstance } from "fastify";

import { ResponseError } from "../types/ResponseError";

import users from "../db/users";
import sessions from "../db/sessions";

export let main = async ( fastify: FastifyInstance ) => {
  fastify.get<{ Querystring: { token: string }, Params: { user: string } }>(
    '/id/v1/profile/:user', 
    {
      schema: {
        summary: 'Returns a user profile',
        tags: [ 'PhazeID (Profile)' ],
        response: {
          400: ResponseError,
          401: ResponseError,
          403: ResponseError,
          501: ResponseError,
          200: {
            ok: { type: 'boolean' },
            id: { type: 'string' },
            username: { type: 'string' },
            hasMfa: { type: 'boolean' },
            avatar: { type: 'string' }
          }
        }
      }
    },
    async ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');

    if(!req.headers['cf-connecting-ip'])return reply.code(400).send({ ok: false, error: 'Invalid Request' });
    if(!req.query.token)return reply.code(400).send({ ok: false, error: 'Invalid Query String' });

    let session = await sessions.findOne({ token: req.query.token });
    if(!session)return reply.code(401).send({ ok: false, error: 'Invalid Token' });

    if(req.headers['cf-connecting-ip'] !== session.loc!.ip)
      return reply.code(401).send({ ok: false, error: 'Invalid Session' });
    
    let user = await users.findById(session.userID);
    if(!user){
      await sessions.deleteOne({ _id: session._id });
      reply.code(401).send({ ok: false, error: 'Invalid Session' });

      return;
    }

    if(user.hasMfa && !session.hasMfa)
      return reply.code(403).send({ ok: false, error: 'MFA Auth Needed' });

    if(!session.expiresOn || session.expiresOn.getTime() < Date.now()){
      user.sessions = user.sessions.filter(x => x !== session!._id);
      await user.save();

      await sessions.deleteOne({ _id: session._id });
      reply.code(401).send({ ok: false, error: 'Invalid Session' });

      return;
    }

    if(!session.valid)
      return reply.code(403).send({ ok: false, error: 'Session requires verification' });

    if(req.params.user){
      return reply.send({
        ok: true,
        id: user._id,
        username: user.username,
        hasMfa: user.hasMfa,
        avatar: user.avatar
      })
    }

    reply.code(501).send({ ok: false, error: 'Endpoint Doesn\'t Exist... Yet.' })
  })

  fastify.put<{ Querystring: { token: string }, Body: { username: string } }>(
    '/id/v1/profile/username', 
    {
      schema: {
        summary: 'Change your username',
        tags: [ 'PhazeID (Profile)' ],
        body: { username: { type: 'string' } },
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

    if(!req.headers['cf-connecting-ip'])return reply.code(400).send({ ok: false, error: 'Invalid Request' });
    if(!req.query.token)return reply.code(400).send({ ok: false, error: 'Invalid Query String' });

    let session = await sessions.findOne({ token: req.query.token });
    if(!session)return reply.code(401).send({ ok: false, error: 'Invalid Token' });

    if(req.headers['cf-connecting-ip'] !== session.loc!.ip)
      return reply.code(401).send({ ok: false, error: 'Invalid Session' });
    
    let user = await users.findById(session.userID);
    if(!user){
      await sessions.deleteOne({ _id: session._id });
      reply.code(401).send({ ok: false, error: 'Invalid Session' });

      return;
    }

    if(user.hasMfa && !session.hasMfa)
      return reply.code(403).send({ ok: false, error: 'MFA Auth Needed' });

    if(!session.expiresOn || session.expiresOn.getTime() < Date.now()){
      user.sessions = user.sessions.filter(x => x !== session!._id);
      await user.save();

      await sessions.deleteOne({ _id: session._id });
      reply.code(401).send({ ok: false, error: 'Invalid Session' });

      return;
    }

    if(!session.valid)
      return reply.code(403).send({ ok: false, error: 'Session requires verification' });

    if(user.lastUsernameChange!.getTime() < Date.now() - 600000)
      return reply.code(429).send({ ok: false, error: 'You can only change your username every 10 minutes' });
    
    let existsUser = await users.findOne({ username: req.body.username });
    if(existsUser)return reply.code(409).send({ ok: false, error: 'User already exists' });

    user.username = req.body.username;
    await user.save();

    reply.send({ ok: true });

    user.lastUsernameChange = new Date();
    await user.save();
  })
}