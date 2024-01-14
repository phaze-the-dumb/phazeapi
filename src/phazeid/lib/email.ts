import { FastifyInstance } from "fastify";

import { VerifyRequestBody, VerifyRequestBodyType } from "../types/VerifyRequestBody";
import { ResponseError } from "../types/ResponseError";

import users from "../db/users";
import sessions from "../db/sessions";

export let main = async ( fastify: FastifyInstance ) => {
  fastify.post<{ Body: VerifyRequestBodyType, Querystring: { token: String } }>(
    '/id/v1/email/verify',
    {
      schema: {
        summary: 'Verifies an email address during the signup process',
        tags: [ 'PhazeID (Email)' ],
        querystring: {
          token: { type: 'string' }
        },
        body: VerifyRequestBody,
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
      reply.header("Access-Control-Allow-Methods", "POST");

      if(!req.headers['cf-connecting-ip'])return reply.code(400).send({ ok: false, error: 'Invalid Request' });

      if(req.headers["content-type"] !== 'application/json')return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });
      if(!req.body || !req.body.code)return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });

      if(!req.query.token)return reply.code(400).send({ ok: false, error: 'Invalid Query String' });

      let session = await sessions.findOne({ token: req.query.token });
      if(!session)return reply.code(401).send({ ok: false, error: 'Invalid Token' });

      if(req.headers['cf-connecting-ip'] !== session.loc!.ip)
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      
      let user = await users.findById(session.userID);
      if(!user){
        await sessions.deleteOne({ _id: session._id });
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      }

      if(!session.expiresOn || session.expiresOn.getTime() < Date.now()){
        user.sessions = user.sessions.filter(x => x !== session!._id);
        await user.save();

        await sessions.deleteOne({ _id: session._id });
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      }

      if(!session.valid)
        return reply.code(403).send({ ok: false, error: 'Session requires verification' });

      if(user.emailVerified)
        return reply.code(409).send({ ok: false, error: 'Email already verified' });

      if(user.emailVerificationCode !== req.body.code)
        return reply.code(403).send({ ok: false, error: 'Invalid Code' });

      user.emailVerified = true;
      user.emailVerificationCode = '';
      await user.save();

      reply.send({ ok: true });
    }
  )
}