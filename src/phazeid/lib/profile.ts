import { FastifyInstance } from "fastify";
import { Transporter } from "nodemailer";

import { ResponseError } from "../types/ResponseError";
import * as aviUtils from '../aviUtils';

import users from "../db/users";
import sessions from "../db/sessions";

export let main = async ( fastify: FastifyInstance, transport: Transporter ) => {
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
          404: ResponseError,
          200: {
            ok: { type: 'boolean' },
            id: { type: 'string' },
            username: { type: 'string' },
            email: { type: 'string' },
            hasMfa: { type: 'boolean' },
            avatar: { type: 'string' }
          }
        }
      }
    },
    async ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "GET");

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
      
    if(!user.emailVerified)
      return reply.code(403).send({ ok: false, error: 'Verify Email' });

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

    if(req.params.user === '@me'){
      reply.send({
        ok: true,
        id: user._id,
        username: user.username,
        email: user.email,
        hasMfa: user.hasMfa,
        avatar: user.avatar
      })
    } else{
      let findUser = await users.findById(req.params.user);
      if(!findUser)
        return reply.code(404).send({ ok: false, error: 'User not found' });

      reply.send({
        ok: true,
        id: findUser._id,
        username: findUser.username,
        avatar: findUser.avatar
      })
    }
  })

  fastify.options('/id/v1/profile/username', ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "PUT");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
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
    reply.header("Access-Control-Allow-Methods", "PUT");

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
      
    if(!user.emailVerified)
      return reply.code(403).send({ ok: false, error: 'Verify Email' });

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

    if(user.lastUsernameChange!.getTime() > Date.now() - 600000)
      return reply.code(429).send({ ok: false, error: 'You can only change your username every 10 minutes' });
    
    let existsUser = await users.findOne({ username: req.body.username });
    if(existsUser)return reply.code(409).send({ ok: false, error: 'User already exists' });

    user.username = req.body.username;
    user.lastUsernameChange = new Date();
    await user.save();

    reply.send({ ok: true });
  })

  fastify.options('/id/v1/profile/avatar', ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "PUT");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
  })

  fastify.put<{ Querystring: { token: string }, Body: { email: string } }>(
    '/id/v1/profile/email', 
    {
      schema: {
        summary: 'Change your email',
        tags: [ 'PhazeID (Profile)' ],
        body: { email: { type: 'string' } },
        response: {
          400: ResponseError,
          401: ResponseError,
          403: ResponseError,
          409: ResponseError,
          429: ResponseError,
          500: ResponseError,
          200: { ok: { type: 'boolean' } }
        }
      }
    },
    async ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "PUT");

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
      
    if(!user.emailVerified)
      return reply.code(403).send({ ok: false, error: 'Verify Email' });

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

    if(user.lastEmailChange!.getTime() > Date.now() - 600000)
      return reply.code(429).send({ ok: false, error: 'You can only change your email every 10 minutes' });
    
    let existsUser = await users.findOne({ email: req.body.email });
    if(existsUser)return reply.code(409).send({ ok: false, error: 'User already exists' });

    user.email = req.body.email;
    user.emailVerified = false;
    user.emailVerificationCode = Math.floor(Math.random() * 1_000_000).toString().padStart(6, '0');

    user.lastEmailChange = new Date();

    let mail = () => {
      return new Promise<{ err: any, info: any }>(( res, rej ) => {
        transport.sendMail({
          from: 'Phaze ID <no-reply@phazed.xyz>',
          to: user!.email!,
          subject: 'Verification Email',
          html: `Your verification code is ${ user!.emailVerificationCode }<br />Do <b>NOT</b> share this code with anyone.`
        }, ( err, info ) => {
          res({ err, info });
        })
      })
    }

    let sent = await mail();

    if(sent.err){
      console.error(sent.err);
      return reply.code(500).send({ ok: false, error: 'Failed to verify email' });
    }

    await user.save();
    reply.send({ ok: true });
  })

  fastify.options('/id/v1/profile/avatar', ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "PUT");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
  })

  fastify.put<{ Querystring: { token: string }, Body: { img: string } }>(
    '/id/v1/profile/avatar', 
    {
      schema: {
        summary: 'Change your avatar',
        tags: [ 'PhazeID (Profile)' ],
        consumes: [ 'multipart/form-data' ],
        response: {
          400: ResponseError,
          401: ResponseError,
          403: ResponseError,
          429: ResponseError,
          500: ResponseError,
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
      
    if(!user.emailVerified)
      return reply.code(403).send({ ok: false, error: 'Verify Email' });

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

    if(user.lastAvatarChange!.getTime() > Date.now() - 600000)
      return reply.code(429).send({ ok: false, error: 'You can only change your avatar every 10 minutes' });

    let data = await req.file();
    if(!data)
      return reply.code(500).send({ ok: false, error: 'No file attached' });

    let newAviId = crypto.randomUUID();

    aviUtils.deleteAvi(user._id + '/' + user.avatar);
    aviUtils.upload(await data.toBuffer(), user._id + '/' + newAviId);

    user.avatar = newAviId;
    await user.save();

    reply.send({ ok: true });
  })
}