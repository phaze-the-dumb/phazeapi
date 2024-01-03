import { FastifyInstance } from "fastify";
import * as argon2 from "argon2";
import mongoose from "mongoose";
import crypto from "node:crypto";
import * as nodemailer from 'nodemailer';

import { SignupRequestBody, SignupRequestBodyType } from "./types/SignupRequestBody";
import { VerifyRequestBody, VerifyRequestBodyType } from "./types/VerifyRequestBody";
import { LoginRequestBody, LoginRequestBodyType } from "./types/LoginRequestBody";
import { ResponseError } from "./types/ResponseError";

import * as aviUtils from "./aviUtils";
import users from "./db/users";
import sessions from "./db/sessions";
import { cleanSessionsForUser } from "./sessionUtils";

let main = ( fastify: FastifyInstance ) => {
  mongoose.connect(process.env.MONGO_URI!)
    .then(() => console.log('Connected to MongoDB'))
    .catch(( e ) => console.error('Could not connect to MongoDB', e));

  let transport = nodemailer.createTransport({
    host: 'mail.phazed.xyz',
    port: 465,
    auth: {
      user: 'no-reply@phazed.xyz',
      pass: process.env.EMAIL_KEY
    },
    tls: { rejectUnauthorized: false },
  })

  // Auth
  fastify.post<{ Body: SignupRequestBodyType }>(
    '/api/id/v1/auth/signup',
    {
      schema: {
        body: SignupRequestBody,
        response: {
          400: ResponseError,
          409: ResponseError,
          406: ResponseError,
          500: ResponseError,
          200: { ok: { type: 'boolean' }, session: { type: 'string' } }
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');
      if(!req.headers['cf-connecting-ip'])return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });

      if(req.headers["content-type"] !== 'application/json')return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });
      if(!req.body || !req.body.username || !req.body.password || !req.body.email)return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });

      let user = await users.findOne({ username: req.body.username });
      if(user)return reply.code(409).send({ ok: false, error: 'User Already Exists' });

      user = await users.findOne({ email: req.body.email });
      if(user)return reply.code(409).send({ ok: false, error: 'User Already Exists' });

      let ipReq = await fetch(`https://ipinfo.io/${req.headers['cf-connecting-ip']}?token=${process.env.IPINFO_KEY}`);
      let ipInfo = await ipReq.json();

      let userID = crypto.randomUUID();

      let session = await sessions.create({
        _id: crypto.randomUUID(),
        token: crypto.randomBytes(32).toString('hex'),
        createdOn: new Date(),
        expiresOn: new Date(Date.now() + 259200000),
        loc: ipInfo,
        valid: true,
        challengeCode: '',
        userID
      })

      let userData = {
        _id: userID,

        username: req.body.username,
        password: await argon2.hash(req.body.password, { hashLength: 50, type: argon2.argon2id }),

        email: req.body.email,
        emailVerificationCode: Math.floor(Math.random() * 1_000_000).toString().padStart(6, '0'),
        emailVerified: false,

        avatar: crypto.randomUUID(),

        hasMfa: false,
        mfaString: null,

        roles: [],
        allowedApps: [],

        sessions: [ session._id ]
      }

      let mail = () => {
        return new Promise<{ err: any, info: any }>(( res, rej ) => {
          transport.sendMail({
            from: 'Phaze ID <no-reply@phazed.xyz>',
            to: userData.email,
            subject: 'Verification Email',
            html: `Your verication code is ${ userData.emailVerificationCode }<br />Do <b>NOT</b> share this code with anyone.`
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

      aviUtils.generateAvi(userData.username, userData._id + '/' + userData.avatar);
      await users.create(userData);

      reply.send({ ok: true, session: session.token })
    }
  )

  fastify.post<{ Body: LoginRequestBodyType }>(
    '/api/id/v1/auth/login',
    {
      schema: {
        body: LoginRequestBody,
        response: {
          400: ResponseError,
          403: ResponseError,
          200: { ok: { type: 'boolean' }, session: { type: 'string' }, requiresMfa: { type: 'boolean' }, valid: { type: 'boolean' } }
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');
      if(!req.headers['cf-connecting-ip'])return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });

      if(req.headers["content-type"] !== 'application/json')return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });
      if(!req.body || !req.body.username || !req.body.password)return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });

      let user = await users.findOne({ username: req.body.username });
      if(!user)return reply.code(403).send({ ok: false, error: 'Incorrect Username or Password' });

      let isValid = await argon2.verify(user.password!, req.body.password.toString(), { type: argon2.argon2id });

      if(isValid){
        let sessionsList = await cleanSessionsForUser(user._id!);

        let ipReq = await fetch(`https://ipinfo.io/${req.headers['cf-connecting-ip']}?token=${process.env.IPINFO_KEY}`);
        let ipInfo = await ipReq.json();

        let sessionValid = sessionsList.find(x => x.loc.ip === ipInfo.ip);
        if(!sessionValid || !sessionValid.valid)sessionValid = null;

        let session = await sessions.create({
          _id: crypto.randomUUID(),
          token: crypto.randomBytes(32).toString('hex'),
          createdOn: new Date(),
          expiresOn: new Date(Date.now() + 259200000),
          loc: ipInfo,
          valid: sessionValid ? true : false,
          challengeCode: sessionValid ? '' : Math.floor(Math.random() * 1_000_000).toString().padStart(6, '0'),
          userID: user._id
        })

        if(!session.valid){
          let mail = () => {
            return new Promise<{ err: any, info: any }>(( res, rej ) => {
              transport.sendMail({
                from: 'Phaze ID <no-reply@phazed.xyz>',
                to: user!.email!,
                subject: 'Verification Email',
                html: `Your verication code is ${ session.challengeCode }<br />Do <b>NOT</b> share this code with anyone.`
              }, ( err, info ) => {
                res({ err, info });
              })
            })
          }
    
          let sent = await mail();

          if(sent.err){
            console.error(sent.err);

            await sessions.deleteOne({ _id: session._id });
            return reply.send({ ok: false, error: 'Failed to verify email' });
          }
        }

        user.sessions.push(session._id!);
        await user.save();

        reply.send({ ok: true, session: session.token, requiresMfa: user.hasMfa, valid: session.valid })
      } else
        reply.code(403).send({ ok: false, error: 'Incorrect Username or Password' });
    }
  )

  fastify.get<{ Querystring: { token: String } }>(
    '/api/id/v1/auth/sessions',
    {
      schema: {
        response: {
          400: ResponseError,
          401: ResponseError,
          403: ResponseError,
          200: { 
            ok: { type: 'boolean' },
            currentSession: { type: 'string' },
            sessionCount: { type: 'number' },
            sessions: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  _id: { type: 'string' },
                  createdOn: { type: 'number' },
                  expiresOn: { type: 'number' },
                  valid: { type: 'boolean' },
                  loc: {
                    type: 'object',
                    properties: {
                      ip: { type: 'string' },
                      hostname: { type: 'string' },
                      city: { type: 'string' },
                      region: { type: 'string' },
                      country: { type: 'string' },
                      loc: { type: 'string' },
                      org: { type: 'string' },
                      postal: { type: 'string' },
                      timezone: { type: 'string' }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');

      if(!req.headers['cf-connecting-ip'])return reply.code(400).send({ ok: false, error: 'Invalid Request' });
      if(!req.query.token)return reply.code(400).send({ ok: false, error: 'Invalid Query String' });

      let session = await sessions.findOne({ token: req.query.token });
      if(!session)return reply.code(401).send({ ok: false, error: 'Invalid Token' });

      if(req.headers['cf-connecting-ip'] !== session.loc!.ip)
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      
      let user = await users.findById(session.userID);
      if(!user){
        sessions.deleteOne({ _id: session._id });
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      }

      if(!session.expiresOn || session.expiresOn.getTime() < Date.now()){
        user.sessions = user.sessions.filter(x => x !== session!._id);
        await user.save();

        sessions.deleteOne({ _id: session._id });
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      }

      if(!session.valid)
        return reply.code(403).send({ ok: false, error: 'Session requires verification' });

      let sessionsList = await cleanSessionsForUser(user._id!);
      reply.send({ ok: true, currentSession: session._id, sessionCount: sessionsList.length, sessions: sessionsList.map(x => { return { _id: x._id, valid: x.valid, createdOn: x.createdOn.getTime(), expiresOn: x.expiresOn.getTime(), loc: x.loc } }) })
    }
  )

  fastify.delete<{ Querystring: { sessionId: string, token: String } }>(
    '/api/id/v1/auth/sessions',
    {
      schema: {
        response: {
          400: ResponseError,
          401: ResponseError,
          404: ResponseError,
          403: ResponseError,
          200: { ok: { type: 'boolean' } }
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');

      if(!req.headers['cf-connecting-ip'])return reply.code(400).send({ ok: false, error: 'Invalid Request' });
      if(!req.query.token)return reply.code(400).send({ ok: false, error: 'Invalid Query String' });

      let session = await sessions.findOne({ token: req.query.token });
      if(!session)return reply.code(401).send({ ok: false, error: 'Invalid Token' });

      if(req.headers['cf-connecting-ip'] !== session.loc!.ip)
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      
      let user = await users.findById(session.userID);
      if(!user){
        sessions.deleteOne({ _id: session._id });
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      }

      if(!session.expiresOn || session.expiresOn.getTime() < Date.now()){
        user.sessions = user.sessions.filter(x => x !== session!._id);
        await user.save();

        sessions.deleteOne({ _id: session._id });
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      }

      if(!session.valid)
        return reply.code(403).send({ ok: false, error: 'Session requires verification' });

      let sessionToRemove = await sessions.findById(req.query.sessionId);
      if(!sessionToRemove)return reply.code(404).send({ ok: false, error: 'Cannot find session' });

      user.sessions = user.sessions.filter(x => x !== req.query.sessionId);

      await sessions.deleteOne({ _id: req.query.sessionId });
      await user.save();

      reply.send({ ok: true });
    }
  )

  fastify.post<{ Body: VerifyRequestBodyType, Querystring: { token: String } }>(
    '/api/id/v1/auth/sessions/verify',
    {
      schema: {
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
        sessions.deleteOne({ _id: session._id });
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      }

      if(!session.expiresOn || session.expiresOn.getTime() < Date.now()){
        user.sessions = user.sessions.filter(x => x !== session!._id);
        await user.save();

        sessions.deleteOne({ _id: session._id });
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      }

      if(session.valid)
        return reply.code(409).send({ ok: false, error: 'Email already verified' });

      if(session.challengeCode !== req.body.code)
        return reply.code(403).send({ ok: false, error: 'Invalid Code' });

      session.valid = true;
      session.challengeCode = '';
      await session.save();

      reply.send({ ok: true });
    }
  )

  // Email
  fastify.post<{ Body: VerifyRequestBodyType, Querystring: { token: String } }>(
    '/api/id/v1/email/verify',
    {
      schema: {
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
        sessions.deleteOne({ _id: session._id });
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      }

      if(!session.expiresOn || session.expiresOn.getTime() < Date.now()){
        user.sessions = user.sessions.filter(x => x !== session!._id);
        await user.save();

        sessions.deleteOne({ _id: session._id });
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

export default main;