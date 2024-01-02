import { FastifyInstance } from "fastify";
import * as argon2 from "argon2";
import mongoose from "mongoose";
import crypto from "node:crypto";
import * as nodemailer from 'nodemailer';

import { SignupRequestBody, SignupRequestBodyType } from "./types/SignupRequestBody";
import { VerifyRequestBody, VerifyRequestBodyType } from "./types/VerifyRequestBody";
import { LoginRequestBody, LoginRequestBodyType } from "./types/LoginRequestBody";
import { ResponseError } from "./types/ResponseError";
import { SignupResponse } from "./types/SignupResponse";
import { LoginResponse } from "./types/LoginResponse";

import * as aviUtils from "./aviUtils";
import users from "./db/users";
import sessions from "./db/sessions";
import { VerifyResponse } from "./types/VerifyResponse";

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
          200: SignupResponse
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

      let ipReq = await fetch(`https://ipinfo.io/${req.headers['cf-connecting-ip']}?token=96a00067d1963b`);
      let ipInfo = await ipReq.json();

      let userID = crypto.randomUUID()

      let session = await sessions.create({
        _id: crypto.randomUUID(),
        token: crypto.randomBytes(32).toString('hex'),
        createdOn: new Date(),
        expiresOn: new Date(Date.now() + 259200000),
        loc: ipInfo,
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
        return reply.send({ ok: false, error: 'Failed to verify email' });
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
          200: LoginResponse
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');

      if(req.headers["content-type"] !== 'application/json')return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });
      if(!req.body || !req.body.username || !req.body.password)return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });

      let user = await users.findOne({ username: req.body.username });
      if(!user)return reply.code(403).send({ ok: false, error: 'Incorrect Username or Password' });

      let isValid = await argon2.verify(user.password!, req.body.password.toString(), { type: argon2.argon2id });

      if(isValid)
        reply.send({ ok: true, session: 'no', requiresMfa: user.hasMfa })
      else
        reply.code(403).send({ ok: false, error: 'Incorrect Username or Password' });
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
          200: VerifyResponse
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');

      if(req.headers["content-type"] !== 'application/json')return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });
      if(!req.body || !req.body.code)return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });

      if(!req.query.token)return reply.code(400).send({ ok: false, error: 'Invalid Query String' });

      let session = await sessions.findOne({ token: req.query.token });
      if(!session)return reply.code(401).send({ ok: false, error: 'Invalid Token' });

      // if(!session.expiresOn || session.expiresOn.getTime() > Date.now())
      //   return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      
      let user = await users.findById(session.userID);
      if(!user){
        sessions.deleteOne({ _id: session._id })
        return reply.code(401).send({ ok: false, error: 'Invalid Session' });
      }

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