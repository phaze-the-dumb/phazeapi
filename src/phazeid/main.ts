import { FastifyInstance } from "fastify";
import * as argon2 from "argon2";
import mongoose from "mongoose";
import crypto from "node:crypto";
import * as nodemailer from 'nodemailer';

import { AuthRequestBody, AuthRequestBodyType } from "./types/AuthRequestBody";

import users from "./db/users";
import { ResponseError } from "./types/ResponseError";
import { SignupResponse } from "./types/SignupResponse";
import { LoginResponse } from "./types/LoginResponse";
import * as aviUtils from "./aviUtils";

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

  fastify.post<{ Body: AuthRequestBodyType }>(
    '/api/id/v1/auth/signup',
    {
      schema: {
        body: AuthRequestBody,
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
      if(!req.headers['CF-Connecting-IP'])return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });

      if(req.headers["content-type"] !== 'application/json')return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });
      if(!req.body || !req.body.username || !req.body.password || !req.body.email)return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });

      let user = await users.findOne({ username: req.body.username });
      if(user)return reply.code(409).send({ ok: false, error: 'User Already Exists' });

      let ipReq = await fetch(`https://ipinfo.io/${req.headers['CF-Connecting-IP']}?token=96a00067d1963b`);
      let ipInfo = await ipReq.json();

      let userData = {
        _id: crypto.randomUUID(),

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

        sessions: [
          {
            token: crypto.randomBytes(32).toString('hex'),
            createdOn: new Date(),
            expiresOn: new Date(Date.now() + 259200000),
            loc: ipInfo
          }
        ]
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

      reply.send({ ok: true, session: userData.sessions[0].token })
    }
  )

  fastify.post<{ Body: AuthRequestBodyType }>(
    '/api/id/v1/auth/login',
    {
      schema: {
        body: AuthRequestBody,
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
        reply.send({ ok: true, session: 'help', requiresMfa: user.hasMfa })
      else
        reply.code(403).send({ ok: false, error: 'Incorrect Username or Password' });
    }
  )
}

export default main;