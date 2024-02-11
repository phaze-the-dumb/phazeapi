import * as aviUtils from "../aviUtils";
import crypto from "node:crypto";
import * as argon2 from "argon2";
import { FastifyInstance } from "fastify";
import { Transporter } from "nodemailer";
import * as Speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';

import { cleanSessionsForUser, findUserFromToken } from "../sessionUtils";
import { SignupRequestBody, SignupRequestBodyType } from "../types/SignupRequestBody";
import { LoginRequestBody, LoginRequestBodyType } from "../types/LoginRequestBody";
import { VerifyRequestBody, VerifyRequestBodyType } from "../types/VerifyRequestBody";
import { ResponseError } from "../types/ResponseError";

import users from "../db/users";
import sessions from "../db/sessions";

export let main = async ( fastify: FastifyInstance, transport: Transporter ) => {
  fastify.options('/id/v1/auth/signup', { schema: { hide: true } }, ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "POST");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
  })

  fastify.post<{ Body: SignupRequestBodyType }>(
    '/id/v1/auth/signup',
    {
      schema: {
        summary: 'Create a user account',
        tags: [ 'PhazeID (Auth)' ],
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
      reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
      reply.header("Access-Control-Allow-Methods", "POST");

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

      let session = {
        _id: crypto.randomUUID(),
        token: crypto.randomBytes(32).toString('hex'),
        createdOn: new Date(),
        expiresOn: new Date(Date.now() + 604800000),
        loc: ipInfo,
        valid: true,
        challengeCode: '',
        userID
      }

      let userData = {
        _id: userID,

        username: req.body.username,
        password: await argon2.hash(req.body.password, { hashLength: 50, type: argon2.argon2id }),

        lastUsernameChange: new Date(),
        lastPasswordChange: new Date(),

        email: req.body.email,
        emailVerificationCode: Math.floor(Math.random() * 1_000_000).toString().padStart(6, '0'),
        emailVerified: false,

        avatar: crypto.randomUUID(),

        lastEmailChange: new Date(),
        lastAvatarChange: new Date(0),

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
            html: `Your verification code is ${ userData.emailVerificationCode }<br />Do <b>NOT</b> share this code with anyone.`
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
      await sessions.create(session);

      reply.send({ ok: true, session: session.token })
    }
  )

  fastify.options('/id/v1/auth/login', { schema: { hide: true } }, ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "POST");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
  })

  fastify.post<{ Body: LoginRequestBodyType }>(
    '/id/v1/auth/login',
    {
      schema: {
        summary: 'Generate a new session for an account',
        tags: [ 'PhazeID (Auth)' ],
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
      reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
      reply.header("Access-Control-Allow-Methods", "POST");

      if(!req.headers['cf-connecting-ip'])return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });

      if(req.headers["content-type"] !== 'application/json')return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });
      if(!req.body || !req.body.username || !req.body.password)return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });

      let user = await users.findOne({ username: req.body.username });
      if(!user)return reply.code(403).send({ ok: false, error: 'Incorrect Username or Password' });

      let isValid = await argon2.verify(user.password!, req.body.password, { type: argon2.argon2id });

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
                subject: 'Log-in Verification',
                html: `Your verication code is ${ session.challengeCode }<br />Do <b>NOT</b> share this code with anyone.<br /><br />IP Address: ${ipInfo.ip}<br />User-Agent: ${req.headers['user-agent']}<br /><br />If you do not recognise this login attempt, please contact _phaz on discord immediately.<br />Best regards, Phaze.`
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

        if(session.valid){
          transport.sendMail({
            from: 'Phaze ID <no-reply@phazed.xyz>',
            to: user!.email!,
            subject: 'Log-in Notification',
            html: `Hello ${user.username},<br /><br />There has just been a successful login attempt to your account<br /><br />IP Address: ${ipInfo.ip}<br />User-Agent: ${req.headers['user-agent']}<br /><br />If you do not recognise this login attempt, please contact _phaz on discord immediately.<br />Best regards, Phaze.`
          }, ( err, info ) => {
            if(err)
              console.error(err);
          })
        }
      } else
        reply.code(403).send({ ok: false, error: 'Incorrect Username or Password' });
    }
  )

  fastify.options('/id/v1/auth/resetpassword', { schema: { hide: true } }, ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "POST");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
  })
  
  fastify.post<{ Body: { email: String } }>(
    '/id/v1/auth/resetpassword',
    {
      schema: {
        summary: 'Send an email to reset the accounts password',
        tags: [ 'PhazeID (Auth)' ],
        body: { email: { type: 'string' } },
        response: {
          400: ResponseError,
          401: ResponseError,
          500: ResponseError,
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
      if(!req.body || !req.body.email)return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });
      
      let user = await users.findOne({ email: req.body.email });
      if(!user)
        return reply.code(401).send({ ok: false, error: 'Email not found' });

      user.passwordChangeToken = crypto.randomBytes(64).toString('hex');
      await user.save();

      let mail = () => {
        return new Promise<{ err: any, info: any }>(( res, rej ) => {
          transport.sendMail({
            from: 'Phaze ID <no-reply@phazed.xyz>',
            to: user!.email!,
            subject: 'Password Reset',
            html: `Click <a href="https://id.phazed.xyz/?passreset=${user!.passwordChangeToken}">here</a> to finish resetting your password<br /><br />IP Address: ${req.headers['cf-connecting-ip']}<br />User-Agent: ${req.headers['user-agent']}<br /><br />Best regards, Phaze.`
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

      reply.send({ ok: true });
    }
  )

  fastify.options('/id/v1/auth/resetpassword/reset', { schema: { hide: true } }, ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "POST");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
  })
  
  fastify.post<{ Body: { token: string, password: string } }>(
    '/id/v1/auth/resetpassword/reset',
    {
      schema: {
        summary: 'Fully reset an accounts password',
        tags: [ 'PhazeID (Auth)' ],
        body: { token: { type: 'string' }, password: { type: 'string' } },
        response: {
          400: ResponseError,
          401: ResponseError,
          500: ResponseError,
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
      if(!req.body || !req.body.token || !req.body.password)return reply.code(400).send({ ok: false, error: 'Invalid Request Body' });
      
      let user = await users.findOne({ passwordChangeToken: req.body.token });
      if(!user)
        return reply.code(401).send({ ok: false, error: 'Email not found' });

      user.password = await argon2.hash(req.body.password, { hashLength: 50, type: argon2.argon2id });
      user.passwordChangeToken = null;
      
      await user.save();
      reply.send({ ok: true });

      transport.sendMail({
        from: 'Phaze ID <no-reply@phazed.xyz>',
        to: user!.email!,
        subject: 'Password Reset Notification',
        html: `Your account password has been reset, If you do not recognise this activity please contact _phaz on discord immediately. <br /><br />IP Address: ${req.headers['cf-connecting-ip']}<br />User-Agent: ${req.headers['user-agent']}<br /><br />Best regards, Phaze.`
      }, ( err, info ) => {
        console.error(err);
      })
    }
  )

  fastify.get<{ Querystring: { token: string } }>(
    '/id/v1/auth/sessions',
    {
      schema: {
        summary: 'List all sessions for an account',
        tags: [ 'PhazeID (Auth)' ],
        querystring: {
          token: { type: 'string' }
        },
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
      reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
      reply.header("Access-Control-Allow-Methods", "GET");

      let { session, user } = await findUserFromToken(req, reply);
      if(!user)return;

      let sessionsList = await cleanSessionsForUser(user._id!);
      reply.send({ ok: true, currentSession: session._id, sessionCount: sessionsList.length, sessions: sessionsList.map(x => { return { _id: x._id, valid: x.valid, createdOn: x.createdOn.getTime(), expiresOn: x.expiresOn.getTime(), loc: x.loc } }) })
    }
  )

  fastify.options('/id/v1/auth/sessions', { schema: { hide: true } }, ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "DELETE,GET");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
  })

  fastify.delete<{ Querystring: { sessionId: string, token: string } }>(
    '/id/v1/auth/sessions',
    {
      schema: {
        summary: 'Delete a session for an account',
        tags: [ 'PhazeID (Auth)' ],
        querystring: {
          token: { type: 'string' }
        },
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
      reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
      reply.header("Access-Control-Allow-Methods", "DELETE");

      let { user } = await findUserFromToken(req, reply);
      if(!user)return;

      let sessionToRemove = await sessions.findById(req.query.sessionId);
      if(!sessionToRemove)return reply.code(404).send({ ok: false, error: 'Cannot find session' });

      user.sessions = user.sessions.filter(( x: string ) => x !== req.query.sessionId);

      await sessions.deleteOne({ _id: req.query.sessionId });
      await user.save();

      reply.send({ ok: true });
    }
  )

  fastify.options('/id/v1/auth/sessions/verify', { schema: { hide: true } }, ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "POST");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
  })

  fastify.post<{ Body: VerifyRequestBodyType, Querystring: { token: string } }>(
    '/id/v1/auth/sessions/verify',
    {
      schema: {
        summary: 'Verify a session via email',
        tags: [ 'PhazeID (Auth)' ],
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

      let { session, user } = await findUserFromToken(req, reply, { dontRequireEmail: true, dontRequireMfa: true });
      if(!user)return;

      if(session.valid)
        return reply.code(409).send({ ok: false, error: 'Email already verified' });

      if(session.challengeCode !== req.body.code)
        return reply.code(403).send({ ok: false, error: 'Invalid Code' });

      session.valid = true;
      session.challengeCode = '';
      await session.save();

      reply.send({ ok: true });

      transport.sendMail({
        from: 'Phaze ID <no-reply@phazed.xyz>',
        to: user!.email!,
        subject: 'Log-in Notification',
        html: `Hello ${user.username},<br /><br />There has just been a successful login attempt to your account<br /><br />IP Address: ${session.loc!.ip}<br />User-Agent: ${req.headers['user-agent']}<br /><br />If you do not recognise this login attempt, please contact _phaz on discord immediately.<br />Best regards, Phaze.`
      }, ( err, info ) => {
        if(err)
          console.error(err);
      })
    }
  )
  
  fastify.options('/id/v1/auth/mfa', { schema: { hide: true } }, ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "POST");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
  })

  fastify.post<{ Body: VerifyRequestBodyType, Querystring: { token: string } }>(
    '/id/v1/auth/mfa',
    {
      schema: {
        summary: 'Verify a session via MFA',
        tags: [ 'PhazeID (Auth)' ],
        querystring: {
          token: { type: 'string' }
        },
        body: VerifyRequestBody,
        response: {
          400: ResponseError,
          401: ResponseError,
          403: ResponseError,
          200: { ok: { type: 'boolean' } }
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');
      reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
      reply.header("Access-Control-Allow-Methods", "POST");

      let { session, user } = await findUserFromToken(req, reply, { dontRequireMfa: true });
      if(!user)return;

      if(!user.hasMfa || session.hasMfa)
        return reply.code(403).send({ ok: false, error: 'User does not have MFA enabled, or session is already verified' });

      let verified = Speakeasy.totp.verify({
        secret: user.mfaString!,
        encoding: 'base32',
        token: req.body.code
      })

      if(!verified)
        return reply.code(403).send({ ok: false, error: 'Invalid Code' });

      session.hasMfa = true;
      await session.save();

      reply.send({ ok: true });
    }
  )

  fastify.options('/id/v1/auth/mfa/enable', { schema: { hide: true } }, ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "POST,GET");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
  })

  fastify.get<{ Querystring: { token: string } }>(
    '/id/v1/auth/mfa/enable',
    {
      schema: {
        summary: 'Enable MFA (Part 1)',
        tags: [ 'PhazeID (Auth)' ],
        querystring: {
          token: { type: 'string' }
        },
        response: {
          400: ResponseError,
          401: ResponseError,
          403: ResponseError,
          500: ResponseError,
          200: { ok: { type: 'boolean' }, secret: { type: 'string' } }
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');
      reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
      reply.header("Access-Control-Allow-Methods", "GET");

      let { user } = await findUserFromToken(req, reply);
      if(!user)return;

      if(user.hasMfa) 
        return reply.code(409).send({ ok: false, error: 'Already has MFA' });

      let secret = Speakeasy.generateSecret({ length: 32, name: 'Phaze ID' });

      user.mfaString = secret.base32;
      await user.save();

      let qr = (): Promise<{ err: Error | null | undefined, url: string }> => {
        return new Promise(( res ) => {
          QRCode.toDataURL(secret.otpauth_url!, ( err, url ) => {
            res({ err, url });
          })
        })
      }

      let { err, url } = await qr();

      if(err)
        return reply.code(500).send({ ok: false, error: 'Internal Server Error' });

      reply.send({ ok: true, secret: url });
    }
  )

  fastify.post<{ Body: VerifyRequestBodyType, Querystring: { token: string } }>(
    '/id/v1/auth/mfa/enable',
    {
      schema: {
        summary: 'Enable MFA (Part 2)',
        tags: [ 'PhazeID (Auth)' ],
        body: { code: { type: 'string' } },
        querystring: {
          token: { type: 'string' }
        },
        response: {
          400: ResponseError,
          401: ResponseError,
          403: ResponseError,
          200: { ok: { type: 'boolean' } }
        }
      }
    },
    async ( req, reply ) => {
      reply.header('Content-Type', 'application/json');
      reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
      reply.header("Access-Control-Allow-Methods", "POST");

      let { user } = await findUserFromToken(req, reply);
      if(!user)return;

      if(user.hasMfa) 
        return reply.code(409).send({ ok: false, error: 'Already has MFA' });
      
      let verified = Speakeasy.totp.verify({
        secret: user.mfaString!,
        encoding: 'base32',
        token: req.body.code
      })

      if(!verified)
        return reply.code(403).send({ ok: false, error: 'Invalid Code' });

      user.hasMfa = true;
      await user.save();

      reply.send({ ok: true });
    }
  )

  fastify.get<{ Querystring: { token: string } }>(
    '/id/v1/auth/mfa/disable', 
    {
      schema: {
        summary: 'Disables MFA on an account',
        tags: [ 'PhazeID (Auth)' ],
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
    reply.header("Access-Control-Allow-Methods", "GET");

    
    let { user } = await findUserFromToken(req, reply);
    if(!user)return;

    user.hasMfa = false;
    user.mfaString = '';

    await user.save();
    reply.send({ ok: true })
  })

  fastify.options('/id/v1/auth/password', { schema: { hide: true } }, ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "PUT");
    reply.header("Access-Control-Allow-Headers", "Content-Type");
    
    reply.send('200 OK');
  })

  fastify.put<{ Querystring: { token: string }, Body: { password: string, mfaCode?: string, previousPass: string } }>(
    '/id/v1/auth/password', 
    {
      schema: {
        summary: 'Change your password',
        tags: [ 'PhazeID (Auth)' ],
        body: {
          password: { type: 'string' },
          mfaCode: { type: 'string' },
          previousPass: { type: 'string' }
        },
        response: {
          400: ResponseError,
          401: ResponseError,
          403: ResponseError,
          200: { ok: { type: 'boolean' } }
        }
      }
    },
    async ( req, reply ) => {
    reply.header('Content-Type', 'application/json');
    reply.header('Access-Control-Allow-Origin', 'https://id.phazed.xyz');
    reply.header("Access-Control-Allow-Methods", "PUT");

    let { session, user } = await findUserFromToken(req, reply);
    if(!user)return;

    if(!await argon2.verify(user.password!, req.body.previousPass, { type: argon2.argon2id }))
      return reply.code(403).send({ ok: false, error: 'Incorrect Password' });

    if(user.hasMfa){
      if(!req.body.mfaCode)return reply.code(403).send({ ok: false, error: 'Invalid Code' });
      
      let verified = Speakeasy.totp.verify({
        secret: user.mfaString!,
        encoding: 'base32',
        token: req.body.mfaCode
      })

      if(!verified)
        return reply.code(403).send({ ok: false, error: 'Invalid Code' });

      user.password = await argon2.hash(req.body.password, { hashLength: 50, type: argon2.argon2id });
      await user.save();

      reply.send({ ok: true });
    } else{
      user.password = await argon2.hash(req.body.password, { hashLength: 50, type: argon2.argon2id });
      await user.save();

      reply.send({ ok: true });
    }

    if(user.lastPasswordChange!.getTime() > Date.now() - 60000){
      transport.sendMail({
        from: 'Phaze ID <no-reply@phazed.xyz>',
        to: user!.email!,
        subject: 'Password Changed Notification',
        html: `Hello ${user.username},<br /><br />There has been a successful password change on your account.<br /><br />IP Address: ${session.loc!.ip}<br />User-Agent: ${req.headers['user-agent']}<br /><br />If you do not recognise this password change, please contact _phaz on discord immediately.<br />Best regards, Phaze.`
      }, ( err, info ) => {
        if(err)
          console.error(err);
      })
    }

    user.lastPasswordChange = new Date();
    await user.save();
  })
}