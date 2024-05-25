import { FastifyInstance } from "fastify";
import mongoose from "mongoose";
import * as nodemailer from 'nodemailer';

import * as auth from './lib/auth';
import * as email from './lib/email';
import * as profile from './lib/profile';
import * as oauth from './lib/oauth';
import * as patreon from './lib/patreon';

let main = async ( fastify: FastifyInstance ) => {
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
  await auth.main(fastify, transport);

  // Email
  await email.main(fastify);

  // Profile
  await profile.main(fastify, transport);

  // OAuth
  await oauth.main(fastify);

  // Patreon
  await patreon.main(fastify);
}

export default main;