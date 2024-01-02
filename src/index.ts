import Fastify from "fastify";
import { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import { spawn } from 'child_process';
import 'dotenv/config';

import phazeid from './phazeid/main';

let fastify = Fastify({ logger: true }).withTypeProvider<TypeBoxTypeProvider>();

fastify.get('/api/status', ( req, reply ) => {
  reply.header('Access-Control-Allow-Origin', '*');
  reply.send({ ok: true });
})

fastify.get<{ Querystring: { key: String } }>('/api/update', ( req, reply ) => {
  if(req.query.key !== process.env.MASTER_KEY)
    return reply.code(403).send({ ok: false });

  console.log('Pulling github repo.');

  spawn('git', [ 'pull', 'origin' ]).on('close', () => {
    console.log('Pulled github repo. Installing deps...');

    spawn('npm', [ 'install' ]).on('close', () => {
      console.log('Installed deps. Building...');

      spawn('npm', [ 'run', 'build' ]).on('close', () => {
        console.log('Built code. Restarting...');

        reply.send({ ok: true });
        spawn('service api restart');
      })
    })
  })
})

phazeid(fastify);

fastify.listen({ port: 8080, host: '0.0.0.0' });
