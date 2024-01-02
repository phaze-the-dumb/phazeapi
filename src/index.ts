import Fastify from "fastify";
import { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import { spawnSync } from 'child_process';
import 'dotenv/config';

import phazeid from './phazeid/main';

let fastify = Fastify({ logger: true }).withTypeProvider<TypeBoxTypeProvider>();

fastify.get('/api/status', ( req, reply ) => {
  reply.header('Access-Control-Allow-Origin', '*');
  reply.send({ ok: true });
})

fastify.get<{ Querystring: { key: String } }>('/api/update', ( req, reply ) => {
  if(req.query.key === process.env.MASTER_KEY)
    return reply.code(403).send({ ok: false });

  spawnSync('git pull origin');
  spawnSync('npm run build');

  reply.send({ ok: true });
  spawnSync('service api restart');
})

phazeid(fastify);

fastify.listen({ port: 8080, host: '0.0.0.0' });
