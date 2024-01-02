import Fastify from "fastify";
import { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import 'dotenv/config';

import phazeid from './phazeid/main';

let fastify = Fastify({ logger: true }).withTypeProvider<TypeBoxTypeProvider>();

fastify.get('/api/status', ( req, reply ) => {
  reply.header('Access-Control-Allow-Origin', '*');
  reply.send({ ok: true });
})

phazeid(fastify);

fastify.listen({ port: 8080, host: '0.0.0.0' });
