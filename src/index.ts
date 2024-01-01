import Fastify from "fastify";
import dotenv from "dotenv";
import { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";

import phazeid from './phazeid/main';

dotenv.config();

let fastify = Fastify({ logger: true }).withTypeProvider<TypeBoxTypeProvider>();

fastify.get('/api/status', ( req, reply ) => {
  reply.header('Access-Control-Allow-Origin', '*');
  reply.send({ ok: true });
})

phazeid(fastify);

fastify.listen({ port: 8080, host: '0.0.0.0' });