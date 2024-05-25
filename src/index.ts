import Fastify from "fastify";
import { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import { spawn } from 'child_process';
import 'dotenv/config';

import swagger from '@fastify/swagger';
import swaggerui from '@fastify/swagger-ui';
import multipart from '@fastify/multipart';

import phazeid from './phazeid/main';

let main = async () => {
  let fastify = Fastify({ logger: true }).withTypeProvider<TypeBoxTypeProvider>();

  await fastify.register(swagger, {
    swagger: {
      info: {
        title: 'Phaze API',
        description: '',
        version: '0.1.0'
      },
      host: 'api.phazed.xyz',
      schemes: [ 'https' ],
      consumes: [ 'application/json' ],
      produces: [ 'application/json' ],
      tags: [
        { name: 'PhazeID (Auth)', description: 'Endpoints used to authenticate users.' },
        { name: 'PhazeID (Email)', description: 'Endpoints relating to emails.' },
        { name: 'PhazeID (External Auth)', description: 'Endpoints relating to auth.' },
        { name: 'PhazeID (Profile)', description: 'Endpoints used for users profiles.' },
        { name: 'Internal', description: 'Internal endpoints, Locked Down.' },
      ],
    }
  })
  
  await fastify.register(multipart, {
    limits: {
      fieldNameSize: 100,
      fieldSize: 100,
      fields: 10,
      fileSize: 2_000_000,
      files: 1,
      headerPairs: 2_000,
      parts: 1_000 
    }
  });

  await fastify.register(swaggerui, {
    routePrefix: '/docs'
  })

  fastify.get('/api/status', { schema: { tags: [ 'Internal' ] } }, ( req, reply ) => {
    reply.header('Access-Control-Allow-Origin', '*');
    reply.send({ ok: true });
  })

  fastify.get<{ Querystring: { key: String } }>('/api/update', { schema: { tags: [ 'Internal' ] } }, ( req, reply ) => {
    if(req.query.key !== process.env.MASTER_KEY)
      return reply.code(403).send({ ok: false });

    console.log('Pulling github repo.');

    spawn('git', [ 'pull', 'origin' ]).on('close', () => {
      console.log('Pulled github repo. Installing deps...');

      spawn('pnpm', [ 'install' ]).on('close', () => {
        console.log('Installed deps. Building...');

        spawn('pnpm', [ 'build' ]).on('close', () => {
          console.log('Built code. Restarting...');

          reply.send({ ok: true }).then(() => {
            spawn('service', [ 'api', 'restart' ]);
          }, () => {});
        })
      })
    })
  })

  await phazeid(fastify);

  fastify.listen({ port: 7001, host: '0.0.0.0' });

  await fastify.ready();
  fastify.swagger();
}

main();