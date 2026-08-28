import 'dotenv/config';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyView from '@fastify/view';
import fastifyFormbody from '@fastify/formbody';
import path from 'path';
import { fileURLToPath } from 'url';
import webRoutes from './routes/web.js';
import fastifyJwt from '@fastify/jwt';
import { listAllUser } from './core/auth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'iamgay';

try {
  listAllUser()
}
catch (e) {
  console.log(e)
}
const fastify = Fastify({ logger: true });

fastify.register(fastifyJwt, { secret: JWT_SECRET })
fastify.register(fastifyFormbody);

fastify.register(fastifyStatic, {
  root: path.join(__dirname, 'public'),
  prefix: '/public/',
});

fastify.register(fastifyView, {
  engine: {
    ejs: (await import('ejs')).default,
  },
  root: path.join(__dirname, 'views'),
});

fastify.register(webRoutes);

try {
  await fastify.listen({ port: PORT });
  console.log(`ok server started at http://localhost:${PORT}!`);
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}