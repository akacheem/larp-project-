import 'dotenv/config';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyView from '@fastify/view';
import fastifyFormbody from '@fastify/formbody';
import path from 'path';
import { fileURLToPath } from 'url';
import webRoutes from './routes/web.js';
import fastifyJwt from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';
import { initDatabase } from './core/db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_change_in_production';
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'fallback_cookie_secret_change_in_production';

if (process.env.NODE_ENV === 'production' && (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'iamgay')) {
  console.warn('⚠️ CẢNH BÁO BẢO MẬT: Vui lòng cấu hình JWT_SECRET ngẫu nhiên và an toàn trên Server Production!');
}

// Tự động kiểm tra và khởi tạo các bảng trong Database (đặc biệt khi kết nối Turso mới)
await initDatabase();

const fastify = Fastify({ 
  logger: process.env.DEBUG_MODE === 'true' ? true : { level: 'info' }
});

// Thêm các Security Headers bảo vệ ứng dụng
fastify.addHook('onSend', async (request, reply) => {
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('X-Frame-Options', 'SAMEORIGIN');
  reply.header('Referrer-Policy', 'strict-origin-when-cross-origin');
});

fastify.register(fastifyJwt, { secret: JWT_SECRET });
await fastify.register(fastifyCookie, {
  secret: COOKIE_SECRET,
  parseOptions: {}
});
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
  // host: '0.0.0.0' là bắt buộc để các nền tảng Cloud (Render, Railway...) nhận diện và mở cổng cho người dùng bên ngoài truy cập
  await fastify.listen({ port: Number(PORT), host: '0.0.0.0' });
  console.log(`🚀 Máy chủ EduManager đang chạy tại http://0.0.0.0:${PORT}`);
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}