export default async function (fastify) {
    // default route 
    fastify.get('/', async (request, reply) => {
        return reply.view('index.ejs', {});
    });

    fastify.get('/signup', async (request, reply) => {
        return reply.view('signup.ejs', {});
    });
}