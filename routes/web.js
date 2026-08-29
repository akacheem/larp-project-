import { isUserAlreadySignup, newUser } from "../core/auth.js";

// fastify.decorate('authenticate', async (request, reply) => {
//     try {
//         await request.jwtVerify()
//     } catch {
//         reply.status(401).send({ error: 'Unauthorized', message: 'Invalid or missing token' })
//     }
// })

export default async function (fastify) {
    // default route 
    fastify.get('/', async (request, reply) => {
        return reply.view('index.ejs', {});
    });

    fastify.get('/signup', async (request, reply) => {
        return reply.view('signup.ejs', {});
    });

    fastify.post('/submit-signup', async (request, reply) => {
        const { username, email, password, isOrganization } = request.body;

        if (!username || !email || !password || !isOrganization) {
            return reply.status(400).send({ error: 'Bad Request', message: 'All fields are required' });
        }

        if (await isUserAlreadySignup(email)) {
            console.log(await isUserAlreadySignup(email))
            return reply.status(409).send({ error: 'Conflict', message: 'Email already used!' });
        }

        try {
            await newUser(username, isOrganization, email, password);
        } catch (e) {
            console.log(e)
            return reply.status(500).send({ error: 'Internal Server Error', message: 'Internal Server Error!' });
        }

        // setup jwt cookie
        let jwtStr = fastify.jwt.sign({ username, email });

        return reply.status(200).send({ error: 'OK', message: 'OK', token: jwtStr });
    })
}