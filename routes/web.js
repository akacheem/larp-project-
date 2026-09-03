import { isUserAlreadySignup, newUser, verifyLogin } from "../core/auth.js";

// fastify.decorate('authenticate', async (request, reply) => {
//     try {
//         await request.jwtVerify()
//     } catch {
//         reply.status(401).send({ error: 'Unauthorized', message: 'Invalid or missing token' })
//     }
// })

async function genJwtToken(fastify, username, email) {
    return await fastify.jwt.sign({ username, email });
}

export default async function (fastify) {
    // default route 
    fastify.get('/', async (request, reply) => {
        return reply.view('index.ejs', {});
    });

    fastify.get('/signup', async (request, reply) => {
        return reply.view('signup.ejs', {});
    });

    fastify.get('/logout', async (request, reply) => {
        return reply.view('logout.ejs');
    })

    fastify.get('/login', async (request, reply) => {
        return reply.view('login.ejs');
    })

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

        return reply.status(200).send({ message: 'OK', token: genJwtToken(fastify, username, email) });
    })

    fastify.post("/submit-login", async (request, reply) => {
        const { email, password } = request.body;
        if (!password || !email) {
            return reply.status(400).send({ error: 'Bad Request', message: 'All fields are required' });
        }

        const verifyDat = await verifyLogin(email, password);

        if (verifyDat.status)
            return reply.status(200).send({ message: 'OK', token: await genJwtToken(fastify, verifyDat.user.name, verifyDat.user.email) });

        return reply.status(401).send({ error: 'Unauthorized', message: 'Unauthorized' });
    })
}