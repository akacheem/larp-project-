import EventEmitter from 'events';

/**
 * REAL-TIME SYNCHRONIZATION EVENT BROKER (SSE)
 * 
 * Manages active Server-Sent Events (SSE) connections across organizations and classes.
 * Broadcasts data mutation events (batch student updates, deductions, AI executions)
 * so multiple connected users receive immediate updates without manual page refreshes.
 */

class SyncBroker extends EventEmitter {
    constructor() {
        super();
        this.clients = new Set();
        this.heartbeatInterval = null;
        this.initHeartbeat();
    }

    initHeartbeat() {
        // Send a lightweight comment ping every 25 seconds to keep SSE streams alive
        this.heartbeatInterval = setInterval(() => {
            const deadClients = [];
            for (const client of this.clients) {
                if (!client.reply.raw.destroyed && client.reply.raw.writable) {
                    try {
                        client.reply.raw.write(': ping\n\n');
                    } catch {
                        deadClients.push(client);
                    }
                } else {
                    deadClients.push(client);
                }
            }
            for (const dead of deadClients) {
                this.unregisterClient(dead);
            }
        }, 25000);

        if (this.heartbeatInterval.unref) {
            this.heartbeatInterval.unref();
        }
    }

    /**
     * Register a new client SSE connection
     */
    registerClient(request, reply, user, { classId = null, orgId = null } = {}) {
        const rawRes = reply.raw;

        // Hijack Fastify reply to manage the stream directly
        if (typeof reply.hijack === 'function') {
            reply.hijack();
        }

        rawRes.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache, no-transform',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
            'Access-Control-Allow-Origin': '*'
        });

        // Resolve organization ID for this user
        const resolvedOrgId = orgId 
            ? Number(orgId) 
            : (user.isOrganizationAccount ? Number(user.id) : Number(user.organizationId || 0));

        const client = {
            id: `client_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
            request,
            reply,
            userId: Number(user.id),
            userName: user.name || user.username || user.email,
            orgId: resolvedOrgId,
            classId: classId ? Number(classId) : null,
            connectedAt: Date.now()
        };

        this.clients.add(client);

        // Immediate greeting
        rawRes.write(`event: connected\ndata: ${JSON.stringify({ clientId: client.id, status: 'ok', timestamp: Date.now() })}\n\n`);

        const cleanup = () => {
            this.unregisterClient(client);
        };

        rawRes.on('close', cleanup);
        rawRes.on('error', cleanup);
        request.raw.on('close', cleanup);
        request.raw.on('error', cleanup);

        return client;
    }

    unregisterClient(client) {
        if (!client) return;
        this.clients.delete(client);
        try {
            if (!client.reply.raw.destroyed) {
                client.reply.raw.end();
            }
        } catch {
            // Ignore socket closure errors
        }
    }

    /**
     * Broadcast an event to relevant clients
     * @param {Object} eventParams
     * @param {number} [eventParams.orgId] - Target organization
     * @param {number} [eventParams.classId] - Target class (null for org-wide like dashboard)
     * @param {string} eventParams.type - e.g. 'STUDENTS_UPDATED', 'STUDENT_DEDUCTED', 'AI_MUTATION', 'CLASS_MUTATED'
     * @param {number} [eventParams.senderUserId] - ID of the user that initiated the action
     * @param {Object} [eventParams.data] - Custom event payload
     * @param {string} [eventParams.message] - Human-readable summary
     */
    broadcastSyncEvent({
        orgId = null,
        classId = null,
        type = 'SYNC',
        senderUserId = null,
        data = {},
        message = ''
    }) {
        const payload = JSON.stringify({
            type,
            orgId: orgId ? Number(orgId) : null,
            classId: classId ? Number(classId) : null,
            senderUserId: senderUserId ? Number(senderUserId) : null,
            data,
            message,
            timestamp: Date.now()
        });

        const eventData = `event: sync\ndata: ${payload}\n\n`;
        const deadClients = [];

        for (const client of this.clients) {
            // Filter by organization if specified
            if (orgId && client.orgId && client.orgId !== Number(orgId)) {
                continue;
            }

            // If an event is specific to a class, send it to:
            // 1. Clients on that specific class (client.classId === classId)
            // 2. Clients on the dashboard (client.classId === null)
            if (classId && client.classId !== null && client.classId !== Number(classId)) {
                continue;
            }

            if (!client.reply.raw.destroyed && client.reply.raw.writable) {
                try {
                    client.reply.raw.write(eventData);
                } catch {
                    deadClients.push(client);
                }
            } else {
                deadClients.push(client);
            }
        }

        for (const dead of deadClients) {
            this.unregisterClient(dead);
        }
    }

    getConnectedClientsCount(orgId = null) {
        if (!orgId) return this.clients.size;
        let count = 0;
        for (const c of this.clients) {
            if (c.orgId === Number(orgId)) count++;
        }
        return count;
    }
}

export const syncBroker = new SyncBroker();
