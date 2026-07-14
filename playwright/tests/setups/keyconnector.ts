import { createServer, type Server } from 'node:http';

/**
 * Barebone in-memory key connector, just enough for the clients to enroll and unlock.
 * Keys are stored per token subject; token validation is deliberately out of scope,
 * this only exists to test the Vaultwarden and web client side of the flow.
 */
export function startMockKeyConnector(port: number) {
    const keys = new Map<string, string>();

    const server = createServer((req, res) => {
        // The web client calls us cross-origin, with credentials
        res.setHeader('Access-Control-Allow-Origin', req.headers['origin'] ?? '*');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] ?? '*');

        if (req.method === 'OPTIONS') {
            res.writeHead(204).end();
            return;
        }

        if (req.url === '/alive') {
            res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({}));
            return;
        }

        const sub = tokenSubject(req.headers['authorization']);
        if (!sub) {
            res.writeHead(401).end();
            return;
        }

        if (req.url !== '/user-keys') {
            res.writeHead(404).end();
            return;
        }

        if (req.method === 'GET') {
            if (!keys.has(sub)) {
                res.writeHead(404).end();
                return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ key: keys.get(sub) }));
        } else if (req.method === 'POST') {
            let body = '';
            req.on('data', (chunk) => body += chunk);
            req.on('end', () => {
                keys.set(sub, JSON.parse(body).key);
                res.writeHead(200).end();
            });
        } else {
            res.writeHead(405).end();
        }
    });

    server.listen(port);
    console.log(`Mock key connector running on port ${port}`);

    return {
        keys,
        stop: () => server.close(),
    };
}

function tokenSubject(header?: string): string | null {
    try {
        return JSON.parse(Buffer.from(header.replace(/^Bearer /, '').split('.')[1], 'base64url').toString()).sub;
    } catch {
        return null;
    }
}
