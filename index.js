'use strict';

const net = require('net');
const tls = require('tls');

// ================= CONFIG =================

const LISTEN_HOST = '0.0.0.0';
const LISTEN_PORT = 20267;

const SOCKS_USER = 'admw';
const SOCKS_PASS = 'admw';

const UPSTREAM_HOST = '45.56.228.8';
const UPSTREAM_PORT = 443;

//dial
const TLS_REJECT_UNAUTHORIZED = false;

// ==========================================

function log(type, message) {
    console.log(
        `[${new Date().toISOString()}] [${type}] ${message}`
    );
}

class SocketReader {
    constructor(socket) {
        this.socket = socket;
        this.buffer = Buffer.alloc(0);
        this.waiters = [];
        this.error = null;
        this.closed = false;

        this.onData = (data) => {
            this.buffer = Buffer.concat([this.buffer, data]);
            this.flush();
        };

        this.onError = (err) => {
            this.error = err;
            this.flush();
        };

        this.onClose = () => {
            this.closed = true;
            this.flush();
        };

        socket.on('data', this.onData);
        socket.on('error', this.onError);
        socket.on('close', this.onClose);
    }

    flush() {
        while (this.waiters.length > 0) {
            const resolve = this.waiters.shift();
            resolve();
        }
    }

    async waitForData() {
        if (this.error) throw this.error;
        if (this.closed) throw new Error('Socket closed');

        await new Promise((resolve) => {
            this.waiters.push(resolve);
        });

        if (this.error) throw this.error;
        if (this.closed && this.buffer.length === 0) {
            throw new Error('Socket closed');
        }
    }

    async read(size) {
        while (this.buffer.length < size) {
            await this.waitForData();
        }

        const result = this.buffer.subarray(0, size);
        this.buffer = this.buffer.subarray(size);

        return result;
    }

    async readUntil(marker, maxSize = 16384) {
        while (true) {
            const index = this.buffer.indexOf(marker);

            if (index !== -1) {
                const end = index + marker.length;
                const result = this.buffer.subarray(0, end);
                this.buffer = this.buffer.subarray(end);
                return result;
            }

            if (this.buffer.length > maxSize) {
                throw new Error('Response too large');
            }

            await this.waitForData();
        }
    }

    release() {
        this.socket.removeListener('data', this.onData);
        this.socket.removeListener('error', this.onError);
        this.socket.removeListener('close', this.onClose);

        if (this.buffer.length > 0) {
            this.socket.unshift(this.buffer);
            this.buffer = Buffer.alloc(0);
        }
    }
}

function closeSocket(socket) {
    if (socket && !socket.destroyed) {
        socket.destroy();
    }
}

function sendSocksReply(socket, code) {
    const reply = Buffer.from([
        0x05,
        code,
        0x00,
        0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ]);

    socket.write(reply);
}

function formatHost(host) {
    return host.includes(':') ? `[${host}]` : host;
}

async function connectUpstream(targetHost, targetPort) {
    return new Promise((resolve, reject) => {
        log(
            'UPSTREAM',
            `Connecting to ${UPSTREAM_HOST}:${UPSTREAM_PORT}`
        );

        const socket = tls.connect({
            host: UPSTREAM_HOST,
            port: UPSTREAM_PORT,

            // غیرفعال‌کردن اعتبارسنجی گواهی
            rejectUnauthorized: TLS_REJECT_UNAUTHORIZED
        });

        socket.setTimeout(20000);

        socket.once('secureConnect', async () => {
            try {
                socket.setTimeout(0);

                log('UPSTREAM', 'TLS connection established');

                const host = formatHost(targetHost);

                const request =
                    `CONNECT ${host}:${targetPort} HTTP/1.1\r\n` +
                    `Host: ${host}:${targetPort}\r\n` +
                    `Proxy-Connection: Keep-Alive\r\n` +
                    `Connection: Keep-Alive\r\n` +
                    `\r\n`;

                const reader = new SocketReader(socket);

                socket.write(request);

                const response = await reader.readUntil(
                    Buffer.from('\r\n\r\n')
                );

                const responseText = response.toString('latin1');
                const statusLine = responseText.split('\r\n')[0];

                log('UPSTREAM', `Response: ${statusLine}`);

                const match = statusLine.match(
                    /^HTTP\/\d(?:\.\d)?\s+(\d{3})/
                );

                if (!match || Number(match[1]) !== 200) {
                    reader.release();
                    throw new Error(
                        `Upstream CONNECT failed: ${statusLine}`
                    );
                }

                reader.release();

                resolve(socket);

            } catch (err) {
                closeSocket(socket);
                reject(err);
            }
        });

        socket.once('error', (err) => {
            reject(err);
        });

        socket.once('timeout', () => {
            closeSocket(socket);
            reject(new Error('Upstream connection timeout'));
        });
    });
}

async function handleClient(client) {
    const reader = new SocketReader(client);

    try {
        // SOCKS5 greeting
        const greeting = await reader.read(2);

        if (greeting[0] !== 0x05) {
            throw new Error('Unsupported SOCKS version');
        }

        const methods = await reader.read(greeting[1]);

        if (!methods.includes(0x02)) {
            client.write(Buffer.from([0x05, 0xFF]));
            throw new Error('Username/password authentication required');
        }

        client.write(Buffer.from([0x05, 0x02]));

        // Username/password authentication
        const authHeader = await reader.read(2);

        if (authHeader[0] !== 0x01) {
            throw new Error('Invalid authentication version');
        }

        const username = (
            await reader.read(authHeader[1])
        ).toString();

        const passwordLength = (await reader.read(1))[0];

        const password = (
            await reader.read(passwordLength)
        ).toString();

        if (
            username !== SOCKS_USER ||
            password !== SOCKS_PASS
        ) {
            client.write(Buffer.from([0x01, 0x01]));
            throw new Error('Authentication failed');
        }

        client.write(Buffer.from([0x01, 0x00]));

        log('AUTH', 'Client authenticated');

        // SOCKS5 connection request
        const request = await reader.read(4);

        if (request[0] !== 0x05 || request[1] !== 0x01) {
            sendSocksReply(client, 0x07);
            throw new Error('Unsupported SOCKS command');
        }

        const addressType = request[3];

        let targetHost;

        if (addressType === 0x01) {
            // IPv4
            targetHost = Array.from(
                await reader.read(4)
            ).join('.');

        } else if (addressType === 0x03) {
            // Domain name
            const length = (await reader.read(1))[0];

            targetHost = (
                await reader.read(length)
            ).toString();

        } else if (addressType === 0x04) {
            // IPv6
            const bytes = await reader.read(16);

            const groups = [];

            for (let i = 0; i < 16; i += 2) {
                groups.push(
                    bytes.readUInt16BE(i).toString(16)
                );
            }

            targetHost = groups.join(':');

        } else {
            sendSocksReply(client, 0x08);
            throw new Error('Unsupported address type');
        }

        const portBuffer = await reader.read(2);
        const targetPort = portBuffer.readUInt16BE(0);

        log(
            'SOCKS',
            `Requested destination: ${targetHost}:${targetPort}`
        );

        // Connect through HTTPS upstream proxy
        const upstream = await connectUpstream(
            targetHost,
            targetPort
        );

        // Restore any buffered client data
        reader.release();

        sendSocksReply(client, 0x00);

        log(
            'CONNECTED',
            `${targetHost}:${targetPort} through upstream`
        );

        // Bidirectional data transfer
        client.pipe(upstream);
        upstream.pipe(client);

        client.on('error', () => closeSocket(upstream));
        upstream.on('error', () => closeSocket(client));

        client.on('close', () => closeSocket(upstream));
        upstream.on('close', () => closeSocket(client));

    } catch (err) {
        log('ERROR', err.message);

        reader.release();
        closeSocket(client);
    }
}

// ================= SERVER =================

const server = net.createServer((client) => {
    log(
        'CLIENT',
        `New connection from ${client.remoteAddress}:${client.remotePort}`
    );

    handleClient(client);
});

server.on('error', (err) => {
    log('SERVER ERROR', err.message);
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
    console.log('');
    console.log('======================================');
    console.log('       SOCKS5 PROXY STARTED');
    console.log('======================================');

    log('SERVER', `Listening on ${LISTEN_HOST}:${LISTEN_PORT}`);
    log('SOCKS5', `Port: ${LISTEN_PORT}`);
    log('SOCKS5', `Username: ${SOCKS_USER}`);
    log('SOCKS5', 'Password: ********');
    log('UPSTREAM', `${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
    log('TLS', 'Certificate verification: DISABLED');

    console.log('======================================');
    console.log('');
});
