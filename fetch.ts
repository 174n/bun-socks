import * as net from "node:net";
import * as tls from "node:tls";

/**
 * Parses a standard SOCKS5 connection string.
 * Example: socks5://user:pass@127.0.0.1:1080
 */
export function parseProxyUrl(proxyUrl: string) {
	try {
		const parsed = new URL(proxyUrl);

		// Validate Protocol
		if (!parsed.protocol.startsWith("socks5")) {
			throw new Error(
				`Unsupported proxy protocol: ${parsed.protocol}. Only socks5: is supported.`,
			);
		}

		// Extract Authentication
		const user = parsed.username ? decodeURIComponent(parsed.username) : "";
		const password = parsed.password ? decodeURIComponent(parsed.password) : "";

		// Extract Host
		let host = parsed.hostname;
		// URL class keeps brackets for IPv6 (e.g. "[::1]"), but net.connect needs raw IP
		if (host.startsWith("[") && host.endsWith("]")) {
			host = host.slice(1, -1);
		}

		// Extract Port
		const port = parsed.port ? parseInt(parsed.port, 10) : 1080;

		return { host, port, user, password };
	} catch (err) {
		throw new Error(
			`Invalid proxy URL: ${proxyUrl}. Error: ${(err as Error).message}`,
		);
	}
}

/**
 * Establishes a raw TCP connection to the SOCKS5 proxy and performs the handshake.
 */
async function connectSocks5(
	proxyConfig: string,
	targetHost: string,
	targetPort: number,
): Promise<net.Socket> {
	const config = parseProxyUrl(proxyConfig);

	// Clean target host brackets if present
	let cleanTargetHost = targetHost;
	if (cleanTargetHost.startsWith("[") && cleanTargetHost.endsWith("]")) {
		cleanTargetHost = cleanTargetHost.slice(1, -1);
	}

	return new Promise((resolve, reject) => {
		const socket = net.connect(config.port, config.host);

		socket.setTimeout(10000, () => {
			socket.destroy();
			reject(new Error("Proxy connection timed out"));
		});

		socket.on("error", reject);

		socket.on("connect", () => {
			socket.setTimeout(0);
			// 1. Handshake: Version 5, Method 2 (User/Pass) & Method 0 (No Auth)
			const methods = new Uint8Array([0x05, 0x02, 0x00, 0x02]);
			socket.write(methods);
		});

		let state = "handshake";

		socket.on("data", (data) => {
			try {
				if (state === "handshake") {
					if (data[0] !== 0x05) throw new Error("Invalid SOCKS version");

					const selectedMethod = data[1];

					if (selectedMethod === 0x02) {
						// Username/Password Auth Required
						if (!config.user)
							throw new Error(
								"Proxy requested auth, but no credentials provided in URL",
							);

						const userLen = Buffer.byteLength(config.user);
						const passLen = Buffer.byteLength(config.password);
						const authBuffer = Buffer.alloc(3 + userLen + passLen);

						let offset = 0;
						authBuffer[offset++] = 0x01;
						authBuffer[offset++] = userLen;
						authBuffer.write(config.user, offset);
						offset += userLen;
						authBuffer[offset++] = passLen;
						authBuffer.write(config.password, offset);

						socket.write(authBuffer);
						state = "auth";
					} else if (selectedMethod === 0x00) {
						// No Auth Required - Skip to Connect
						sendConnectRequest();
					} else {
						throw new Error("Proxy rejected supported authentication methods");
					}
				} else if (state === "auth") {
					if (data[1] !== 0x00) throw new Error("SOCKS5 Authentication failed");
					sendConnectRequest();
				} else if (state === "connect") {
					if (data[1] !== 0x00)
						throw new Error(`SOCKS5 Connect failed: ${data[1]}`);

					// Done. Clean listeners so the socket is "raw" for the caller
					socket.removeAllListeners("data");
					socket.removeAllListeners("error");
					socket.removeAllListeners("timeout");
					resolve(socket);
				}
			} catch (err) {
				socket.destroy();
				reject(err);
			}
		});

		function sendConnectRequest() {
			// 3. Connect Request (Domain mode 0x03 is safest/simplest)
			const len = Buffer.byteLength(cleanTargetHost);
			const portBuffer = Buffer.alloc(2);
			portBuffer.writeUInt16BE(targetPort);

			const connectReq = Buffer.concat([
				Buffer.from([0x05, 0x01, 0x00, 0x03, len]),
				Buffer.from(cleanTargetHost),
				portBuffer,
			]);

			socket.write(connectReq);
			state = "connect";
		}
	});
}

export function decodeChunked(buffer: Buffer): Uint8Array {
	const chunks: Buffer[] = [];
	let index = 0;

	while (index < buffer.length) {
		const lineEnd = buffer.indexOf("\r\n", index);
		if (lineEnd === -1) break;

		const sizeStr = buffer.toString("utf8", index, lineEnd);
		const size = parseInt(sizeStr, 16);

		if (Number.isNaN(size)) {
			index = lineEnd + 2;
			continue;
		}
		if (size === 0) break;

		const dataStart = lineEnd + 2;
		const dataEnd = dataStart + size;

		if (dataEnd > buffer.length) break;

		chunks.push(buffer.subarray(dataStart, dataEnd));
		index = dataEnd + 2;
	}

	return new Uint8Array(Buffer.concat(chunks));
}

/**
 * Custom Fetch implementation that supports SOCKS5 via the 'proxy' init option.
 */
export async function fetch(
	input: string | URL | Request,
	init?: RequestInit & { proxy?: string },
): Promise<Response> {
	const proxyUrl = init?.proxy;

	// Fallback 1: No proxy specified
	if (!proxyUrl) {
		return globalThis.fetch(input, init);
	}

	// Fallback 2: Invalid proxy configuration string
	try {
		parseProxyUrl(proxyUrl);
	} catch (_err) {
		console.warn(
			`[bun-socks-proxy] Invalid proxy configuration: "${proxyUrl}". Falling back to native fetch.`,
		);

		// Fix: Strip the 'proxy' property so native fetch doesn't error on the unsupported protocol
		const { proxy: _, ...nativeInit } = init || {};
		return globalThis.fetch(input, nativeInit);
	}

	// 1. Normalize Input using native Request
	const req =
		input instanceof Request
			? new Request(input, init)
			: new Request(input.toString(), init);
	const urlObj = new URL(req.url);
	const isHttps = urlObj.protocol === "https:";
	const port = urlObj.port ? parseInt(urlObj.port, 10) : isHttps ? 443 : 80;

	// 2. Prepare Body (Read into memory to calculate Content-Length)
	let bodyUint8: Uint8Array | null = null;
	try {
		const buffer = await req.arrayBuffer();
		if (buffer.byteLength > 0) {
			bodyUint8 = new Uint8Array(buffer);
		}
	} catch (_e) {
		// Body already consumed or invalid
	}

	// 3. Get raw SOCKS socket
	const socksSocket = await connectSocks5(proxyUrl, urlObj.hostname, port);
	let socket: net.Socket | tls.TLSSocket = socksSocket;

	// 4. Upgrade to TLS manually if needed
	if (isHttps) {
		socket = tls.connect({
			socket: socksSocket,
			servername: urlObj.hostname,
			rejectUnauthorized: true,
		});
		await new Promise<void>((resolve, reject) => {
			socket.once("secureConnect", () => resolve());
			socket.once("error", reject);
		});
	}

	return new Promise((resolve, reject) => {
		// 5. Construct Raw HTTP Request
		const path = urlObj.pathname + urlObj.search;
		const hostHeader = urlObj.hostname + (urlObj.port ? `:${urlObj.port}` : "");

		let headerString = `${req.method} ${path} HTTP/1.1\r\n`;
		headerString += `Host: ${hostHeader}\r\n`;
		headerString += `Connection: close\r\n`;

		// Add Content-Length if body exists and header is missing
		if (bodyUint8 && !req.headers.has("content-length")) {
			req.headers.set("Content-Length", bodyUint8.byteLength.toString());
		}

		req.headers.forEach((value, key) => {
			const lowerKey = key.toLowerCase();
			if (lowerKey !== "host" && lowerKey !== "connection") {
				headerString += `${key}: ${value}\r\n`;
			}
		});

		if (!req.headers.has("user-agent")) {
			headerString += `User-Agent: Bun-Socks-Client\r\n`;
		}

		headerString += `\r\n`;

		// 6. Send Headers & Body
		socket.write(headerString);
		if (bodyUint8) {
			socket.write(bodyUint8);
		}

		// 7. Read Raw Response
		const chunks: Buffer[] = [];
		socket.on("data", (chunk) => chunks.push(chunk));

		socket.on("end", () => {
			const fullBuffer = Buffer.concat(chunks);

			const separator = Buffer.from("\r\n\r\n");
			const splitIndex = fullBuffer.indexOf(separator);

			if (splitIndex === -1) {
				reject(new Error("Invalid HTTP response: No header separator found"));
				return;
			}

			const headerBuffer = fullBuffer.subarray(0, splitIndex);
			const rawBody = fullBuffer.subarray(splitIndex + 4);

			const headerText = headerBuffer.toString();
			const lines = headerText.split("\r\n");
			const [_, statusStr, ...statusTextParts] = lines[0].split(" ");

			const status = parseInt(statusStr, 10) || 200;
			const statusText = statusTextParts.join(" ");

			const headers = new Headers();
			for (let i = 1; i < lines.length; i++) {
				const line = lines[i];
				if (!line) continue;
				const sep = line.indexOf(":");
				if (sep > 0) {
					const key = line.substring(0, sep).trim();
					const val = line.substring(sep + 1).trim();
					headers.append(key, val);
				}
			}

			let finalBody: Uint8Array = new Uint8Array(rawBody);

			const transferEncoding = headers.get("transfer-encoding");
			if (transferEncoding?.includes("chunked")) {
				finalBody = decodeChunked(rawBody);
			}

			resolve(
				new Response(finalBody, {
					status,
					statusText,
					headers,
				}),
			);
		});

		socket.on("error", (err) => reject(err));
	});
}
