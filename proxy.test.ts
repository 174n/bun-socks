import { beforeAll, describe, expect, test } from "bun:test";
import { fetch as socksFetch } from "./fetch";

// Define strict types for our Environment to avoid TS errors
const rawConfig = process.env.PROXY_CONFIG;
let PROXY_URL = "";

describe("SOCKS5 Proxy Advanced Tests", () => {
	beforeAll(() => {
		if (!rawConfig) {
			console.warn("⚠️ PROXY_CONFIG is missing. Skipping tests.");
			// We can't actually skip 'describe' blocks dynamically in Bun yet,
			// but we will guard the tests inside.
			return;
		}

		// Convert comma-separated config to URL format if necessary
		// or just use it if it's already a URL.
		if (rawConfig.includes("://")) {
			PROXY_URL = rawConfig;
		} else {
			const [host, port, user, pass] = rawConfig
				.split(",")
				.map((s) => s.trim());
			const urlHost =
				host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
			PROXY_URL = `socks5://${user}:${pass}@${urlHost}:${port}`;
		}

		console.log(`🔌 Using Proxy: ${PROXY_URL}`);
	});

	test("Security: Proxy IP should differ from Local IP", async () => {
		if (!PROXY_URL) return;

		const ipService = "https://api64.ipify.org?format=json";

		// 1. Local IP
		const localRes = await fetch(ipService);
		const localJson = await localRes.json();

		// 2. Proxy IP
		const proxyRes = await socksFetch(ipService, { proxy: PROXY_URL });
		const proxyJson = await proxyRes.json();

		console.log(`🏠 Local: ${localJson.ip} | 🌍 Proxy: ${proxyJson.ip}`);

		expect(proxyRes.status).toBe(200);
		expect(proxyJson.ip).toBeDefined();
		expect(proxyJson.ip).not.toBe(localJson.ip);
	});

	test("Protocol: Should handle HTTP (Non-SSL) requests", async () => {
		if (!PROXY_URL) return;

		// We use detectportal.firefox.com as it supports plain HTTP reliably without redirects
		const res = await socksFetch(
			"http://detectportal.firefox.com/success.txt",
			{ proxy: PROXY_URL },
		);
		const text = await res.text();

		expect(res.status).toBe(200);
		expect(text.trim()).toBe("success");
	});

	test("Protocol: Should handle HTTPS (TLS Upgrade) requests", async () => {
		if (!PROXY_URL) return;

		const res = await socksFetch("https://postman-echo.com/get", {
			proxy: PROXY_URL,
		});
		const data = await res.json();

		expect(res.status).toBe(200);
		expect(data.url).toBe("https://postman-echo.com/get");
	});

	test("Methods: Should handle POST requests with JSON body", async () => {
		if (!PROXY_URL) return;

		const payload = { message: "Hello from SOCKS5", timestamp: Date.now() };

		const res = await socksFetch("https://postman-echo.com/post", {
			method: "POST",
			body: JSON.stringify(payload),
			headers: { "Content-Type": "application/json" },
			proxy: PROXY_URL,
		});

		const data = await res.json();

		expect(res.status).toBe(200);
		// Postman Echo puts the JSON body in the 'json' field
		expect(data.json).toEqual(payload);

		// Postman Echo usually lowercases headers in the response JSON
		expect(data.headers["content-type"]).toBe("application/json");
	});

	test("Headers: Should pass custom headers correctly", async () => {
		if (!PROXY_URL) return;

		const res = await socksFetch("https://postman-echo.com/headers", {
			headers: { "X-Custom-Auth": "SecretToken123" },
			proxy: PROXY_URL,
		});

		const data = await res.json();

		expect(res.status).toBe(200);
		// Header keys in the JSON response from Postman Echo are typically lowercase
		expect(data.headers["x-custom-auth"]).toBe("SecretToken123");

		// Verify default User-Agent is set by our library
		expect(data.headers["user-agent"]).toContain("Bun-Socks-Client");
	});

	test("Concurrency: Should handle parallel requests", async () => {
		if (!PROXY_URL) return;

		// Fire off 3 requests simultaneously using reliable endpoints
		const urls = [
			"https://postman-echo.com/ip",
			"https://postman-echo.com/headers",
			"https://postman-echo.com/get?test=concurrency",
		];

		const promises = urls.map((url) => socksFetch(url, { proxy: PROXY_URL }));
		const responses = await Promise.all(promises);

		for (const res of responses) {
			expect(res.ok).toBe(true);
			expect(res.status).toBe(200);
		}
	});

	test("Configuration: Should fallback to direct fetch on invalid proxy config", async () => {
		const invalidProxy = "invalid-protocol://nothing";

		// Should NOT throw, but return a valid response via direct fetch
		const res = await socksFetch(
			"http://detectportal.firefox.com/success.txt",
			{ proxy: invalidProxy },
		);
		const text = await res.text();

		expect(res.status).toBe(200);
		expect(text.trim()).toBe("success");
		// We cannot easily verify the IP is local here without external calls,
		// but the fact it didn't throw and returned success proves the fallback worked.
	});
});
