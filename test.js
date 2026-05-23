import assert from 'node:assert';
import clash2sub from './index.js'

/**
 * Mocking a Shadowsocks configuration
 */
const mockProxies = [
	{
		name: "MyServer",
		type: "ss",
		server: "103.46.142.6",
		port: 80,
		cipher: "chacha20-ietf-poly1305",
		password: "Aass@112233"
	}
];

try {
	console.log('Starting Shadowsocks conversion test...');

	const result = clash2sub.convertClashProxiesToV2rayLinks(mockProxies);

	// The expected link based on base64(cipher:password) and server details
	const expectedLink = `ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpBYXNzQDExMjIzMw==@103.46.142.6:80#MyServer`;

	// Validate the result
	assert.strictEqual(result.length, 1, "Result should contain exactly one link!");
	assert.strictEqual(result[0], expectedLink, "Generated link does not match the expected format... 😿");

	console.log("Test passed successfully!");
} catch (err) {
	console.error('Oops... Test failed: ฅ(X_X)ฅ');
	console.error(err.message);
	process.exit(1);
}
