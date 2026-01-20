/**
 * OIDC-Loki Standalone Server
 *
 * Entry point for running Loki as a standalone service.
 */

import { Loki } from "./core/loki.js";
import type { LokiConfig } from "./core/types.js";

async function main() {
	// TODO: Load config from file or CLI args
	const config: LokiConfig = {
		server: {
			port: Number(process.env["LOKI_PORT"]) || 3000,
			host: process.env["LOKI_HOST"] ?? "localhost",
		},
		provider: {
			issuer: process.env["LOKI_ISSUER"] ?? "http://localhost:3000",
			clients: [
				{
					client_id: "test-client",
					client_secret: "test-secret",
					redirect_uris: ["http://localhost:8080/callback"],
					grant_types: ["authorization_code", "client_credentials"],
				},
			],
		},
	};

	const loki = new Loki(config);

	// Handle shutdown
	const shutdown = async () => {
		console.log("\nShutting down Loki...");
		await loki.stop();
		process.exit(0);
	};

	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);

	await loki.start();

	console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██╗      ██████╗ ██╗  ██╗██╗                               ║
║   ██║     ██╔═══██╗██║ ██╔╝██║                               ║
║   ██║     ██║   ██║█████╔╝ ██║                               ║
║   ██║     ██║   ██║██╔═██╗ ██║                               ║
║   ███████╗╚██████╔╝██║  ██╗██║                               ║
║   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝                               ║
║                                                               ║
║   OIDC-Loki: The Bad Identity Provider                       ║
║   Security Chaos Engineering for OIDC                        ║
║                                                               ║
╠═══════════════════════════════════════════════════════════════╣
║   Server:  ${loki.address.padEnd(46)}║
║   Issuer:  ${loki.issuer.padEnd(46)}║
║   Plugins: ${String(loki.plugins.count).padEnd(46)}║
╚═══════════════════════════════════════════════════════════════╝
`);
}

main().catch((err) => {
	console.error("Failed to start Loki:", err);
	process.exit(1);
});
