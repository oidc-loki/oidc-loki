/**
 * Admin API routes using Hono
 *
 * Provides REST endpoints for:
 * - Session management (CRUD)
 * - Plugin discovery
 * - Ledger retrieval
 * - Health monitoring
 */

import { Hono } from "hono";
import type { Session, SessionConfig } from "../core/types.js";
import type { MischiefLedger } from "../ledger/types.js";
import type { PluginRegistry } from "../plugins/registry.js";

export interface AdminDependencies {
	getIssuer: () => string;
	getPluginCount: () => number;
	getPluginRegistry: () => PluginRegistry;
	listSessions: () => Session[];
	createSession: (config?: Partial<SessionConfig>) => { id: string; mode: string };
	getSession: (
		id: string,
	) => { id: string; mode: string; isEnded: boolean; getLedger: () => MischiefLedger } | undefined;
	deleteSession: (id: string) => boolean;
	purgeSessions: () => void;
}

/**
 * Create the admin API Hono app
 */
export function createAdminApi(deps: AdminDependencies): Hono {
	const app = new Hono();

	// Health check
	app.get("/health", (c) => {
		return c.json({
			status: "ok",
			issuer: deps.getIssuer(),
			plugins: deps.getPluginCount(),
		});
	});

	// ===== Sessions API =====

	// List all sessions
	app.get("/sessions", (c) => {
		const sessions = deps.listSessions().map((s) => ({
			id: s.id,
			name: s.name,
			mode: s.mode,
			mischief: s.mischief,
			startedAt: s.startedAt.toISOString(),
			endedAt: s.endedAt?.toISOString(),
		}));
		return c.json({ sessions });
	});

	// Create a new session
	app.post("/sessions", async (c) => {
		const body = await c.req.json<Partial<SessionConfig>>().catch(() => ({}));
		const sessionConfig: Partial<SessionConfig> = {
			mode: body.mode ?? "explicit",
			mischief: body.mischief ?? [],
		};
		if (body.name !== undefined) {
			sessionConfig.name = body.name;
		}
		if (body.probability !== undefined) {
			sessionConfig.probability = body.probability;
		}
		const session = deps.createSession(sessionConfig);
		return c.json({ sessionId: session.id }, 201);
	});

	// Get session details
	app.get("/sessions/:id", (c) => {
		const id = c.req.param("id");
		const session = deps.getSession(id);
		if (!session) {
			return c.json({ error: "Session not found" }, 404);
		}
		const ledger = session.getLedger();
		return c.json({
			id: session.id,
			mode: session.mode,
			isEnded: session.isEnded,
			ledger: ledger.meta,
			summary: ledger.summary,
		});
	});

	// Get session ledger (full)
	app.get("/sessions/:id/ledger", (c) => {
		const id = c.req.param("id");
		const session = deps.getSession(id);
		if (!session) {
			return c.json({ error: "Session not found" }, 404);
		}
		return c.json(session.getLedger());
	});

	// Delete a session
	app.delete("/sessions/:id", (c) => {
		const id = c.req.param("id");
		const deleted = deps.deleteSession(id);
		if (!deleted) {
			return c.json({ error: "Session not found" }, 404);
		}
		return c.json({ deleted: true });
	});

	// Purge all sessions
	app.delete("/sessions", (c) => {
		deps.purgeSessions();
		return c.json({ purged: true });
	});

	// ===== Plugins API =====

	// List all plugins
	app.get("/plugins", (c) => {
		const plugins = deps
			.getPluginRegistry()
			.getAll()
			.map((p) => ({
				id: p.id,
				name: p.name,
				severity: p.severity,
				phase: p.phase,
				description: p.description,
			}));
		return c.json({ plugins });
	});

	// Get plugin details
	app.get("/plugins/:id", (c) => {
		const id = c.req.param("id");
		const plugin = deps.getPluginRegistry().get(id);
		if (!plugin) {
			return c.json({ error: "Plugin not found" }, 404);
		}
		return c.json({
			id: plugin.id,
			name: plugin.name,
			severity: plugin.severity,
			phase: plugin.phase,
			description: plugin.description,
			spec: plugin.spec,
		});
	});

	// Get plugins by phase
	app.get("/plugins/phase/:phase", (c) => {
		const phase = c.req.param("phase") as "token-signing" | "token-claims" | "response";
		const plugins = deps
			.getPluginRegistry()
			.getByPhase(phase)
			.map((p) => ({
				id: p.id,
				name: p.name,
				severity: p.severity,
				description: p.description,
			}));
		return c.json({ plugins });
	});

	// Get plugins by severity
	app.get("/plugins/severity/:severity", (c) => {
		const severity = c.req.param("severity") as "critical" | "high" | "medium" | "low";
		const plugins = deps
			.getPluginRegistry()
			.getBySeverity(severity)
			.map((p) => ({
				id: p.id,
				name: p.name,
				phase: p.phase,
				description: p.description,
			}));
		return c.json({ plugins });
	});

	// ===== Admin Actions =====

	// Reset everything
	app.post("/reset", (c) => {
		deps.purgeSessions();
		return c.json({ reset: true });
	});

	return app;
}
