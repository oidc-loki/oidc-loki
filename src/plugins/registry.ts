/**
 * Plugin Registry - manages discovery and registration of mischief plugins
 */

import { existsSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { PluginsConfig } from "../core/types.js";
import type { MischiefPlugin } from "./types.js";

export class PluginRegistry {
	private readonly plugins = new Map<string, MischiefPlugin>();
	private readonly config: Required<PluginsConfig>;

	constructor(config?: PluginsConfig) {
		this.config = {
			customDir: config?.customDir ?? "./plugins",
			disabled: config?.disabled ?? [],
		};
	}

	/**
	 * Load built-in plugins
	 */
	async loadBuiltIn(): Promise<void> {
		const { builtInPlugins } = await import("./built-in/index.js");

		for (const plugin of builtInPlugins) {
			if (!this.config.disabled.includes(plugin.id)) {
				this.plugins.set(plugin.id, plugin);
			}
		}
	}

	/**
	 * Discover and load custom plugins from the custom directory
	 *
	 * Scans for .js, .mjs, and .ts files and dynamically imports them.
	 * Each file can export a default MischiefPlugin or named exports.
	 */
	async discoverCustom(): Promise<void> {
		const customDir = resolve(process.cwd(), this.config.customDir);

		if (!existsSync(customDir)) {
			return; // No custom plugins directory, skip silently
		}

		const files = readdirSync(customDir).filter(
			(file) => /\.(js|mjs|ts)$/.test(file) && !file.endsWith(".d.ts"),
		);

		for (const file of files) {
			const filePath = resolve(customDir, file);
			await this.loadPluginFile(filePath);
		}
	}

	/**
	 * Load plugins from a single file
	 */
	private async loadPluginFile(filePath: string): Promise<void> {
		try {
			// Convert to file URL for dynamic import (required for ES modules)
			const fileUrl = pathToFileURL(filePath).href;
			const module = await import(fileUrl);

			// Check for default export
			if (module.default && this.isValidPlugin(module.default)) {
				this.registerIfEnabled(module.default);
			}

			// Check for named exports
			for (const [key, value] of Object.entries(module)) {
				if (key !== "default" && this.isValidPlugin(value)) {
					this.registerIfEnabled(value as MischiefPlugin);
				}
			}
		} catch (err) {
			// Log but don't throw - one bad plugin shouldn't break everything
			console.warn(`Failed to load plugin from ${filePath}:`, err);
		}
	}

	/**
	 * Register a plugin if not disabled
	 */
	private registerIfEnabled(plugin: MischiefPlugin): void {
		if (!this.config.disabled.includes(plugin.id)) {
			this.plugins.set(plugin.id, plugin);
		}
	}

	/**
	 * Validate that an object conforms to MischiefPlugin interface
	 */
	private isValidPlugin(obj: unknown): obj is MischiefPlugin {
		if (!obj || typeof obj !== "object") return false;

		const plugin = obj as Partial<MischiefPlugin>;
		return (
			typeof plugin.id === "string" &&
			typeof plugin.name === "string" &&
			typeof plugin.description === "string" &&
			typeof plugin.severity === "string" &&
			typeof plugin.phase === "string" &&
			typeof plugin.apply === "function" &&
			plugin.spec !== undefined &&
			typeof plugin.spec === "object" &&
			"description" in plugin.spec
		);
	}

	/**
	 * Register a plugin programmatically
	 */
	register(plugin: MischiefPlugin): void {
		this.plugins.set(plugin.id, plugin);
	}

	/**
	 * Unregister a plugin
	 */
	unregister(id: string): boolean {
		return this.plugins.delete(id);
	}

	/**
	 * Get a plugin by ID
	 */
	get(id: string): MischiefPlugin | undefined {
		return this.plugins.get(id);
	}

	/**
	 * Check if a plugin exists
	 */
	has(id: string): boolean {
		return this.plugins.has(id);
	}

	/**
	 * Get all registered plugins
	 */
	getAll(): MischiefPlugin[] {
		return Array.from(this.plugins.values());
	}

	/**
	 * Get plugin IDs
	 */
	getIds(): string[] {
		return Array.from(this.plugins.keys());
	}

	/**
	 * Get plugins by phase
	 */
	getByPhase(phase: MischiefPlugin["phase"]): MischiefPlugin[] {
		return this.getAll().filter((p) => p.phase === phase);
	}

	/**
	 * Get plugins by severity
	 */
	getBySeverity(severity: MischiefPlugin["severity"]): MischiefPlugin[] {
		return this.getAll().filter((p) => p.severity === severity);
	}

	/**
	 * Get count of registered plugins
	 */
	get count(): number {
		return this.plugins.size;
	}
}
