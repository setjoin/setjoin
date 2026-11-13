import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig(({ mode }) => ({
	plugins: [sveltekit()],
	test: {
		include: ['src/**/*.{test,spec}.{js,ts}'],
		environment: 'jsdom',
		globals: true,
		setupFiles: ['./vitest.setup.ts'],
		coverage: {
			// Vitest 4 includes untouched source files only when this scope is
			// explicit. Keep the denominator honest across the whole Webmail tree.
			include: ['src/**/*.{js,ts,svelte}'],
			reporter: ['text', 'json', 'json-summary'],
			// Ratchet the measured 2026-07-23 whole-src baseline. These floors make
			// `npm run test:coverage` fail on material regression while leaving
			// room for source-map rounding across supported Node patch releases.
			thresholds: { statements: 80, branches: 70, functions: 80, lines: 82 },
		},
		server: {
			// B3 Task 9: open-color (an @excalidraw/excalidraw transitive dep)
			// ships as a bare `main: "open-color.json"` CJS package with no
			// import assertion — Node's native ESM loader (which Vitest uses
			// for externalized deps) rejects that. Inlining routes it through
			// Vite's own JSON-aware transform instead (the client `vite build`
			// path never hits this — it never externalizes to Node's loader).
			deps: { inline: [/@excalidraw\/excalidraw/, /open-color/] },
		},
	},
	resolve: {
		// B3 Task 9: @excalidraw/excalidraw's package.json exports its own
		// index.css ONLY under custom "development"/"production" conditions
		// (no "default" fallback) — this project's own conditions list
		// previously hard-coded to just ['browser'], which satisfies neither,
		// so `vite build`'s stricter resolution (rolldown) rejected the CSS
		// import. Add whichever of the two matches the actual build mode
		// (mirrors Vite's own normally-automatic condition, which the
		// pre-existing conditions override was suppressing).
		conditions: ['browser', mode === 'production' ? 'production' : 'development']
	},
	server: {
		port: 5173,
		proxy: {
			'/jmap': 'http://localhost:8080',
			'/.well-known': 'http://localhost:8080',
			'/auth': 'http://localhost:8080',
			'/blobs': 'http://localhost:8080',
			'/admin': 'http://localhost:8080'
		}
	}
}));
