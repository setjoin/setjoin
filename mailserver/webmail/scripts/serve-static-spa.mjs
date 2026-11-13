import { createReadStream, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';

const root = resolve(process.argv[2] ?? 'build');
const port = Number.parseInt(process.argv[3] ?? '4178', 10);
const types = new Map([
	['.css', 'text/css; charset=utf-8'],
	['.html', 'text/html; charset=utf-8'],
	['.js', 'text/javascript; charset=utf-8'],
	['.json', 'application/json; charset=utf-8'],
	['.svg', 'image/svg+xml'],
	['.woff2', 'font/woff2']
]);

createServer((request, response) => {
	// One hostile request must never kill the preview server (a malformed
	// percent-encoding throws URIError out of decodeURIComponent, and a path
	// that vanishes between existsSync and statSync races ENOENT out of it) —
	// both answer 400/404 and keep the process serving the Playwright lane.
	try {
		const pathname = new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
		const relative = normalize(decodeURIComponent(pathname)).replace(/^(\.\.(\/|\\|$))+/, '');
		let target = join(root, relative);
		let stat = null;
		try {
			stat = statSync(target);
		} catch {
			stat = null; // missing or raced away — fall through to the SPA fallback
		}
		if (!target.startsWith(root) || stat === null || stat.isDirectory()) {
			target = join(root, 'index.html');
		}
		response.setHeader('Content-Type', types.get(extname(target)) ?? 'application/octet-stream');
		createReadStream(target).on('error', () => {
			response.writeHead(404).end('not found');
		}).pipe(response);
	} catch (error) {
		// decodeURIComponent URIError (or anything unexpected): 400, keep serving.
		response.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' }).end('bad request');
		void error;
	}
}).listen(port, '127.0.0.1');
