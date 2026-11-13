#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import readline from 'node:readline';
import { once } from 'node:events';

const reportPath = process.argv[2];
if (!reportPath) {
	console.error('stream-go-test-json: report path is required');
	process.exit(2);
}

fs.mkdirSync(path.dirname(reportPath), { recursive: true });
const report = fs.createWriteStream(reportPath, { encoding: 'utf8' });
const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
let malformed = false;

for await (const line of lines) {
	if (!report.write(`${line}\n`)) await once(report, 'drain');
	if (!line.trim()) continue;
	try {
		const event = JSON.parse(line);
		if (event.Action === 'output' && typeof event.Output === 'string') {
			if (!process.stdout.write(event.Output)) await once(process.stdout, 'drain');
		}
	} catch (error) {
		malformed = true;
		console.error(`stream-go-test-json: malformed event: ${error.message}`);
	}
}

report.end();
await once(report, 'finish');
if (malformed) process.exitCode = 1;
