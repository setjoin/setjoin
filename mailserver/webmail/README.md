# Mailserver Webmail

A SvelteKit-based webmail frontend for the Mailserver JMAP API.

## Features

- **Login** — JWT authentication against the gateway
- **Inbox** — Folder list with unread counts; message list with sender/subject/date
- **Compose** — Plain-text email composition via JMAP EmailSubmission
- **Settings** — Placeholder for account preferences

## Development

```bash
npm install
npm run dev
```

The dev server proxies JMAP and auth requests to the gateway at `http://localhost:8080`.

## Build

```bash
npm run build
```

Outputs a static site to `build/` suitable for any static host or CDN.
