#!/usr/bin/env python3
"""Actual vdirsyncer 0.20.0 sessions. Recording tooling; no Python in replay.

Arguments: observing front-door URL, fixture bearer token, fresh outcomes file.
The Rust observer records the unmodified client HTTP request/response bytes.
"""
import asyncio
import json
import os
import sys

import aiohttp
import vdirsyncer
from vdirsyncer.storage.dav import CardDAVStorage, DAVSession
from vdirsyncer.vobject import Item

base, token, output = sys.argv[1:]
os.environ["NO_PROXY"] = os.environ.get("NO_PROXY", "") + ",127.0.0.1,localhost"
network_request = DAVSession.request


async def authorized_request(self, method, path, **kwargs):
    headers = kwargs.setdefault("headers", {})
    headers.update({"Authorization": "Bearer " + token, "Host": "mail.test",
                    "Origin": "http://mail.test", "Accept-Encoding": "identity",
                    "X-Request-ID": "gofree-cal5-oracle"})
    return await network_request(self, method, path, **kwargs)


DAVSession.request = authorized_request
outcomes = []
phase = "discovery"


async def collect(source):
    return [value async for value in source]


async def operation(name, action):
    try:
        result = await action()
        outcomes.append({"session": phase, "operation": name, "result": "ok",
                         "count": len(result) if isinstance(result, list) else None})
        return result
    except Exception as error:
        # Preserve Go's client-visible failures, without transient ports/messages.
        outcomes.append({"session": phase, "operation": name,
                         "result": type(error).__name__})
        return None


async def main():
    global phase
    assert vdirsyncer.__version__ == "0.20.0"
    async with aiohttp.TCPConnector() as connector:
        await operation("discover-addressbooks", lambda: collect(CardDAVStorage.discover(
            url=base + "/carddav/", connector=connector)))
        for version in ("3.0", "4.0"):
            phase = "configured-vcard-" + version
            book = CardDAVStorage(url=base + "/carddav/994271/", connector=connector,
                                  use_vcard_4=version == "4.0")
            await operation("addressbook-name", lambda: book.get_meta("displayname"))
            card = ("BEGIN:VCARD\r\nVERSION:" + version + "\r\nUID:cal5-client-v" + version[0]
                    + "\r\nFN:Real client round trip\r\nN:Client;Alice;;;\r\n"
                    "EMAIL;TYPE=WORK:alice@example.test\r\nEND:VCARD\r\n")
            created = await operation("create-contact", lambda: book.upload(Item(card)))
            if created:
                href, etag = created
                await operation("get-returned-href", lambda: book.get(href))
                listing = await operation("list-contacts", lambda: collect(book.list()))
                if listing:
                    await operation("get-listed-contacts", lambda: collect(
                        book.get_multi([entry[0] for entry in listing])))
                updated = Item(card.replace("Real client round trip", "Real client updated"))
                next_etag = await operation("update-contact", lambda: book.update(href, updated, etag))
                await operation("delete-contact", lambda: book.delete(href, next_etag or etag))
            await operation("empty-after-delete", lambda: collect(book.list()))
        phase = "configured-gal"
        gal = CardDAVStorage(url=base + "/carddav/gal/", connector=connector)
        listing = await operation("list-directory", lambda: collect(gal.list()))
        if listing:
            await operation("read-directory", lambda: collect(gal.get_multi([entry[0] for entry in listing])))
        await operation("directory-is-read-only", lambda: gal.upload(Item(
            "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:cal5-client-forbidden\r\nFN:Forbidden\r\nEND:VCARD\r\n")))
    for version in ("3.0", "4.0"):
        for name in ("create-contact", "get-listed-contacts", "update-contact", "delete-contact"):
            assert any(row["session"] == "configured-vcard-" + version
                       and row["operation"] == name and row["result"] == "ok" for row in outcomes), outcomes
    assert any(row["operation"] == "read-directory" and row["result"] == "ok"
               and row["count"] == 2 for row in outcomes), outcomes
    with open(output, "x", encoding="utf-8") as target:
        json.dump({"client": "vdirsyncer", "version": vdirsyncer.__version__,
                   "outcomes": outcomes}, target, indent=2)
        target.write("\n")


asyncio.run(main())
