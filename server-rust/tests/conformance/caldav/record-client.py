#!/usr/bin/env python3
"""Capture actual python-caldav 3.7.0 traffic against the frozen-Go front door.

Recorder only: pip install caldav==3.7.0 in a disposable venv. Normal Rust
session replay consumes the checked-in capture and needs no Python package.
Arguments: front-door URL, fixture bearer token, output JSON file.
"""
import json
import sys
from urllib.parse import urlsplit

import caldav

base, token, output = sys.argv[1:]
client = caldav.DAVClient(
    url=base + "/caldav/",
    headers={"Authorization": "Bearer " + token, "Host": "mail.test", "Accept-Encoding": "identity",
             "Origin": "http://mail.test", "X-Request-ID": "gofree-cal4-oracle"},
    require_tls=False, timeout=20, rate_limit_handle=False,
)
traffic, outcomes = [], []
phase = "discovery"
current_operation = ""
network_request = client.session.request


def capture(method, url, **kwargs):
    response = network_request(method, url, **kwargs)
    request = response.request
    body = request.body or b""
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    traffic.append({
        "session": phase,
        "operation": current_operation,
        "method": request.method,
        "path": urlsplit(request.url).path,
        "query": urlsplit(request.url).query,
        "headers": {k.lower(): v for k, v in request.headers.items()
                    if k.lower() not in {"authorization", "host", "content-length", "connection", "accept-encoding"}},
        "body": body,
        "response": {"status": response.status_code,
                     "headers": {k.lower(): [v] for k, v in response.headers.items()},
                     "body": response.content.decode("utf-8")},
    })
    return response


client.session.request = capture


def operation(name, action):
    global current_operation
    current_operation = name
    try:
        result = action()
        outcomes.append({"operation": name, "result": "ok", "count": len(result) if isinstance(result, list) else None})
        return result
    except Exception as exc:
        # Go's discovery/multiget bugs are part of the session, not a reason to
        # synthesize more compliant traffic. Error messages can contain ports.
        outcomes.append({"operation": name, "result": type(exc).__name__})
        return None


# Discovery is allowed to reveal the frozen server's broken resource types.
principal = operation("discover-principal", lambda: client.principal())
if principal is not None:
    operation("discover-calendars", lambda: principal.calendars())

client.close()
phase = "configured-calendar"
client = caldav.DAVClient(
    url=base + "/caldav/", headers={"Authorization": "Bearer " + token,
        "Host": "mail.test", "Origin": "http://mail.test", "Accept-Encoding": "identity",
        "X-Request-ID": "gofree-cal4-oracle"},
    require_tls=False, timeout=20, rate_limit_handle=False,
)
network_request = client.session.request
client.session.request = capture

calendar = caldav.Calendar(client=client, url=base + "/caldav/994261/")
operation("configured-calendar-name", calendar.get_display_name)
ical = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//CAL4 Real Client//EN\r\n"
        "BEGIN:VEVENT\r\nUID:cal4-client\r\nDTSTAMP:20310101T000000Z\r\n"
        "DTSTART:20310102T100000Z\r\nDTEND:20310102T110000Z\r\n"
        "SUMMARY:Real client round trip\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
event = operation("create-event", lambda: calendar.save_event(ical))
if event is not None:
    operation("fetch-event", lambda: event.load())
    operation("query-events", lambda: calendar.search(event=True))
    operation("lookup-uid", lambda: calendar.event_by_uid("cal4-client"))
    event.data = ical.replace("Real client round trip", "Real client updated")
    operation("update-event", lambda: event.save())
    operation("delete-event", event.delete)

client.close()
with open(output, "x", encoding="utf-8") as target:
    json.dump({"client": "python-caldav", "version": caldav.__version__,
               "outcomes": outcomes, "traffic": traffic}, target, indent=2)
    target.write("\n")
