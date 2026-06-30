# 03 — Turbo Intruder and the Single-Packet Attack Technique

## Why a special tool is needed at all

The core problem with exploiting a race window is **network jitter**: even if you click "send" on
two requests at the exact same instant, TCP/IP, TLS negotiation, routing, and server-side request
queuing introduce small, unpredictable delays. If those delays are larger than the race window
itself (often single-digit milliseconds), your "simultaneous" requests will actually be processed
sequentially by the server, and the race condition will never trigger — even though the underlying
vulnerability is real.

Burp Repeater (2023.9+) and the Turbo Intruder extension both solve this with the
**single-packet attack technique**, first published by PortSwigger Research at Black Hat USA 2023
(whitepaper: *Smashing the State Machine: The True Potential of Web Race Conditions*).

## The single-packet attack technique, explained

On an HTTP/2 connection, a client can open a single TCP stream and queue up multiple complete HTTP
requests on it, but deliberately withhold the very last byte (or last frame) of each request from
actually being transmitted. Because none of the requests are "complete" from the server's
perspective yet, the server cannot begin processing any of them. The client then releases the
withheld final bytes for all queued requests **within the same TCP packet**. The server receives
every request as functionally simultaneous, because they arrive together in one packet rather than
as a sequence of separate packets each subject to independent network-layer delay.

This is what allows 20–30 requests to be fired with effectively zero network jitter between them —
the technique only depends on TCP/IP-level packet delivery, not on the client's ability to call
multiple HTTP libraries "at the same time," which was the old and much less reliable approach.

Two important constraints:

- **Requires HTTP/2.** The single-packet attack only works against targets that support HTTP/2. If
  a target only supports HTTP/1.1, Burp Repeater automatically falls back to the older **last-byte
  synchronization** technique instead, which is similar in spirit (queue requests, release the
  final byte of each near-simultaneously) but is inherently less precise because HTTP/1.1 requires
  separate TCP connections per request.
- **Requires a single TCP connection.** All the queued requests must travel over the same
  connection so they can be released together in one packet — this is why Turbo Intruder's
  configuration explicitly sets concurrency to one connection (`concurrentConnections=1`) for this
  technique, which looks counterintuitive at first ("don't I want lots of parallel connections to
  go fast?") but is in fact the entire point: it's not about parallel connections, it's about
  synchronized release of one connection's queued requests.

## When to reach for Turbo Intruder instead of Burp Repeater's built-in grouping

Burp Repeater's native "send group in parallel" is sufficient for simple cases — identical requests
against a single endpoint. Turbo Intruder is the right tool when you need:

- A large number of requests (Repeater's grouped tabs become unwieldy past a handful).
- Per-request value substitution (e.g. firing the same race attack across a wordlist, or varying
  one parameter per request — as in the password-reset single-endpoint collision scenario).
- Staggered or multi-phase timing (e.g. connection warming requests followed by the real attack
  batch, or introducing a deliberate client-side delay to work around back-end processing-time
  mismatches in multi-endpoint races).
- Retry logic, because a single race attempt frequently doesn't land the desired interleaving on
  the first try and needs to be repeated programmatically.

## Full script breakdown: `race-single-packet-attack.py`

This is the official Turbo Intruder template for the single-packet attack technique (available in
Turbo Intruder's bundled examples directory once installed from the BApp Store). Below, every part
is broken down piece by piece — what it does mechanically, and why it's necessary for the race
window to actually form.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2
                            )

    # queue 20 requests in gate '1'
    for i in range(20):
        engine.queue(target.req, gate='1')

    # send all requests in gate '1' in parallel
    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

### `def queueRequests(target, wordlists):`

This is the entry point Turbo Intruder always calls. `target` carries the endpoint and the base
request (whatever request you sent to Turbo Intruder from Repeater/Proxy); `wordlists` would carry
any payload lists you've configured, which aren't needed for a basic limit-overrun attack since
every queued request is identical.

### `engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)`

This line constructs the request engine and is where the single-packet attack is actually selected.
Each parameter matters individually:

- **`endpoint=target.endpoint`** — tells the engine which host/port to connect to; inherited
  directly from the request you sent to Turbo Intruder.
- **`concurrentConnections=1`** — this is the critical, non-obvious setting. It forces every queued
  request onto a single shared TCP connection rather than opening one connection per request. This
  is required because the single-packet technique depends on releasing multiple requests' final
  bytes together on *one* connection's packet stream. Setting this higher would defeat the
  technique entirely by spreading requests across multiple independently-jittered connections.
- **`engine=Engine.BURP2`** — selects Burp's HTTP/2 engine implementation, which is what actually
  implements the "queue requests withholding the last byte/frame, then release together" mechanics.
  If you used `Engine.THREADED` or `Engine.BURP` instead (the engines used for normal high-volume
  fuzzing/brute-forcing), you would get regular concurrent requests over multiple connections —
  fast, but subject to full network jitter, and not a true single-packet attack. `Engine.BURP2`
  specifically requires the target to support HTTP/2; against an HTTP/1.1-only target you would
  instead use an engine/approach suited to last-byte synchronization.

### `for i in range(20): engine.queue(target.req, gate='1')`

This loop queues 20 copies of the base request. Two things are happening:

- **Why 20 (and not just 2)?** Although the underlying race condition often only strictly requires
  two requests to collide, sending a larger batch compensates for **server-side jitter** —
  unpredictable internal latency on the server itself (thread scheduling, downstream service calls,
  database connection pool contention) that the single-packet technique cannot eliminate, since it
  only solves the *network*-jitter problem, not server-internal timing variance. A bigger batch
  increases the statistical odds that at least two requests land inside the actual race window even
  if server-side processing isn't perfectly uniform. This is especially important during initial
  discovery, when you don't yet know how wide the real race window is.
- **`gate='1'`** — this is the mechanism that implements "queue but don't send yet." The `gate`
  argument tells the engine to hold each request's final byte back and associate it with a named
  group (here, `'1''`). Nothing is transmitted to the server as a result of this loop; the requests
  are only prepared and grouped client-side at this point. You can have multiple differently-named
  gates in one script if you need separate batches released at separate times (for example, a
  connection-warming gate released first, followed by the real attack gate released second — see
  the multi-endpoint timing notes below).

### `engine.openGate('1')`

This is the moment the attack actually fires. Calling `openGate` on a named gate releases the
withheld final bytes for every request queued under that gate name, in one synchronized operation,
which Burp's HTTP/2 engine packages into a single outgoing TCP packet where possible. This is the
direct software implementation of the "single packet" in "single-packet attack" — all 20 requests
become complete, valid HTTP/2 requests on the wire at effectively the same instant, which is what
creates a genuine race window collision opportunity at the server.

### `def handleResponse(req, interesting): table.add(req)`

This is Turbo Intruder's standard response handler, called once per response received. `table.add`
populates the results table in the Turbo Intruder output tab so you can review status codes,
response lengths, and timing for all 20 responses afterward. For race condition analysis
specifically, what you're looking for is: did more than one request return a "success" response
(e.g. more than one `200 OK` confirming a coupon was applied, or more than one withdrawal
confirmation) instead of exactly one success and the rest rejected. You should also check the
response **timestamps** shown in the table — a negative or near-zero gap between two responses is
itself a strong clue that the requests were processed concurrently, even before checking the
response bodies.

## Adapting the template: per-request payload substitution

For the single-endpoint password-reset collision scenario in `02`, the two queued requests are not
identical — they need different usernames. The relevant change to the loop looks like this:

```python
engine.queue(target.req, ['attacker_username'], gate='1')
engine.queue(target.req, ['victim_username'],   gate='1')
engine.openGate('1')
```

Here, the base request (`target.req`) must contain a `%s` marker at the position of the username
parameter (set by highlighting that value in Repeater before sending to Turbo Intruder). The list
passed as the second argument to `queue()` supplies the substitution value for that request. Both
requests are still queued into the same gate, so they are still released together in the same
single-packet release — only the payload content differs, not the timing mechanism.

## Working around multi-endpoint timing mismatches

When the two requests you need to race hit genuinely different endpoints (a multi-endpoint race —
see `02`), their internal server-side processing times frequently won't naturally align, even with
perfect network-level synchronization. Two documented workarounds, both implemented by adjusting
the queueing logic rather than the gate/engine setup itself:

- **Connection warming** — queue one or more inconsequential "warm-up" requests (e.g. a `GET` to
  the homepage) ahead of the real attack requests, on the same connection, to absorb backend
  connection-establishment delay before the timed requests are sent.
- **Introducing a client-side delay / abusing rate limits** — if one endpoint is inherently slower
  to process, you can either insert an explicit delay before queuing the faster endpoint's request
  (at the cost of no longer being a true single packet, since this requires splitting requests
  across separate packets), or deliberately trigger a rate-limit/resource-limit delay on the faster
  endpoint with a burst of dummy requests, so that its processing time naturally slows down to
  match the slower endpoint — preserving the ability to use the single-packet release for the
  actual attack pair.

Both techniques are about manipulating *server-side* timing to compensate for the fact that the
single-packet attack only guarantees synchronized arrival, not synchronized completion.

## Practical checklist before running an attack

1. Confirm the target negotiates HTTP/2 (check the protocol in Burp's request/response details) —
   `Engine.BURP2` will not produce a single-packet attack against an HTTP/1.1-only target.
2. Benchmark the endpoint first by sending the request group sequentially (separate connections) to
   establish a baseline response time and confirm normal (non-colliding) behavior.
3. Run the parallel batch and compare: did more than one request succeed where business logic says
   only one should have?
4. If no collision occurs on the first attempt, increase the batch size and/or re-run — race window
   alignment is probabilistic, not guaranteed on a single attempt, especially with server-side
   jitter in play.
5. Once a collision is confirmed, trim the request count down to the minimum that reliably
   reproduces it, for a clean, reviewable proof-of-concept in your report.
