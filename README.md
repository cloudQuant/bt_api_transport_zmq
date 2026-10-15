# bt_api_transport_zmq

`bt_api_transport_zmq` is a provider-neutral transport boundary. It owns a
small versioned JSON wire format, ZeroMQ socket safety, bounded buffering,
message sequencing, and authenticated server-side command delivery. It does
not own order state, risk state, provider execution policy, or retry policy.

An application supplies a local/server authenticator and a command handler.
The handler normally delegates to `bt_api_gateway`; a client payload cannot
grant itself an account or strategy scope. The client raises
`CommandOutcomeUnknown` on timeout and never automatically resends a write
command. Reconciliation is a separate request.

Remote TCP use requires CurveZMQ server credentials and an explicit client
public-key ACL. The server runs ZAP authentication, takes peer identity from
the authenticated Curve `User-Id` metadata (not the client-chosen ROUTER
identity), then checks the server-configured principal's exact scope and
command-kind ACL before calling the handler. Account and strategy identity or
scope claims in the envelope or nested payload must match the same immutable
grant. Unencrypted local loopback, IPC, and inproc endpoints remain available
for offline/integration use with an injected authenticator. Messages reject
secret-shaped keys and non-finite JSON values before they enter a queue or
durable journal.

## Market PUB/SUB wire versions

The market transport keeps wire version 1 as the default: the publisher sends
one encoded envelope frame and each authorized subscriber receives every
market key on that audience endpoint. Wire version 2 is an explicit opt-in for
one-key subscribers. The publisher sends two frames: a binary topic containing
the complete `MarketSubscriptionKey.stream_id`, followed by the unchanged
encoded envelope. The subscriber installs a ZeroMQ prefix filter for that full
topic, then verifies the exact topic, envelope, stream ID, payload key, peer,
and scope.

Both ends must agree on the wire version through the trusted deployment or
market-subscription capability contract before opening the stream. Mixed
versions do not fall back: a v1 subscriber drops v2 multipart messages, and a
v2 subscriber does not match v1 envelope frames. The SDK/control plane must
reject a mismatch rather than report an empty stream as a successful
subscription. Topic filtering reduces delivery work; it is not authorization.
CURVE authentication and the publisher's finite principal ACL remain required
for both versions. High-water marks and envelope size limits apply in either
version.
