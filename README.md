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
