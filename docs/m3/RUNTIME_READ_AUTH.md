# Runtime read authentication

When the management API has an API token or account authentication configured,
the M3 inspection, security-event, session and runtime-event read endpoints
require an authenticated VIEWER, OPERATOR or ADMIN. Anonymous requests and
invalid/expired/logged-out tokens receive HTTP 401 before the engine is queried.
Existing configuration mutations still require ADMIN; VIEWER remains read-only.
The public health endpoint and legacy configuration read contract are unchanged.

`/ws/events` and `/ws/stats` apply the same authentication before upgrading.
Non-browser clients can use the Authorization header. The browser console sends
`ngfw.v1` and `ngfw.auth.<base64url UTF-8 token>` in Sec-WebSocket-Protocol because
the native WebSocket constructor cannot set Authorization. Only `ngfw.v1` is
selected in the response; credentials are not put in the URL or reflected as the
selected protocol. Malformed and multiple credential protocols are rejected.
The console reopens its sockets when its token changes and does not dial while
no token is set. Production access should use a TLS-protected management channel.

Embedded test APIs without either authentication mechanism retain their
existing unauthenticated behavior. This is not an anonymous-read exception for
an appliance configured with a token.

Regressions exercise anonymous/invalid credentials, all three roles, configuration
write denial, logout, WebSocket authentication before upgrade, ambiguous
credentials and the selected protocol. The browser transport test round-trips
credentials including UTF-8 and characters unsafe in a raw protocol token.

This change also retains the existing profile-aware Candidate compiler, so
building the API from the published source accepts valid M3/M4 Candidates
consistently with the authoritative engine.
