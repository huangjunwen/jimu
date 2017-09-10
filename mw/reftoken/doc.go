// Middleware that translate tokens transparently. Can be used as session.
//
// Usage scenario: After user authentication, some user identity data is generated and encoded as a token (so called "real token") such as JWT or just plain JSON.
//
// Then set this to a header and response.
//
// When the middlware receives such header, it creates a reference (opaque) token mapping to the real one, storing them in a kv store, response the ref token in a header (or cookie) instead of the real one to the client.
//
// In the reverse direction, when the middlware receives such reference token, it translate back to the real one transparently. Thus later handler can use this header as user identity directly.
//
// Some extra benefits:
//   1. Handlers can use the same way to identify a user no matter whether the request is sent from a web page using cookie or from API request.
//   2. Logout is trivial since tokens are stored server-side.
//
// The idea is from https://www.slideshare.net/opencredo/authentication-in-microservice-systems-david-borsos2
package reftoken
