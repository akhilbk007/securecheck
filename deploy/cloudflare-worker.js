// Serves SecureCheck at https://akhilkulal.in/project/securecheck/ by forwarding
// requests under that path to the hosted scanner. Because the browser only
// ever talks to akhilkulal.in, no CORS configuration is needed.
//
// Setup (Cloudflare dashboard):
//   1. Workers & Pages > Create > Worker, paste this file, set ORIGIN below, deploy.
//   2. Worker > Settings > Domains & Routes > Add route:
//        akhilkulal.in/project/securecheck*
const ORIGIN = "https://YOUR-APP.onrender.com"; // where the scanner is hosted
const PREFIX = "/project/securecheck";

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Relative links in the page need the trailing slash.
    if (url.pathname === PREFIX) {
      return Response.redirect(url.origin + PREFIX + "/" + url.search, 301);
    }
    if (!url.pathname.startsWith(PREFIX + "/")) {
      return new Response("Not found", { status: 404 });
    }

    const target = new URL(url.pathname.slice(PREFIX.length) + url.search, ORIGIN);
    const headers = new Headers(request.headers);
    // Pass the real visitor address on so per-visitor rate limiting works.
    headers.set("X-Forwarded-For", request.headers.get("CF-Connecting-IP") || "");

    return fetch(target, {
      method: request.method,
      headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
      redirect: "manual",
    });
  },
};
