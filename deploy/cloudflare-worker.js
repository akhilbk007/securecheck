// Serves SecureCheck at https://akhilkulal.in/project/securecheck/ by forwarding
// requests under that path to the hosted scanner. Because the browser only
// ever talks to akhilkulal.in, no CORS configuration is needed.
//
// Setup (Cloudflare dashboard):
//   1. Workers & Pages > Create application > Hello World, paste this file, deploy.
//   2. Settings > Domains & Routes > Add > Route: akhilkulal.in/project/securecheck*
//   3. Settings > Trigger Events > Add > Cron Trigger: */10 * * * *
//      (keeps the free Render service from going to sleep)
const ORIGIN = "https://securecheck-1ldi.onrender.com"; // where the scanner is hosted
const PREFIX = "/project/securecheck";

const WAKING_PAGE = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="8">
<title>SecureCheck is starting</title>
<style>body{margin:0;min-height:100vh;display:grid;place-content:center;text-align:center;
background:#e6ecf1;color:#0f2438;font-family:system-ui,sans-serif;padding:2rem}
h1{font-size:1.75rem;margin:0 0 .5rem}p{margin:0;color:#4b5f72}</style></head>
<body><h1>SecureCheck is starting up</h1>
<p>The scanner was asleep. This page reloads by itself in a few seconds.</p></body></html>`;

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

    const response = await fetch(target, {
      method: request.method,
      headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
      redirect: "manual",
    });

    // The free host answers 502/503 while it wakes up. Show a page that
    // reloads itself instead of a bare error.
    const wantsPage = request.method === "GET" &&
      (request.headers.get("Accept") || "").includes("text/html");
    if ((response.status === 502 || response.status === 503) && wantsPage) {
      return new Response(WAKING_PAGE, {
        status: 503,
        headers: { "Content-Type": "text/html; charset=utf-8", "Retry-After": "8", "Cache-Control": "no-store" },
      });
    }
    return response;
  },

  // Runs on the Cron Trigger: a small request that keeps the scanner awake.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(fetch(ORIGIN + "/api/health"));
  },
};
