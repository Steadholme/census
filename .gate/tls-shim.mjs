import fs from "node:fs";
import http from "node:http";
import https from "node:https";

const listenHost = "127.0.0.1";
const listenPort = 8443;
const upstreamHost = "127.0.0.1";
const upstreamPort = 9131;
const certPath = process.env.CENSUS_TLS_CERT;
const keyPath = process.env.CENSUS_TLS_KEY;

if (!certPath || !keyPath) {
  throw new Error("CENSUS_TLS_CERT and CENSUS_TLS_KEY are required");
}

const server = https.createServer(
  { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) },
  (request, response) => {
    const headers = { ...request.headers };
    headers.host = `${upstreamHost}:${upstreamPort}`;
    headers["x-forwarded-proto"] = "https";

    const upstream = http.request(
      {
        host: upstreamHost,
        port: upstreamPort,
        method: request.method,
        path: request.url,
        headers,
      },
      (upstreamResponse) => {
        response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(response);
      },
    );

    upstream.setTimeout(9_000, () => upstream.destroy(new Error("upstream timeout")));
    upstream.on("error", () => {
      if (!response.headersSent) {
        response.writeHead(502, {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
        });
      }
      response.end("fixture unavailable\n");
    });
    request.pipe(upstream);
  },
);

server.on("clientError", (_error, socket) => {
  socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
});

const shutdown = () => server.close(() => process.exit(0));
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

server.listen(listenPort, listenHost, () => {
  process.stdout.write(`census TLS shim ready on https://${listenHost}:${listenPort}\n`);
});
