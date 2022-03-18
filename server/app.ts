import { log, oak } from "./deps.ts";
import * as auth_web from "./auth_web.ts";
import * as data_web from "./data_web.ts";
import * as env from "./env.ts";


const app = new oak.Application();

/**
 * Bypass CORS if frontend_address specified
 */
if (env.frontend_address) {
  app.use((ctx, next) => {
    ctx.response.headers.set(
      "Access-Control-Allow-Origin",
      env.frontend_address,
    );
    ctx.response.headers.set("Access-Control-Allow-Credential", "true");
    ctx.response.headers.set(
      "Access-Control-Allow-Methods",
      "GET,HEAD,OPTIONS",
    );
    ctx.response.headers.set(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept, Authorization",
    );
    return next();
  });
}

/**
 * Basic logging
 */
app.use(async (ctx, next) => {
  await next();
  log.info(
    `${new Date().toISOString()} ${ctx.request.method} ${ctx.request.url}`,
  );
});

await log.setup({
  handlers: {
      console: new log.handlers.ConsoleHandler("DEBUG", {
          formatter: "{levelName} {datetime} {msg}"
      }),
  },
  loggers: {
      default: {
          level: env.log_level as log.LevelName,
          handlers: ["console"],
      }
  },
});

/**
 * Route /ping
 */
const ping_router = new oak.Router();
ping_router
  .get("/ping", (ctx) => {
    ctx.response.body = env.address;
  });
app.use(ping_router.routes());
app.use(ping_router.allowedMethods());

/**
 * Route /auth
 */
const auth_router = (new oak.Router()).use(
  "/auth",
  auth_web.router.routes(),
  auth_web.router.allowedMethods(),
);
app.use(auth_router.routes());
app.use(auth_router.allowedMethods());
app.use(auth_web.middleware);

/**
 * Route /data
 */
const data_router = (new oak.Router()).use(
  "/data",
  data_web.router.routes(),
  data_web.router.allowedMethods(),
);
app.use(data_router.routes());
app.use(data_router.allowedMethods());

/**
 * Serve frontend at /
 */
app.use(async (context, next) => {
  try {
    await context.send({
      root: env.serve_path,
      index: "index.html",
    });
  } catch {
    next();
  }
});

/**
 * Start listening
 */
const hostname = env.address.split(":")[0];
const port = env.address.split(":")[1];
log.info(`Listening on ${hostname}:${port}`);
await app.listen({
  hostname: hostname,
  port: Number(port),
  alpnProtocols: ["h2"],
	/**
	 * WIP: Auto-SSL
	 */
  // secure: true,
  // certFile: env.https_cert_file,
  // keyFile: env.https_key_file
});
