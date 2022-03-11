# Deployment

## Running Edrys

To run the Edrys server, clone the code repo and launch the app bundle in
`/dist` using Deno:

```
deno run -A dist/app.js --address localhost:8000 --serve-path dist/static
```

You can also run `server/app.ts` instead if you plan on modifying the source
code.

### HTTPS development setup

It is recommended to run Edrys behind HTTPS even in development,
since many modules require it.  You can use [Caddy](https://caddyserver.com/download) to easily acheive that, for example:

```
caddy reverse-proxy --from localhost:8001 --to localhost:8000
```

This envelopes the app in an HTTPS server accessible on https://localhost:8001 (assuming your Edrys is running at http://localhost:8000).

### Updating the app

When a new version is released on GitHub, you can easily update your instance by running `git pull` and restarting your server.

## Configuration

The server accepts various configuration variables. All variables can be passed
in either via environment variables (`EDRYS_{COMMAND_NAME}`) or through command line
arguments (`--{command-name}`).

### Basics

- `address`: defines hostname and port the server will listen on, eg.
  `localhost:8000`
- `secret`: some string that will be used for as a private key behind the
  scenes. Make up a long strong password (must be specified for proper security)
- `config-class-creators-csv`: a list of emails that can create new classes
  (defaults to `*` for anyone)
- `serve-path`: file path to where static files will be served (defaults to
  `./static`)

### Email Sending

Email sending is used to send email verification messages. If not set up,
messages are simply logged to console instead. You can use any SMTP provider.
These for example include Gmail, SendGrid, Mailgun, or AWS SES.

- `smtp-tls`: true or false
- `smtp-host`: eg. smtp.example.com
- `smtp-port`: eg. 465
- `smtp-from`: email where messages will be sent from
- `smtp-username`
- `smtp-password`

### Data Storage

Edrys does not use a database, instead it stores data either directly to file or
uses an S3-compatible API.

- `data-engine`: either `file` (default) or `s3`

For file:

- `data-file-path`: the path where data will be stored. Defaults to `./.edrys`

For S3:

- `data-s3-endpoint`
- `data-s3-port`
- `data-s3-use-ssl`
- `data-s3-region`
- `data-s3-access-key`
- `data-s3-secret-key`
- `data-s3-bucket`

### Advanced

- `frontend-address`: use if the front-end is on a different address (enables
  CORS)
- `config-default-modules-json`: can be used to override the default modules in
  a newly created class
- `jwt-lifetime-days`: defines how long before users have to log-in again
  (defaults to 30)

## Running in production

While you can directly expose Edrys to your users (and this will be the goal in
the future), it is currently not recommended. There is no HTTPS or rate limiting
implemented. We recommend running Edrys behind a reverse proxy such as
[Caddy](https://caddyserver.com/docs/quick-starts/reverse-proxy) to quickly gain
these features. For example this will expose your site on `https://example.com`:

```
caddy reverse-proxy --from example.com --to localhost:8000
```

Besides self-hosting, another way to host Edrys is
[Deno Deploy](https://deno.com/deploy) (no affiliation).

Be aware that the Edrys front-end has to be served on the same host where the
API is (which is the case by default).

### Deployment guides

* [Heroku](deployment/Heroku.md)

---

➡️ Next, read about [Developing Modules](Modules.md)

⬆️ Back to [contents](README.md)
