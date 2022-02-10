# Deployment

## Running Edrys

To run the Edrys server, clone the code repo and launch the app bundle in
`/dist` using Deno:

```
deno run -A dist/app.js --address localhost:8000 --secret makeUpSomeSecretTextHere
```

You can also run `server/app.ts` instead if you plan on modifying the source
code.

## Configuration

The server accepts various configuration variables. All variables can be passed
in either via environment variables (`EDRYS_{NAME}`) or through command line
arguments (`--{name}`).

### Basics

- `address`: defines hostname and port the server will listen on, eg.
  `localhost:8000`
- `secret`: some string that will be used for as a private key behind the
  scenes. Make up a long strong password
- `config_class_creators_csv`: a list of emails that can create new classes
  (defaults to `*` for anyone)

### Email Sending

Email sending is used to send email verification messages. If not set up,
messages are simply logged to console instead. You can use any SMTP provider.
These for example include Gmail, SendGrid, Mailgun, or AWS SES.

- `smtp_tls`: true or false
- `smtp_host`: eg. smtp.example.com
- `smtp_port`: eg. 465
- `smtp_from`: email where messages will be sent from
- `smtp_username`
- `smtp_password`

### Data Storage

Edrys does not use a database, instead it stores data either directly to file or
uses an S3-compatible API.

- `data_engine`: either `file` (default) or `s3`

For file:

- `data_file_path`: the path where data will be stored. Defaults to `./.edrys`

For S3:

- `data_s3_endpoint`
- `data_s3_port`
- `data_s3_use_ssl`
- `data_s3_region`
- `data_s3_access_key`
- `data_s3_secret_key`
- `data_s3_bucket`

### Advanced

- `frontend_address`: use if the front-end is on a different address (enables
  CORS)
- `frontend_path`: file path to where static files will be served (defaults to
  `./static`)
- `config_default_modules_json`: can be used to override the default modules in
  a newly created class
- `jwt_lifetime_days`: defines how long before users have to log-in again
  (defaults to 30)

## Running in production

While you can directly expose Edrys to your users (and this will be the goal in
the future), it is currently not recommended. There is no HTTPS or rate limiting
implemented. We recommend running Edrys behind a reverse proxy such as
[Caddy](https://caddyserver.com/docs/quick-starts/reverse-proxy) to quickly gain
these features.

Besides self-hosting, an easy way to host Edrys is
[Deno Deploy](https://deno.com/deploy) (no affiliation).

Be aware that the Edrys front-end has to be served on the same host where the
API is (which is the case by default).
