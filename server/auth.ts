import { djwt, otpauth, SMTPClient } from "./deps.ts";
import * as env from "./env.ts";
import * as data from "./data.ts";
import { base64 } from "./deps.ts";

export let ready = false;
export let smtpClient: SMTPClient | any;
export let jwt_public_key: any;
let jwt_private_key: any;

/**
 * Init SMTP
 */
if (
  env.smtp_hostname == "" ||
  env.smtp_port == 0 ||
  env.smtp_username == "" ||
  env.smtp_password == "" ||
  env.smtp_from == ""
) {
  smtpClient = {
    send: async function (params: any) {
      await (new Promise((resolve) => setTimeout(resolve, 1000)));
      console.log("Email sent", params);
    },
  };
} else {
  smtpClient = new SMTPClient({
    connection: {
      hostname: env.smtp_hostname,
      port: env.smtp_port,
      tls: env.smtp_tls,
      auth: {
        username: env.smtp_username,
        password: env.smtp_password,
      },
    },
  });
}

/**
 * Init JWT keys
 */
if (env.jwt_keys_path) {
  /**
   * If a key pair is provided, use public key scheme
   */
  jwt_private_key = await crypto.subtle.importKey(
    "pkcs8",
    base64.decode(
      await Deno.readTextFile(`${env.jwt_keys_path}/jwt_private_key`),
    ),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-512",
    },
    true,
    ["sign"],
  );
  jwt_public_key = await crypto.subtle.importKey(
    "spki",
    base64.decode(
      await Deno.readTextFile(`${env.jwt_keys_path}/jwt_public_key`),
    ),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-512",
    },
    true,
    ["verify"],
  );
} else {
  /**
   * Use HMAC if only a public key is provided
   */
  jwt_private_key = await crypto.subtle.importKey(
    "raw",
    (new TextEncoder()).encode(env.secret),
    { name: "HMAC", hash: "SHA-512" },
    true,
    ["sign", "verify"],
  );
}

ready = true;

/**
 * Graceful shutdown
 */
export async function teardown() {
  await smtpClient.close();
  ready = false;
}

/**
 * Send a new TOTP token to email
 * @param email Email to send token to
 * @returns Nothing
 */
export async function sendToken(email: string): Promise<void> {
  ensureEmailValid(email);

  const token = getTotp(email).generate();

  await smtpClient.send({
    from: env.smtp_from,
    to: email,
    subject: "Your Edrys secret code",
    content: `Use this secret code in the Edrys app: ${token}`,
    html: `Use this secret code in the Edrys app: <em>${token}</em>`,
  });
}

/**
 * Given an email and token, validate the token was issued for that email
 * from this app and has not expired, and if so return a JWT
 * @param token Token sent to email
 * @param email Email token sent to!
 * @returns [boolean indicating if user is new, signed JWT proving user's identity]
 */
export async function verifyToken(
  token: string,
  email: string,
): Promise<[boolean, string]> {
  ensureEmailValid(email);
  ensureTokenValid(token, email);

  return [
    await ensureUserExists(email),
    await djwt.create(
      { alg: jwt_public_key ? "RS512" : "HS512", typ: "JWT" },
      {
        sub: normaliseEmail(email),
        iat: new Date().getTime(),
        exp: (new Date()).setDate(
          (new Date()).getDate() + env.jwt_lifetime_days,
        ),
      },
      jwt_private_key,
    ),
  ];
}
/**
 * Create account for user in database if it doesn't exist
 * @param email User email (also ID, so will be lower case)
 * @returns If user is new (account did not exist before)
 */
async function ensureUserExists(email: string): Promise<boolean> {
  if (!data.ready) {
    throw new Error(
      `Error ensuring user exists, data module not ready (${email})`,
    );
  }
  try {
    await data.read("users", email);
    return false;
  } catch (_error) {
    // User doesn't exist yet
    let displayName = email.trim().split("@")[0].replaceAll(/[^A-Za-z ]+/g, " ")
      .slice(0, 99);
    displayName = displayName.length <= 1 ? "New User" : displayName;
    await data.write("users", normaliseEmail(email), {
      email: normaliseEmail(email),
      displayName: displayName,
      dateCreated: new Date().getTime(),
      memberships: [],
    } as data.User);
    return true;
  }
}

/**
 * Throws an exception if provided token/email combination is invalid
 * @param token Token sent to email
 * @param email Email recepient of token
 */
function ensureTokenValid(token: string, email: string): void {
  const res = getTotp(email).validate({
    token: token,
    window: 2,
  });
  if (res == null || res < -1) {
    throw new Error(`Invalid token ${email} ${token}`);
  }
}

/**
 * Generates a new TOTP for a given email
 * @param email Email recepient of token
 * @returns TOTP code
 */
function getTotp(email: string): otpauth.TOTP {
  return new otpauth.TOTP({
    issuer: "App",
    label: "EmailToken",
    algorithm: "SHA3-256",
    digits: 6,
    period: 30, // seconds
    secret: otpauth.Secret.fromUTF8(env.secret + email),
  });
}

/**
 * Throws an exception if provided email is invalid
 * @param email Email to test
 */
function ensureEmailValid(email: string): void {
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    throw new Error(`Invalid email ${email}`);
  }
}

/**
 * Throws an exception or returns false if provided JWT is invalid
 * @param jwt JWT to test
 * @returns True if valid
 */
export async function ensureJwtValid(jwt: string) {
  try {
    return await djwt.verify(jwt, jwt_public_key ?? jwt_private_key);
  } catch (_error) {
    throw new Error(`JWT signiture validation error ${jwt}`);
  }
}

/**
 * Helper to normalise an email
 * @param email Email (assuemd to be valid)
 * @returns Normalised email
 */
function normaliseEmail(email: string): string {
  return email.trim().toLowerCase();
}
