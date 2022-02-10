import { base64, oak } from "./deps.ts";
import * as auth from "./auth.ts";

export const middleware = async (ctx: oak.Context, next: Function) => {
  /**
   * Inject identity if Auth header present
   */
  try {
    const jwt =
      ctx.request.headers?.get("Authorization")?.replace("Bearer ", "") ||
      oak.helpers.getQuery(ctx)["jwt"];

    if (!jwt) throw new Error("Unauthorized");

    const jwt_verified = (await auth.ensureJwtValid(jwt));
    ctx.state.user = jwt_verified.sub;
  } catch (_error) {
    // Unauthorized...
  }

  await next();
};

export const router = (new oak.Router())
  /**
   * Expose my public key for cross-instance auth
   * @returns JWT public key or undefined
   */
  .get("/jwtPublicKey", async (ctx) => {
    ctx.response.body = base64.encode(
      await crypto.subtle.exportKey("spki", auth.jwt_public_key),
    );
  })
  /**
   * Generate and send TOTP to an email
   * @param email Email to send token to
   */
  .get("/sendToken", async (ctx) => {
    await auth.sendToken(oak.helpers.getQuery(ctx)["email"]);
    ctx.response.body = "Sent";
  })
  /**
   * Verifies an email/token pair and generates a JWT on success
   * @param email Email to authenticate
   * @param token Token previously sent to email
   * @returns [0] indicates if this is the user's first login,
   * 					[1] is the JWT authenticating the user's identity
   * 					Or a 401 on failure
   */
  .get("/verifyToken", async (ctx) => {
    try {
      const [isNewbie, jwt] = await auth.verifyToken(
        oak.helpers.getQuery(ctx)["token"],
        oak.helpers.getQuery(ctx)["email"],
      );
      ctx.response.body = [isNewbie, jwt];
    } catch (error) {
      console.log(error);
      ctx.response.status = 401;
    }
  });
