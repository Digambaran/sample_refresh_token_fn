import { shared } from "@appblocks/node-sdk";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";

const sample_refresh_token_fn = async (req, res) => {
  const accessTokenSecret = process.env.JWT_SECRET_ACCESS || "sample_shield_login_fn_access";
  const refreshTokenSecret = process.env.JWT_SECRET_REFRESH || "sample_shield_login_fn_refresh";
  const accessTokenExpiry = process.env.JWT_EXPIRY_ACCESS || 60 * 15;
  const refreshTokenExpiry = process.env.JWT_EXPIRY_REFRESH || 86400 * 7;

  const accessTokenExpiresAt = Math.floor(new Date().getTime() / 1000) + accessTokenExpiry;
  const refreshTokenExpiresAt = Math.floor(new Date().getTime() / 1000) + refreshTokenExpiry;

  const { sendResponse, redis } = await shared.getShared();
  try {
    // health check
    if (req.params["health"] === "health") {
      sendResponse(res, 200, { success: true, msg: "Health check success" });
      return;
    }

    const [_bearer, _accessToken, refreshToken] = req.headers.authorization.split(" ");

    const decoded = jwt.verify(refreshToken, refreshTokenSecret, { token_type: "refresh" });
    console.log(`decoded:${decoded}`);

    const { token_id, pair_id, sub } = decoded;

    const ok = await redis.get(`${token_id}:${sub}`);
    if (!ok) {
      const err = new Error("Refresh token expired or invalidated");
      err.name = "jsonWebTokenExpiredorInvalid";
      throw err;
    }
    console.log("refresh token valid");

    console.log("initiating redis transaction");
    const [refreshTokenDeleted, _accessTokenDeleted] = await redis
      .multi()
      .del(`${token_id}:${sub}`)
      .del(`${pair_id}:${sub}`)
      .exec();
    if (!refreshTokenDeleted) {
      const err = new Error("error removing refresh token from redis ");
      err.name = "redisError";
      throw err;
    }

    console.log("refresh token removed from redis");

    const { access, refresh } = generateTokens(sub, {
      access: { secret: accessTokenSecret, expiry: accessTokenExpiry },
      refresh: { secret: refreshTokenSecret, expiry: refreshTokenExpiry },
    });

    const [accessTokenSet, refreshTokenSet] = await redis
      .multi()
      .set(`${access.id}:${sub}`, "ok", {
        EX: accessTokenExpiry,
      })
      .set(`${refresh.id}:${sub}`, "ok", {
        EX: refreshTokenExpiry,
      })
      .exec();

    if (!accessTokenSet || !refreshTokenSet) {
      const err = new Error("error adding new tokens to redis");
      err.name = "redisError";
      throw err;
    }

    console.log("new tokens generated");

    sendResponse(res, 200, {
      err: false,
      msg: "",
      data: {
        token: access.token,
        refreshtoken: refresh.token,
        expiresAt: accessTokenExpiresAt,
      },
    });
    return;
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      console.log(`${err.name}:${err.message}`);
      sendResponse(res, 403, { err: true, msg: "Access Denied", data: {} });
      return;
    }
    if (err.name === "jsonWebTokenExpiredorInvalid") {
      console.log(`${err.name}:${err.message}`);
      sendResponse(res, 403, { err: true, msg: "Access Denied", data: {} });
      return;
    }
    console.log(`${err.name}:${err.message}`);
    sendResponse(res, 500, { err: true, msg: "server error", data: {} });
    return;
  }
};

/**
 * @typedef o
 * @property {string} secret
 * @property {string} expiry
 */
/**
 *
 * @param {string} sub
 * @param {{access:o,refresh:o} param1
 * @returns
 */
const generateTokens = (sub, { access, refresh }) => {
  const accesstokenid = nanoid();
  const refreshtokenid = nanoid();

  const token = jwt.sign(
    {
      iss: "sample-shield-node",
      sub,
      token_id: accesstokenid,
      pair_id: refreshtokenid,
      token_type: "access",
    },
    access.secret,
    { algorithm: "HS256", expiresIn: access.expiry }
  );
  const refreshtoken = jwt.sign(
    {
      iss: "sample-shield-node",
      sub,
      token_id: refreshtokenid,
      pair_id: accesstokenid,
      token_type: "refresh",
    },
    refresh.secret,
    { algorithm: "HS256", expiresIn: refresh.expiry }
  );

  return { access: { id: accesstokenid, token }, refresh: { id: refreshtokenid, token: refreshtoken } };
};

export default sample_refresh_token_fn;
