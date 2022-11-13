import { users } from "../controllers/auth.controller.ts";
import type { Context } from "../deps.ts";
import { verifyJwt } from "../utils/jwt.ts";

const requireUser = async (ctx: Context, next: () => Promise<unknown>) => {
  try {
    const headers: Headers = ctx.request.headers;
    const authorization = headers.get("Authorization");
    const cookieToken = await ctx.cookies.get("access_token");
    let access_token;

    if (authorization) {
      access_token = authorization.split(" ")[1];
    } else if (cookieToken) {
      access_token = cookieToken;
    }

    if (!access_token) {
      ctx.response.status = 401;
      ctx.response.body = {
        status: "fail",
        message: "You are not logged in",
      };
      return;
    }

    const decoded = await verifyJwt<{ sub: string }>({
      token: access_token,
      publicKeyPem: "ACCESS_TOKEN_PUBLIC_KEY",
    });

    const message = "Token is invalid or session has expired";

    if (!decoded) {
      ctx.response.status = 401;
      ctx.response.body = {
        status: "fail",
        message,
      };
      return;
    }

    const user = users.find((user) => user.id === decoded.sub);
    if (!user) {
      ctx.response.status = 401;
      ctx.response.body = {
        status: "fail",
        message,
      };
      return;
    }

    ctx.state["user_id"] = user.id;
    await next();
    delete ctx.state.user_id;
  } catch (error) {
    ctx.response.status = 500;
    ctx.response.body = {
      status: "fail",
      message: error.message,
    };
  }
};

export default requireUser;
