import type { RouterContext } from "../deps.ts";
import { users } from "./auth.controller.ts";

const getMeController = ({ state, response }: RouterContext<string>) => {
  try {
    const user = users.find((user) => user.id === state.user_id);

    response.status = 200;
    response.body = {
      status: "success",
      user,
    };
  } catch (error) {
    response.status = 500;
    response.body = {
      status: "success",
      message: error.message,
    };
    return;
  }
};

export default { getMeController };
