import { getNumericDate, create, verify, dotenvConfig } from "../deps.ts";
import type { Payload, Header } from "../deps.ts";
import { convertToCryptoKey } from "./convertCryptoKey.ts";
dotenvConfig({ export: true, path: ".env", safe: true });

export const signJwt = async ({
  user_id,
  issuer,
  privateKeyPem,
  expiresIn,
}: {
  user_id: string;
  issuer: string;
  privateKeyPem: "ACCESS_TOKEN_PRIVATE_KEY" | "REFRESH_TOKEN_PRIVATE_KEY";
  expiresIn: Date;
}) => {
  const header: Header = {
    alg: "RS256",
    typ: "JWT",
  };

  const nowInSeconds = Math.floor(Date.now() / 1000);
  const tokenExpiresIn = getNumericDate(expiresIn);

  const payload: Payload = {
    iss: issuer,
    iat: nowInSeconds,
    exp: tokenExpiresIn,
    sub: user_id,
  };

  const crytoPrivateKey = await convertToCryptoKey({
    pemKey: atob(Deno.env.get(privateKeyPem) as unknown as string),
    type: "PRIVATE",
  });

  const token = await create(header, payload, crytoPrivateKey!);

  return { token };
};

export const verifyJwt = async <T>({
  token,
  publicKeyPem,
}: {
  token: string;
  publicKeyPem: "ACCESS_TOKEN_PUBLIC_KEY" | "REFRESH_TOKEN_PUBLIC_KEY";
}): Promise<T | null> => {
  try {
    const crytoPublicKey = await convertToCryptoKey({
      pemKey: atob(Deno.env.get(publicKeyPem) as unknown as string),
      type: "PUBLIC",
    });

    return (await verify(token, crytoPublicKey!)) as T;
  } catch (error) {
    console.log(error);
    return null;
  }
};
