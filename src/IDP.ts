import express, { Request, Response, Router } from "express"
import { importPKCS8, SignJWT, exportJWK } from 'jose';
import { generateKeyPairSync, createPublicKey } from 'crypto'

const createCodeStore = ()=> {
  const table: Record<string, { name: string, nonce: string }> = {}

  return {
    register: (name: string, nonce: string): string => {
      const code = `dummy-auth-code-${name}`
      table[code] = {
        name, nonce
      }
      return `dummy-auth-code-${name}`
    },
    read: (code: string): { name: string, nonce: string } => {
      const data = table[code];
      return data
    }
  }
}

export const createIDP = (
  params: {
    issuer: string,
    client_id: string,
  },
): Router => {
  const {
    issuer: ISSUER,
    client_id: CLIENT_ID
  } = params

  const router = Router();
  router.use(express.urlencoded({ extended: false }));

  const JWT_KEY_ID = "my-key-id"

  const { privateKey: privateKeyPEM, publicKey: publicKeyPEM } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  const store = createCodeStore()

  router.get(`/.well-known/openid-configuration`, async (_req: Request, res: Response)=>{
    res.json({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: `${ISSUER}/jwks`,

      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      id_token_signing_alg_values_supported: ['ES256'],
      subject_types_supported: ['public'],
      scopes_supported: ['openid'],
      token_endpoint_auth_methods_supported: ['client_secret_post'],
    });
  });

  router.get(`/authorize`, async (req: Request, res: Response)=>{
    const { redirect_uri, state, nonce } = req.query;

    if (typeof redirect_uri !== 'string') {
      res.status(400).send('No redirect_uri');
      return;
    }

    res.send(`
      <form method="POST" action="login">
        <label>ユーザー名: <input name="username" /></label><br />
        <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
        <input type="hidden" name="state" value="${state ?? ''}" />
        <input type="hidden" name="nonce" value="${nonce ?? ''}" />
        <button type="submit">ログイン</button>
      </form>
    `);
  });

  router.post(`/login`, async (req: Request, res: Response)=>{
    const { redirect_uri, state, nonce, username } = req.body;

    const code = store.register(username, nonce)

    const url = new URL(redirect_uri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state as string);
    res.redirect(url.toString())
  });

  router.get(`/jwks`, async (_req: Request, res: Response)=>{
    const keyObject = createPublicKey(publicKeyPEM);
    const publicJwk = await exportJWK(keyObject);
    publicJwk.kid = JWT_KEY_ID;
    publicJwk.use = "sig";
    publicJwk.alg = "ES256";

    res.json({ keys: [publicJwk]});
  });

  router.post(`/token`, async (req: Request, res: Response)=>{
    const { code } = req.body ?? {}
    const { name, nonce } = store.read(code)

    const privateKey = await importPKCS8(privateKeyPEM, 'ES256');
    const id_token = await new SignJWT({
      sub: name,
      name: name,
      email: name,
      nonce,
      aud: CLIENT_ID
    }).setProtectedHeader({ alg: 'ES256', kid: JWT_KEY_ID })
      .setIssuer(ISSUER)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    res.json({
      access_token: 'dummy-access-token',
      id_token,
      token_type: 'Bearer',
      expires_in: 300
    });
  });

  return router
}
