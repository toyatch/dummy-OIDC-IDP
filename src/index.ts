import express from "express"
import { auth, requiresAuth  } from 'express-openid-connect';

import { assignIDPRoutes } from "./IDPController"

const ORIGIN = 'http://localhost:3000';
const ISSUER = 'http://localhost:3000/IDP'; // IDPのURLを指定
const CLIENT_ID = 'dummy-client-id'

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// CLIENT部分
app.use(auth({
  issuerBaseURL: ISSUER,
  clientID: CLIENT_ID,
  secret: 'a-very-secret-session-key',
  clientSecret: 'dummy-client-secret',
  baseURL: `http://localhost:${port}`,
  authRequired: false,
  idTokenSigningAlg: 'ES256',
  authorizationParams: {
    response_type: 'code',
    scope: 'openid'
  }
}));
app.get('/', requiresAuth (), (req, res) => {
  const {sub, email, name} = req.oidc?.user ?? {};
  res.send(`Hello { sub: "${sub}", email: "${email}", name: "${name}" }`);
});

// IDP部分
assignIDPRoutes(app, {
  origin: ORIGIN,
  path: "IDP",
  client_id: CLIENT_ID,
});

// サーバー起動
const main = async ()=>{
  app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
  });
};
void main()

