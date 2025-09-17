from fastapi import FastAPI, Request, HTTPException
from jwt import PyJWKClient, decode as jwt_decode, InvalidTokenError

JWKS_URL = "https://hello.localhost.pomerium.io/.well-known/pomerium/jwks.json"
AUD = "https://hello.localhost.pomerium.io"
ISS = "https://authenticate.localhost.pomerium.io"

jwks_client = PyJWKClient(JWKS_URL)
app = FastAPI()

@app.get("/hello")
def hello(req: Request):
    token = req.headers.get("X-Pomerium-Jwt-Assertion")
    if not token:
        raise HTTPException(401, "missing assertion")

    try:
        key = jwks_client.get_signing_key_from_jwt(token).ey
        claims = jwt_decode(token, key, algorithms=["ES256","RS256"], audience=AUD, issuer=ISS)
    except InvalidTokenError as e:
        raise HTTPException(401, f"invalid assertion: {e}")

    return {"email": claims.get("email"), "user": claims.get("user"), "groups": claims.get("groups", [])}