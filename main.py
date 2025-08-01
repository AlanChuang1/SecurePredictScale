from fastapi import FastAPI, Request, HTTPException, Depends
import jwt, os
import uvicorn
from auth.rbac import authorize, create_token
from inference import is_anomaly, extract_features

app = FastAPI()

@app.post("/scale")
async def scale(req: Request, auth=Depends(authorize)):
    payload = await req.json()
    try:
        feature_vector = extract_features(payload)
        decision = "scale-up" if is_anomaly(feature_vector) else "no-scale"
        return {"decision": decision}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {e}")

@app.post("/train")
async def train(req: Request, auth=Depends(authorize)):
    return {"status": "training triggered (placeholder)"}

@app.post("/predict")
async def predict_endpoint(req: Request, auth=Depends(authorize)):
    payload = await req.json()
    try:
        output = predict(payload)
        return {"prediction": output}
    except ValueError as ve:
        raise HTTPException(status_code=403, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference failed: {e}")

@app.get("/logs")
async def logs(req: Request, auth=Depends(authorize)):
    return {"logs": ["Anomaly at T1", "Anomaly at T2"]}

@app.get("/token/{role}")
def gen_token(role: str):
    return {"token": create_token(role)}

@app.get("/whoami")
def whoami(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): return {"role": None}
    token = auth.split()[1]
    try:
        role = jwt.decode(token, os.getenv("JWT_SECRET", "supersecret"), algorithms=["HS256"]).get("role")
        return {"role": role}
    except:
        return {"role": "invalid"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)