from fastapi import FastAPI

app = FastAPI(title="Med Newsletter API", version="0.1.0")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/version")
def version():
    return {"version": app.version}
