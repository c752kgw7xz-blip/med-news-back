from fastapi import FastAPI

app = FastAPI(title="Med Newsletter API", version="0.1.0")

@app.get("/")
def root():
    return {"message": "Med Newsletter API", "version": app.version}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/version")
def version():
    return {"version": app.version}