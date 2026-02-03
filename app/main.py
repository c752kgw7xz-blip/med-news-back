from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Med Newsletter API", version="0.1.0")

# Dev: autorise tous les sites Netlify (on resserrera après)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https://.*\.netlify\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "Med Newsletter API", "version": app.version}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/version")
def version():
    return {"version": app.version}
