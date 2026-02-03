from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Med Newsletter API", version="0.1.0")

# CORS: autorise les sites Netlify
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En prod, remplacez par votre URL Netlify exacte
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
