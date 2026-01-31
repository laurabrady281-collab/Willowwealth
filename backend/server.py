import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Willowwealth Backend")

# Keep CORS permissive for preview environments
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    """Basic health check used by the preview environment."""
    mongo_url_present = bool(os.environ.get("MONGO_URL"))
    return {"ok": True, "mongo_url_present": mongo_url_present}
