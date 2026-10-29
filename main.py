import os
import random
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="AegisNet Engine Cloud", version="2.0.0")

# Permitir peticiones desde cualquier origen (PC, Celular, Web, Extensión)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PostEvent(BaseModel):
    user_id: str
    post_id: str
    content: str
    timestamp: float = 0.0
    ip_address: str
    target_user_id: str

@app.get("/")
def read_root():
    return {"status": "AegisNet Engine Cloud Running", "health": "OK"}

@app.post("/api/v1/analyze-event")
async def analyze_event(event: PostEvent):
    try:
        content_lower = event.content.lower()
        is_suspicious = any(word in content_lower for word in ["urgente", "falsa", "masivamente", "compartir", "fraude", "troll", "bot"])
        
        risk_score = 0.85 if is_suspicious else round(random.uniform(0.05, 0.35), 2)
        
        if risk_score >= 0.7:
            enforced_action = "BLOCK_IP_AND_SHADOWBAN"
        elif risk_score >= 0.5:
            enforced_action = "REQUIRE_CAPTCHA"
        else:
            enforced_action = "ALLOW"

        return {
            "user_id": event.user_id,
            "post_id": event.post_id,
            "risk_score": risk_score,
            "enforced_action": enforced_action,
            "status": "success"
        }
    except Exception as e:
        return {
            "user_id": event.user_id,
            "post_id": event.post_id,
            "risk_score": 0.1,
            "enforced_action": "ALLOW",
            "status": "fallback_mode",
            "error_detail": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)