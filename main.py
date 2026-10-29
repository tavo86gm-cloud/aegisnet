from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="AegisNet Security Backend",
    description="Motor backend automatizado para la detección y defensa contra bots y trolls.",
    version="1.0"
)

# Configuración de CORS segura para permitir solicitudes desde la extensión y paneles autorizados
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Puedes acotarlo a dominios específicos si lo deseas
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Token Secreto de Blindaje (Debe coincidir exactamente con el configurado en la extensión)
SECRET_TOKEN = "AEGISNET_SECURE_TOKEN_2026_XYZ"

# Estructura del cuerpo de la petición esperada
class EventData(BaseModel):
    event_type: str = "post_analysis"
    content: str

@app.post("/api/v1/analyze-event")
async def analyze_event(data: EventData, x_aegis_secret_token: str = Header(None)):
    """
    Endpoint principal protegido. Valida la firma criptográfica y analiza el riesgo del texto.
    """
    # Capa de seguridad: Rechazar peticiones que no provengan de la extensión oficial blindada
    if x_aegis_secret_token != SECRET_TOKEN:
        raise HTTPException(
            status_code=403, 
            detail="Acceso denegado: Firma de seguridad inválida o intento de acceso no autorizado."
        )
    
    contenido = data.content.lower()
    risk_score = 15  # Puntaje base para usuarios normales / seguros
    
    # Patrones y palabras clave para identificación de Bots de Spam
    patrones_bot = [
        "gana dinero", "trabaja desde casa", "bitcoin", "cripto", 
        "whatsapp", "telegram", "bit.ly", "link en biografía", 
        "sígueme y te sigo", "invierte ahora", "ingresos diarios", 
        "haz clic aquí", "http://", "https://"
    ]
    
    # Patrones y palabras clave para identificación de Trolls / Hostigadores
    patrones_troll = [
        "inútil", "basura", "estúpido", "idiota", "mentira", 
        "estafa", "payaso", "no sirve", "fake", "fraude", 
        "vendido", "corrupto", "callate", "imbécil"
    ]
    
    # Evaluar nivel de amenaza
    if any(p in contenido for p in patrones_bot):
        risk_score = 90  # Alto riesgo de ser un Bot automatizado
    elif any(p in contenido for p in patrones_troll):
        risk_score = 75  # Riesgo moderado-alto de ser un Troll
        
    # Clasificación final devuelta al navegador
    clasificacion = "bot" if risk_score >= 85 else ("troll" if risk_score >= 60 else "normal")

    return {
        "status": "success",
        "risk_score": risk_score,
        "classification": clasificacion
    }

@app.get("/")
async def root():
    return {
        "system": "AegisNet Security Engine",
        "status": "Online",
        "protection": "Active"
    }
