<div align="center">

# ShieldFlow

### API Gateway de seguridad — Zero Trust

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Redis](https://img.shields.io/badge/Redis-7.2-DC382D?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Supabase-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://supabase.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-green?style=for-the-badge)](LICENSE)

</div>

Capa de seguridad para APIs. Detecta SQL Injection y XSS, limita peticiones por IP, gestiona autenticación JWT y guarda un registro de todo lo que bloquea. Se puede desplegar gratis en Render + Upstash + Supabase.

---

## Arrancar en local

Con Docker:

```bash
git clone https://github.com/tuusuario/shieldflow.git
cd shieldflow
cp .env.example .env
docker-compose up --build
```

Sin Docker:

```bash
python -m venv venv
source venv/bin/activate   # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
docker run -d -p 6379:6379 redis:7.2-alpine
uvicorn app.main:app --reload --port 8000
```

La API queda en `http://localhost:8000`. La documentación interactiva en `http://localhost:8000/docs`.

---

## Configuración

Copia `.env.example` a `.env` y edita los valores que necesites. Los imprescindibles:

```bash
JWT_SECRET_KEY=genera-uno-con-python-c-"import secrets;print(secrets.token_hex(32))"
DATABASE_URL=postgresql+asyncpg://usuario:contraseña@host:5432/shieldflow
REDIS_URL=redis://localhost:6379
```

El resto tiene valores por defecto que funcionan para desarrollo.

---

## Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

No necesitas Redis ni PostgreSQL instalados. Los tests usan versiones en memoria.

---

## Prueba de carga

```bash
# Interfaz web
locust -f locustfile.py --host http://localhost:8000

# Sin interfaz
locust -f locustfile.py --headless --users 100 --spawn-rate 10 --run-time 60s --host http://localhost:8000
```

---

## Endpoints

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| POST | `/api/v1/auth/token` | No | Login |
| POST | `/api/v1/auth/refresh` | No | Rotar tokens |
| GET | `/api/v1/auth/me` | Si | Perfil del usuario actual |
| GET | `/api/v1/gateway/echo` | No | Endpoint público (WAF activo) |
| POST | `/api/v1/gateway/echo` | Si | Echo autenticado |
| GET | `/api/v1/gateway/threats` | Admin | Registro de ataques |
| GET | `/api/v1/gateway/stats` | Admin | Estadísticas |
| GET | `/health` | No | Estado del sistema |
| GET | `/metrics` | No | Métricas Prometheus |

Usuarios de prueba:

| Usuario | Contraseña | Rol |
|---|---|---|
| admin | supersecret | Admin |
| developer | devpassword | Developer |
| readonly | readonlypass | Viewer |

Ejemplo rápido desde terminal:

```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"supersecret"}' | python -m json.tool | grep access_token | cut -d'"' -f4)

# Endpoint protegido
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/auth/me

# Probar WAF (devuelve 403)
curl "http://localhost:8000/api/v1/gateway/echo?message=' OR 1=1--"
```

---

## Desplegar gratis

**Base de datos — Supabase**

1. Crea un proyecto en [supabase.com](https://supabase.com)
2. Ve a Settings → Database → Connection String → Transaction Pooler
3. Copia la URL y cambia `postgresql://` por `postgresql+asyncpg://`
4. Crea las tablas: `DATABASE_URL="tu-url" alembic upgrade head`

**Redis — Upstash**

1. Crea una base de datos en [upstash.com](https://upstash.com)
2. Copia la URL (formato `rediss://...`)

**Servidor — Render**

1. Sube el código a GitHub
2. Nuevo Web Service en [render.com](https://render.com)
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Añade las variables de entorno y despliega

---

## Licencia

MIT
