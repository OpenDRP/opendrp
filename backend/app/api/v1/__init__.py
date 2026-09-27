from fastapi import APIRouter

from app.api.v1.routers.alerts import router as alerts_router
from app.api.v1.routers.assets import router as assets_router
from app.api.v1.routers.connectors import router as connectors_router
from app.api.v1.routers.audit import router as audit_router
from app.api.v1.routers.auth import router as auth_router
from app.api.v1.routers.dashboard import router as dashboard_router
from app.api.v1.routers.breaches import router as breaches_router
from app.api.v1.routers.jobs import router as jobs_router
from app.api.v1.routers.modules import router as modules_router
from app.api.v1.routers.phishing import router as phishing_router
from app.api.v1.routers.reports import router as reports_router
from app.api.v1.routers.settings import router as settings_router
from app.api.v1.routers.users import router as users_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth_router)
api_router.include_router(alerts_router)
api_router.include_router(assets_router)
api_router.include_router(settings_router)
api_router.include_router(breaches_router)
api_router.include_router(reports_router)
api_router.include_router(phishing_router)
api_router.include_router(dashboard_router)
api_router.include_router(users_router)
api_router.include_router(connectors_router)
api_router.include_router(modules_router)
api_router.include_router(audit_router)
api_router.include_router(jobs_router)
