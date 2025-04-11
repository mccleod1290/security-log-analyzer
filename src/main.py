import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

# Import components
from ingestion.log_collector import LogCollector
from analysis.analyzer import SecurityAnalyzer
from visualization.dashboard import Dashboard
from alerts.alert_manager import AlertManager
from storage.elasticsearch_client import ElasticsearchClient
from storage.postgres_client import PostgresClient
from storage.redis_client import RedisClient
from utils.config import load_config

app = FastAPI(title="Security Log Analysis and Visualization Tool")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global components
log_collector = None
security_analyzer = None
dashboard = None
alert_manager = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load configuration
    config = load_config()
    
    # Initialize storage clients
    es_client = ElasticsearchClient(config["elasticsearch"])
    pg_client = PostgresClient(config["postgresql"])
    redis_client = RedisClient(config["redis"])
    
    # Initialize components
    global log_collector, security_analyzer, dashboard, alert_manager
    
    log_collector = LogCollector(es_client, config["ingestion"])
    security_analyzer = SecurityAnalyzer(es_client, redis_client, config["analysis"])
    dashboard = Dashboard(es_client, config["visualization"])
    alert_manager = AlertManager(redis_client, config["alerts"])
    
    # Start background tasks
    asyncio.create_task(log_collector.start_collection())
    asyncio.create_task(security_analyzer.start_analysis())
    asyncio.create_task(alert_manager.start_monitoring())
    
    yield
    
    # Cleanup
    await log_collector.stop()
    await security_analyzer.stop()
    await alert_manager.stop()
    await es_client.close()
    await pg_client.close()
    await redis_client.close()

app.router.lifespan_context = lifespan

@app.get("/")
async def root():
    return {"status": "running", "service": "Security Log Analyzer"}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "components": {
            "log_collector": log_collector.status if log_collector else "not_initialized",
            "analyzer": security_analyzer.status if security_analyzer else "not_initialized",
            "dashboard": dashboard.status if dashboard else "not_initialized",
            "alert_manager": alert_manager.status if alert_manager else "not_initialized"
        }
    }

# Import and include routers from other components
from ingestion.routes import router as ingestion_router
from analysis.routes import router as analysis_router
from visualization.routes import router as visualization_router
from alerts.routes import router as alerts_router

app.include_router(ingestion_router, prefix="/api/ingestion", tags=["ingestion"])
app.include_router(analysis_router, prefix="/api/analysis", tags=["analysis"])
app.include_router(visualization_router, prefix="/api/visualization", tags=["visualization"])
app.include_router(alerts_router, prefix="/api/alerts", tags=["alerts"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) 