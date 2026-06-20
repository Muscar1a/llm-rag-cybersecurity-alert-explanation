.PHONY: up down logs ps build-api up-api monitoring

up:
	docker compose up -d qdrant mlflow

build-api:
	docker compose build rag-api

api:
	uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

up-api:
	docker compose up -d qdrant mlflow rag-api

monitoring:
	docker compose up -d qdrant mlflow rag-api prometheus grafana

down:
	docker compose down

logs:
	docker compose logs -f mlflow

ps:
	docker compose ps
