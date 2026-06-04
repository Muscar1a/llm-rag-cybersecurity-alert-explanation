.PHONY: up down logs ps build-api up-api monitoring

up:
	docker compose up -d minio qdrant mlflow

build-api:
	docker compose build rag-api

up-api:
	docker compose up -d minio qdrant mlflow rag-api

monitoring:
	docker compose up -d minio qdrant mlflow rag-api prometheus grafana

down:
	docker compose down

logs:
	docker compose logs -f mlflow

ps:
	docker compose ps
