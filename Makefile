.PHONY: up down logs ps

up:
	docker compose up -d minio qdrant mlflow

down:
	docker compose down

logs:
	docker compose logs -f mlflow

ps:
	docker compose ps
