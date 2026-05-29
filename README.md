# Installation and Run Guide

## 1. Start infrastructure (Docker)
Make sure Docker Desktop is running, then start MinIO (data storage), Qdrant (vector database), and MLflow (tracking server):

```bash
make up
```

## 2. Initialize DVC
Initialize Data Version Control (DVC) for the project:

```bash
.venv\Scripts\dvc init
```

## 3. Configure DVC remote (store data on MinIO)
Declare the local MinIO instance as the DVC remote storage and set credentials:

```bash
# Add a new remote named minio_remote
.venv\Scripts\dvc remote add -d minio_remote s3://minio-processed

# Set the endpoint URL
.venv\Scripts\dvc remote modify minio_remote endpointurl http://localhost:9000

# Configure credentials (from docker-compose env vars; defaults: admin/admin123)
.venv\Scripts\dvc remote modify minio_remote access_key_id admin
.venv\Scripts\dvc remote modify minio_remote secret_access_key admin123

# Disable SSL since MinIO runs on localhost over HTTP
.venv\Scripts\dvc remote modify minio_remote use_ssl false
```

## 4. Run the data pipeline
The following command will read `dvc.yaml` (if present) and parameters from `params.yaml`, then execute the pipeline steps in order: `clean` → `chunk` → `embed` and push vectors to Qdrant:

```bash
.venv\Scripts\dvc repro
```