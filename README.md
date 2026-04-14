# Cài mc (MinIO Client)
docker exec minio mc alias set local http://localhost:9000 minioadmin minioadmin123

docker exec minio mc mb local/dvc-store-raw; 
docker exec minio mc mb local/dvc-store-processed

# Thêm remote (file .dvc/config - commit lên Git được)
dvc remote add -d minio-raw s3://dvc-store-raw/
dvc remote add -d minio-processed s3://dvc-store-processed/

dvc remote modify minio-raw endpointurl http://localhost:9000
dvc remote modify minio-processed endpointurl http://localhost:9000


dvc remote modify --local minio-raw access_key_id minioadmin; 
dvc remote modify --local minio-raw secret_access_key minioadmin123; 
dvc remote modify --local minio-processed access_key_id minioadmin; 
dvc remote modify --local minio-processed secret_access_key minioadmin123

# Các config này lưu local (KHÔNG commit - chứa credentials)

# Push data lên MinIO
dvc push
