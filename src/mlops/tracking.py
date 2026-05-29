import mlflow
import os

def set_tracking_uri(uri: str = None):
    """
    Set the MLflow tracking URI. Default looks for MLFLOW_TRACKING_URI in env,
    otherwise defaults to http://localhost:5000.
    """
    tracking_uri = uri or os.environ.get("MLFLOW_TRACKING_URI", "http://localhost:5000")
    mlflow.set_tracking_uri(tracking_uri)


def log_rag_experiment(run_name: str, params: dict, metrics: dict, artifacts: list[str] = None, tags: dict = None):
    """
    Log an experiment run to MLflow.
    """
    set_tracking_uri()
    
    with mlflow.start_run(run_name=run_name):
        if params:
            mlflow.log_params(params)
        if metrics:
            mlflow.log_metrics(metrics)
        if artifacts:
            for path in artifacts:
                if os.path.exists(path):
                    mlflow.log_artifact(path)
                else:
                    print(f"Warning: Artifact path {path} does not exist.")
        if tags:
            mlflow.set_tags(tags)
