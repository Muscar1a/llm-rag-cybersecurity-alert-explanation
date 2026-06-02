import mlflow
import os

EXPERIMENT_NAME = "rag-cybersec-benchmark"


def set_tracking_uri(uri: str = None):
    tracking_uri = uri or os.environ.get("MLFLOW_TRACKING_URI", "http://localhost:5000")
    mlflow.set_tracking_uri(tracking_uri)


def log_rag_experiment(
    run_name: str,
    params: dict,
    metrics: dict,
    artifacts: list[str] = None,
    tags: dict = None,
) -> str:
    set_tracking_uri()
    mlflow.set_experiment(EXPERIMENT_NAME)

    with mlflow.start_run(run_name=run_name) as run:
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

        # Log params.yaml as artifact để tie config vào run
        if os.path.exists("params.yaml"):
            mlflow.log_artifact("params.yaml")

        return run.info.run_id


def register_rag_pipeline(run_id: str, model_name: str = "RAGPipeline") -> int | None:
    """Đăng ký config của run vào MLflow Model Registry, trả về version number."""
    set_tracking_uri()
    try:
        mv = mlflow.register_model(f"runs:/{run_id}/.", model_name)
        print(f"  [MLflow] Registered {model_name} version {mv.version} (run: {run_id[:8]})")
        return mv.version
    except Exception as e:
        print(f"  [MLflow] Model registration skipped: {e}")
        return None
