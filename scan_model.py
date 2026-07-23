import json, os
from datetime import datetime
from huggingface_hub import snapshot_download, model_info
from modelscan.modelscan import ModelScan


def download_model(model_repo_id, download_dir=None):
    local_path = snapshot_download(
        repo_id=model_repo_id,
        local_dir=download_dir,
        allow_patterns=["*.bin", "*.h5", "config.json"]
    )
    return local_path


def get_model_metadata(model_repo_id):
    info = model_info(model_repo_id)

    license_tag = next(
        (tag.split("license:")[1] for tag in info.tags if tag.startswith("license:")),
        "not disclosed"
    )

    metadata = {
        "license": license_tag,
        "gated": info.gated,
        "base_model": info.base_models,
        "dataset": {
            "disclosed": "not disclosed",
            "verification_level": "metadata_only"
        }
    }
    return metadata

def scan_model_files(local_path):
    scanner = ModelScan()
    results = scanner.scan(path=local_path)
    return results


def build_ai_bom(model_repo_id):
    local_path = download_model(model_repo_id)
    metadata = get_model_metadata(model_repo_id)
    scan_results = scan_model_files(local_path)

    ai_bom = {
        "model_id": model_repo_id,
        "scan_date": datetime.utcnow().isoformat(),
        "modelscan_version": scan_results["summary"]["modelscan_version"],
        "license": metadata["license"],
        "base_model": metadata["base_model"],
        "dataset": metadata["dataset"],
        "artifact_scan": {
            "tool": "modelscan",
            "total_scanned": scan_results["summary"]["scanned"]["total_scanned"],
            "scanned_files": scan_results["summary"]["scanned"]["scanned_files"],
            "total_skipped": scan_results["summary"]["skipped"]["total_skipped"],
            "skipped_files": scan_results["summary"]["skipped"]["skipped_files"],
            "issues": scan_results["issues"],
            "total_issues": scan_results["summary"]["total_issues"],
            "issues_by_severity": scan_results["summary"]["total_issues_by_severity"],
            "errors": scan_results["errors"]
        },
        "behavioral_scan": None,
        "vulnerability_scan": None,
        "model_integrity_scan": None
    }
    return ai_bom

def save_ai_bom(ai_bom, output_dir="results"):
    model_folder_name = ai_bom["model_id"].replace("/", "--")
    folder_path = f"{output_dir}/{model_folder_name}"
    os.makedirs(folder_path, exist_ok=True)

    file_path = f"{folder_path}/ai_bom.json"
    with open(file_path, "w") as f:
        json.dump(ai_bom, f, indent=2)

    return file_path


if __name__ == "__main__":
    model_id = "openai-community/gpt2"
    result = build_ai_bom(model_id)
    saved_path = save_ai_bom(result)
    print(f"Saved to: {saved_path}")