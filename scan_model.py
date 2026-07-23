import json, os
from datetime import datetime
from huggingface_hub import snapshot_download, model_info, HfApi
from modelscan.modelscan import ModelScan


def format_downloads(n):
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    elif n >= 1_000:
        return f"{n / 1_000:.1f}K"
    else:
        return str(n)


def fetch_top_models(limit=20, output_path="models_list.json"):
    api = HfApi()
    models = api.list_models(
        sort="downloads",
        limit=limit,
        pipeline_tag="text-generation"
    )

    model_list = [
        {
            "model_id": model.id,
            "downloads": format_downloads(model.downloads)
        }
        for model in models
    ]

    data = {
        "generated_date": datetime.utcnow().isoformat(),
        "count": len(model_list),
        "models": model_list
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Fetched {len(model_list)} models, saved to {output_path}")
    return model_list


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

    scanned = scan_results["summary"]["scanned"]
    skipped = scan_results["summary"]["skipped"]

    ai_bom = {
        "model_id": model_repo_id,
        "scan_date": datetime.utcnow().isoformat(),
        "modelscan_version": scan_results["summary"]["modelscan_version"],
        "license": metadata["license"],
        "base_model": metadata["base_model"],
        "dataset": metadata["dataset"],
        "artifact_scan": {
            "tool": "modelscan",
            "total_scanned": scanned["total_scanned"],
            "scanned_files": scanned.get("scanned_files", []),
            "total_skipped": skipped["total_skipped"],
            "skipped_files": skipped.get("skipped_files", []),
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


def build_sarif(ai_bom):
    severity_to_level = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note"
    }

    sarif_results = []
    for issue in ai_bom["artifact_scan"]["issues"]:
        sarif_results.append({
            "ruleId": issue["operator"],
            "level": severity_to_level.get(issue["severity"], "warning"),
            "message": {"text": issue["description"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": issue["source"]}
                }
            }]
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ModelScan",
                    "informationUri": "https://github.com/protectai/modelscan",
                    "version": ai_bom["modelscan_version"]
                }
            },
            "automationDetails": {
                "id": f"modelscan/{ai_bom['model_id']}"
            },
            "results": sarif_results
        }]
    }
    return sarif


def save_sarif(sarif, model_id, output_dir="results"):
    model_folder_name = model_id.replace("/", "--")
    folder_path = f"{output_dir}/{model_folder_name}"
    os.makedirs(folder_path, exist_ok=True)

    file_path = f"{folder_path}/results.sarif"
    with open(file_path, "w") as f:
        json.dump(sarif, f, indent=2)

    return file_path


def scan_all_models(list_path="models_list.json"):
    with open(list_path, "r") as f:
        data = json.load(f)
    model_entries = data["models"]

    summary = {"succeeded": [], "failed": []}

    for entry in model_entries:
        model_id = entry["model_id"]
        print(f"\n--- Scanning: {model_id} ({entry['downloads']} downloads) ---")
        try:
            result = build_ai_bom(model_id)
            saved_path = save_ai_bom(result)
            sarif = build_sarif(result)
            sarif_path = save_sarif(sarif, model_id)
            print(f"Saved: {saved_path}")
            summary["succeeded"].append(model_id)
        except Exception as e:
            print(f"FAILED: {model_id} — {e}")
            summary["failed"].append({"model_id": model_id, "error": str(e)})

    print("\n--- Batch Summary ---")
    print(f"Succeeded: {len(summary['succeeded'])}")
    print(f"Failed: {len(summary['failed'])}")
    for failure in summary["failed"]:
        print(f"  - {failure['model_id']}: {failure['error']}")

    return summary

if __name__ == "__main__":
    fetch_top_models(limit=20)
    scan_all_models()