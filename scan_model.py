import json, os, subprocess
from datetime import datetime
from huggingface_hub import snapshot_download, model_info, HfApi
from modelscan.modelscan import ModelScan


ALLOW_PATTERNS = [
    "*.bin", "*.pt", "*.pth", "*.ckpt",
    "*.h5", "*.keras",
    "*.pb", "variables/*",
    "*.pkl", "*.pickle", "*.joblib", "*.dill", "*.dat", "*.data",
    "*.npy", "*.npz", "*.zip",
    "config.json", "*.safetensors"
]

SEVERITY_TO_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def format_downloads(n):
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    elif n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def save_json(data, filename, model_id, output_dir="results"):
    folder_path = f"{output_dir}/{model_id.replace('/', '--')}"
    os.makedirs(folder_path, exist_ok=True)
    file_path = f"{folder_path}/{filename}"
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)
    return file_path


def fetch_top_models(limit=20, output_path="models_list.json"):
    api = HfApi()
    models = api.list_models(sort="downloads", limit=limit, pipeline_tag="text-generation")
    model_list = [{"model_id": m.id, "downloads": format_downloads(m.downloads)} for m in models]
    data = {"generated_date": datetime.utcnow().isoformat(), "count": len(model_list), "models": model_list}
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Fetched {len(model_list)} models, saved to {output_path}")
    return model_list


def download_model(model_repo_id, download_dir=None):
    return snapshot_download(repo_id=model_repo_id, local_dir=download_dir, allow_patterns=ALLOW_PATTERNS)


def get_model_metadata(model_repo_id):
    info = model_info(model_repo_id)
    license_tag = next(
        (tag.split("license:")[1] for tag in info.tags if tag.startswith("license:")),
        "not disclosed"
    )
    return {
        "license": license_tag,
        "gated": info.gated,
        "base_model": info.base_models,
        "dataset": {"disclosed": "not disclosed", "verification_level": "metadata_only"}
    }


def scan_model_files(local_path):
    scanner = ModelScan()
    return scanner.scan(path=local_path)


def build_modelscan_result(scan_results):
    scanned = scan_results["summary"]["scanned"]
    skipped = scan_results["summary"]["skipped"]
    return {
        "tool": "modelscan",
        "modelscan_version": scan_results["summary"]["modelscan_version"],
        "status": "completed",
        "total_scanned": scanned["total_scanned"],
        "scanned_files": scanned.get("scanned_files", []),
        "total_skipped": skipped["total_skipped"],
        "skipped_files": skipped.get("skipped_files", []),
        "issues": scan_results["issues"],
        "total_issues": scan_results["summary"]["total_issues"],
        "issues_by_severity": scan_results["summary"]["total_issues_by_severity"],
        "errors": scan_results["errors"]
    }


def build_sarif(model_id, modelscan_version, issues):
    sarif_results = []
    for issue in issues:
        sarif_results.append({
            "ruleId": issue["operator"],
            "level": SEVERITY_TO_LEVEL.get(issue["severity"], "warning"),
            "message": {"text": issue["description"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": issue["source"]}}}]
        })
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "ModelScan", "informationUri": "https://github.com/protectai/modelscan", "version": modelscan_version}},
            "automationDetails": {"id": f"modelscan/{model_id}"},
            "results": sarif_results
        }]
    }


def scan_with_modelaudit(local_path, model_id):
    folder_path = f"results/{model_id.replace('/', '--')}"
    os.makedirs(folder_path, exist_ok=True)
    output_file = f"{folder_path}/modelaudit_raw.json"
    sbom_file = f"{folder_path}/sbom.json"

    result = subprocess.run(
        [
            "modelaudit", "scan", local_path,
            "--format", "json",
            "--output", output_file,
            "--strict",
            "--sbom", sbom_file
        ],
        capture_output=True, text=True
    )

    try:
        with open(output_file, "r") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raw = {}

    return {
        "tool": "modelaudit",
        "status": "completed" if raw else "no_output",
        "exit_code": result.returncode,
        "strict_mode": True,
        "files_scanned": raw.get("files_scanned", 0),
        "total_checks": raw.get("total_checks", 0),
        "passed_checks": raw.get("passed_checks", 0),
        "failed_checks": raw.get("failed_checks", 0),
        "issues": raw.get("issues", []),
        "success": raw.get("success", False),
        "sbom_path": sbom_file if os.path.exists(sbom_file) else None,
        "stderr": result.stderr if not raw else None
    }


def build_ai_bom(model_repo_id):
    metadata = get_model_metadata(model_repo_id)

    if metadata["gated"]:
        return {
            "model_id": model_repo_id,
            "scan_date": datetime.utcnow().isoformat(),
            "license": metadata["license"],
            "base_model": metadata["base_model"],
            "dataset": metadata["dataset"],
            "artifact_scan": {"tool": "modelscan", "status": "skipped_gated"},
            "artifact_scan_modelaudit": {"tool": "modelaudit", "status": "skipped_gated"},
            "behavioral_scan": None,
            "vulnerability_scan": None,
            "model_integrity_scan": None
        }

    local_path = download_model(model_repo_id)
    modelscan_result = build_modelscan_result(scan_model_files(local_path))
    modelaudit_result = scan_with_modelaudit(local_path, model_repo_id)

    return {
        "model_id": model_repo_id,
        "scan_date": datetime.utcnow().isoformat(),
        "license": metadata["license"],
        "base_model": metadata["base_model"],
        "dataset": metadata["dataset"],
        "artifact_scan": modelscan_result,
        "artifact_scan_modelaudit": modelaudit_result,
        "behavioral_scan": None,
        "vulnerability_scan": None,
        "model_integrity_scan": None
    }


def build_comparison_row(ai_bom):
    ms = ai_bom.get("artifact_scan", {})
    ma = ai_bom.get("artifact_scan_modelaudit", {})
    return {
        "model_id": ai_bom["model_id"],
        "status": ms.get("status", "unknown"),
        "modelscan_scanned": ms.get("total_scanned", 0),
        "modelscan_skipped": ms.get("total_skipped", 0),
        "modelscan_issues": ms.get("total_issues", 0),
        "modelaudit_files_scanned": ma.get("files_scanned", 0),
        "modelaudit_checks_passed": ma.get("passed_checks", 0),
        "modelaudit_checks_failed": ma.get("failed_checks", 0),
        "modelaudit_issues": len(ma.get("issues", []))
    }

def build_comparison_row(ai_bom):
    ms = ai_bom.get("artifact_scan", {})
    ma = ai_bom.get("artifact_scan_modelaudit", {})
    return {
        "model_id": ai_bom["model_id"],
        "status": ms.get("status", "unknown"),
        "license": ai_bom.get("license"),
        "modelscan": {
            "scanned": ms.get("total_scanned", 0),
            "skipped": ms.get("total_skipped", 0),
            "issues": ms.get("issues", [])
        },
        "modelaudit": {
            "scanned": ma.get("files_scanned", 0),
            "checks_passed": ma.get("passed_checks", 0),
            "checks_failed": ma.get("failed_checks", 0),
            "issues": ma.get("issues", [])
        }
    }

def scan_all_models(list_path="models_list.json"):
    with open(list_path, "r") as f:
        data = json.load(f)

    comparison_rows = []
    summary = {"succeeded": [], "failed": []}

    for entry in data["models"]:
        model_id = entry["model_id"]
        print(f"\n--- Scanning: {model_id} ({entry['downloads']} downloads) ---")
        try:
            ai_bom = build_ai_bom(model_id)
            save_json(ai_bom, "ai_bom.json", model_id)

            if ai_bom["artifact_scan"].get("status") != "skipped_gated":
                sarif = build_sarif(
                    model_id,
                    ai_bom["artifact_scan"].get("modelscan_version", "unknown"),
                    ai_bom["artifact_scan"].get("issues", [])
                )
                save_json(sarif, "results.sarif", model_id)

            comparison_rows.append(build_comparison_row(ai_bom))
            summary["succeeded"].append(model_id)
        except Exception as e:
            print(f"FAILED: {model_id} — {e}")
            summary["failed"].append({"model_id": model_id, "error": str(e)})

    save_json({"generated_date": datetime.utcnow().isoformat(), "models": comparison_rows}, "scanner_comparison.json", "_summary")

    print("\n--- Batch Summary ---")
    print(f"Succeeded: {len(summary['succeeded'])} | Failed: {len(summary['failed'])}")
    for failure in summary["failed"]:
        print(f"  - {failure['model_id']}: {failure['error']}")

    return summary, comparison_rows


if __name__ == "__main__":
    fetch_top_models(limit=20)
    scan_all_models()