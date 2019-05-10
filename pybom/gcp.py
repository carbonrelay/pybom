import subprocess
import yaml


GOOGLE_CLOUD_PROJECT = "my-project"


def summarize_image_vulns(image_name, tag):
    image_fqn = f"us.gcr.io/{GOOGLE_CLOUD_PROJECT}/{image_name}:{tag}"
    command = (
        f"gcloud beta container images describe {image_fqn} "
        "--show-package-vulnerability"
    )
    result = subprocess.run(command, stdout=subprocess.PIPE, shell=True)
    fmtd = yaml.load(result.stdout)

    summary = fmtd["package_vulnerability_summary"]
    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "None"]

    counts = dict()
    for level in levels:
        counts[level] = len(summary["vulnerabilities"][level])

    return counts
