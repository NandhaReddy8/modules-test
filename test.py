import time
import json
from zapv2 import ZAPv2
from collections import defaultdict

def scan(TARGET_URL):

    # Define the target URL and ZAP settings
    ZAP_URL = 'http://localhost:8080'  # Ensure ZAP is running in daemon mode
    # TARGET_URL = 'https://virtuestech.com'  # Target URL for scanning
    API_KEY = 'l73evs1395k61htfduf35f79ss'  # API key (optional, if enabled in ZAP settings)

    # Initialize ZAP API
    zap = ZAPv2(proxies={'http': ZAP_URL, 'https': ZAP_URL}, apikey=API_KEY)

    # Spidering Phase
    print("[*] Starting ZAP Spider scan...")
    zap.spider.scan(TARGET_URL)
    time.sleep(2)  # Wait for the scan to initialize

    # Monitor Spider progress
    while int(zap.spider.status()) < 100:
        print(f"[*] Spider progress: {zap.spider.status()}%")
        time.sleep(10)

    print("[*] Spidering completed!")

    # Passive Scan Phase
    print("[*] Starting Passive Scan...")
    zap.pscan.enable_all_scanners()  # Enable all passive scanners
    time.sleep(2)  # Allow passive scan initialization

    # Monitor Passive Scan Progress
    print("[*] Monitoring Passive Scan progress...")
    while int(zap.pscan.records_to_scan) > 0:
        print(f"[*] Records remaining to scan: {zap.pscan.records_to_scan}")
        time.sleep(10)

    print("[*] Passive Scan completed!")

    # Fetch Passive Scan Alerts
    alerts = zap.core.alerts(baseurl=TARGET_URL)

    # Organize vulnerabilities by type/description
    vulnerabilities_by_type = defaultdict(lambda: {"risk": None, "description": None, "count": 0, "affected_urls": []})

    # Process alerts and group by description
    for alert in alerts:
        description = alert.get("description", "No description available")
        risk = alert.get("risk", "Info").capitalize()
        url = alert.get("url", "No URL")

        # Add the alert to the vulnerabilities_by_type dictionary
        vulnerabilities_by_type[description]["risk"] = risk
        vulnerabilities_by_type[description]["description"] = description
        vulnerabilities_by_type[description]["count"] += 1
        if url not in vulnerabilities_by_type[description]["affected_urls"]:
            vulnerabilities_by_type[description]["affected_urls"].append(url)

    # Create a summary of vulnerabilities by type (ignoring affected URLs count)
    summary = defaultdict(int)
    for vulnerability in vulnerabilities_by_type.values():
        summary[vulnerability["risk"]] += 1

    # Prepare the final results structure
    final_results = {
        "summary": dict(summary),
        "vulnerabilities_by_type": [
            {
                "risk": vuln["risk"],
                "description": vuln["description"],
                "count": len(vuln["affected_urls"]),
                "affected_urls": vuln["affected_urls"][:3] + (
                    ["and {} other sites".format(len(vuln["affected_urls"]) - 3)]
                    if len(vuln["affected_urls"]) > 3
                    else []
                )
            } for vuln in vulnerabilities_by_type.values()
        ]
    }

    # Save the results to a JSON file
    output_file = "zap_vulnerabilities_summary.json"
    with open(output_file, "w") as file:
        json.dump(final_results, file, indent=4)

    print(f"\n[*] Vulnerability segregation completed successfully! Results have been saved to '{output_file}'.")
