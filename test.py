import time
import json
from zapv2 import ZAPv2
from collections import defaultdict

def scan(TARGET_URL):
    try:
        ZAP_URL = 'http://localhost:8080'  
        API_KEY = 'l73evs1395k61htfduf35f79ss'  

        zap = ZAPv2(proxies={'http': ZAP_URL, 'https': ZAP_URL}, apikey=API_KEY)

        # Start Spidering
        print("[*] Starting ZAP Spider scan...")
        scan_id = zap.spider.scan(TARGET_URL)
        time.sleep(2)  

        while int(zap.spider.status(scan_id)) < 100:
            print(f"[*] Spider progress: {zap.spider.status(scan_id)}%")
            time.sleep(10)

        print("[*] Spidering completed!")

        # Start Passive Scan
        print("[*] Starting Passive Scan...")
        zap.pscan.enable_all_scanners()  
        time.sleep(2)  

        # ✅ Corrected This Line:
        while int(zap.pscan.records_to_scan) > 0:
            print(f"[*] Records remaining to scan: {zap.pscan.records_to_scan}")
            time.sleep(10)

        print("[*] Passive Scan completed!")

        # Fetch Alerts
        print("[*] Fetching alerts...")
        alerts = zap.core.alerts(baseurl=TARGET_URL)
        print(f"[*] Alerts received: {len(alerts)}")

        vulnerabilities_by_type = defaultdict(lambda: {"risk": None, "description": None, "count": 0, "affected_urls": []})

        for alert in alerts:
            description = alert.get("description", "No description available")
            risk = alert.get("risk", "Info").capitalize()
            url = alert.get("url", "No URL")

            vulnerabilities_by_type[description]["risk"] = risk
            vulnerabilities_by_type[description]["description"] = description
            vulnerabilities_by_type[description]["count"] += 1
            if url not in vulnerabilities_by_type[description]["affected_urls"]:
                vulnerabilities_by_type[description]["affected_urls"].append(url)

        summary = defaultdict(int)
        for vulnerability in vulnerabilities_by_type.values():
            summary[vulnerability["risk"]] += 1

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

        print(json.dumps(final_results, indent=4))  # Print before saving
        output_file = "zap_vulnerabilities_summary.json"
        with open(output_file, "w") as file:
            json.dump(final_results, file, indent=4)

        print(f"\n[*] Vulnerability segregation completed successfully! Results have been saved to '{output_file}'.")

    except Exception as e:
        print(f"[ERROR] An issue occurred: {e}")

# Example Run
scan("https://example.com")
