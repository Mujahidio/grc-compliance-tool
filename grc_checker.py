"""
GRC Compliance Checklist Tool
Maps security controls to SAMA CSF and NCA ECC frameworks.
Author: Mujahid Ahmed
"""

import json
import csv
import os
from datetime import datetime


CONTROLS = {
    "SAMA CSF": {
        "Cyber Security Leadership and Governance": [
            {"id": "SAMA-1.1", "control": "Information security policy is documented and approved by senior management.", "priority": "Critical"},
            {"id": "SAMA-1.2", "control": "Roles and responsibilities for cybersecurity are clearly defined.", "priority": "Critical"},
            {"id": "SAMA-1.3", "control": "Cybersecurity strategy is aligned with business objectives.", "priority": "High"},
            {"id": "SAMA-1.4", "control": "Board/senior management receives regular cybersecurity reports.", "priority": "High"},
        ],
        "Cyber Security Risk Management": [
            {"id": "SAMA-2.1", "control": "A formal risk assessment process is established and documented.", "priority": "Critical"},
            {"id": "SAMA-2.2", "control": "Risk register is maintained and reviewed periodically.", "priority": "Critical"},
            {"id": "SAMA-2.3", "control": "Risk treatment plans are in place for identified risks.", "priority": "High"},
            {"id": "SAMA-2.4", "control": "Third-party and vendor risks are assessed before engagement.", "priority": "High"},
        ],
        "Cyber Security Operations and Technology": [
            {"id": "SAMA-3.1", "control": "SIEM solution is deployed and monitored 24/7.", "priority": "Critical"},
            {"id": "SAMA-3.2", "control": "Vulnerability assessment and penetration testing (VAPT) is conducted regularly.", "priority": "Critical"},
            {"id": "SAMA-3.3", "control": "Patch management process is defined and enforced.", "priority": "High"},
            {"id": "SAMA-3.4", "control": "Firewall and IDS/IPS are configured and monitored.", "priority": "Critical"},
            {"id": "SAMA-3.5", "control": "Endpoint protection (anti-virus/anti-malware) is deployed on all assets.", "priority": "High"},
        ],
        "Identity and Access Management": [
            {"id": "SAMA-4.1", "control": "Access is granted based on least privilege and need-to-know principles.", "priority": "Critical"},
            {"id": "SAMA-4.2", "control": "Multi-factor authentication (MFA) is enforced for privileged accounts.", "priority": "Critical"},
            {"id": "SAMA-4.3", "control": "Access reviews are conducted at least quarterly.", "priority": "High"},
            {"id": "SAMA-4.4", "control": "Joiner-Mover-Leaver (JML) process is documented and enforced.", "priority": "High"},
        ],
        "Third-Party Cybersecurity": [
            {"id": "SAMA-5.1", "control": "Third-party cybersecurity requirements are included in contracts.", "priority": "High"},
            {"id": "SAMA-5.2", "control": "Third-party access is monitored and logged.", "priority": "High"},
            {"id": "SAMA-5.3", "control": "Annual third-party security assessments are performed.", "priority": "Medium"},
        ],
    },
    "NCA ECC": {
        "Cybersecurity Governance": [
            {"id": "ECC-1.1", "control": "Cybersecurity policies are approved and communicated organization-wide.", "priority": "Critical"},
            {"id": "ECC-1.2", "control": "Cybersecurity function reports to senior executive level.", "priority": "High"},
            {"id": "ECC-1.3", "control": "Cybersecurity awareness program is established.", "priority": "High"},
        ],
        "Cybersecurity Defense": [
            {"id": "ECC-2.1", "control": "Asset inventory is maintained and classified by criticality.", "priority": "Critical"},
            {"id": "ECC-2.2", "control": "Network segmentation is implemented to isolate critical systems.", "priority": "Critical"},
            {"id": "ECC-2.3", "control": "Security event logs are collected, retained, and reviewed.", "priority": "Critical"},
            {"id": "ECC-2.4", "control": "Data Loss Prevention (DLP) controls are implemented.", "priority": "High"},
            {"id": "ECC-2.5", "control": "Cryptographic controls are used to protect sensitive data.", "priority": "High"},
        ],
        "Cybersecurity Resilience": [
            {"id": "ECC-3.1", "control": "Business continuity and disaster recovery plans are documented and tested.", "priority": "Critical"},
            {"id": "ECC-3.2", "control": "Data backup procedures are in place and verified regularly.", "priority": "Critical"},
            {"id": "ECC-3.3", "control": "Incident response plan is defined, tested, and up to date.", "priority": "Critical"},
        ],
        "Cybersecurity in Technology Acquisition": [
            {"id": "ECC-4.1", "control": "Secure development lifecycle (SDLC) is followed for in-house software.", "priority": "High"},
            {"id": "ECC-4.2", "control": "Software components are reviewed for known vulnerabilities before deployment.", "priority": "High"},
            {"id": "ECC-4.3", "control": "Cloud security baseline is defined and enforced.", "priority": "High"},
        ],
    }
}

STATUSES = ["Compliant", "Partially Compliant", "Non-Compliant", "Not Applicable"]
PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def print_header():
    print("=" * 65)
    print("   GRC COMPLIANCE CHECKLIST TOOL")
    print("   Frameworks: SAMA CSF | NCA ECC")
    print("=" * 65)
    print()


def print_summary(results):
    total = len(results)
    if total == 0:
        return
    counts = {s: 0 for s in STATUSES}
    for r in results:
        counts[r["status"]] += 1
    compliant_pct = round((counts["Compliant"] / total) * 100, 1)
    print("\n" + "=" * 65)
    print("  ASSESSMENT SUMMARY")
    print("=" * 65)
    print(f"  Total Controls Assessed : {total}")
    print(f"  Compliant               : {counts['Compliant']} ({compliant_pct}%)")
    print(f"  Partially Compliant     : {counts['Partially Compliant']}")
    print(f"  Non-Compliant           : {counts['Non-Compliant']}")
    print(f"  Not Applicable          : {counts['Not Applicable']}")
    print("=" * 65)

    critical_gaps = [r for r in results if r["status"] == "Non-Compliant" and r["priority"] == "Critical"]
    if critical_gaps:
        print(f"\n  [!] CRITICAL GAPS REQUIRING IMMEDIATE ACTION ({len(critical_gaps)}):")
        for g in critical_gaps:
            print(f"      - [{g['id']}] {g['control'][:55]}...")
    print()


def run_assessment(framework_name, framework_data):
    results = []
    print(f"\n  Starting assessment: {framework_name}\n")

    for domain, controls in framework_data.items():
        print(f"\n  --- Domain: {domain} ---\n")
        for ctrl in controls:
            print(f"  [{ctrl['id']}] [{ctrl['priority']}]")
            print(f"  {ctrl['control']}")
            print()
            for i, status in enumerate(STATUSES, 1):
                print(f"    {i}. {status}")
            while True:
                choice = input("  Select status (1-4): ").strip()
                if choice in ["1", "2", "3", "4"]:
                    break
                print("  Invalid choice. Enter 1-4.")
            notes = input("  Notes/evidence (optional, press Enter to skip): ").strip()
            results.append({
                "framework": framework_name,
                "domain": domain,
                "id": ctrl["id"],
                "control": ctrl["control"],
                "priority": ctrl["priority"],
                "status": STATUSES[int(choice) - 1],
                "notes": notes,
                "assessed_at": datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            print()
    return results


def export_results(results, fmt="json"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "json":
        filename = f"compliance_report_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump({"generated_at": datetime.now().isoformat(), "results": results}, f, indent=2)
    elif fmt == "csv":
        filename = f"compliance_report_{timestamp}.csv"
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["framework", "domain", "id", "control", "priority", "status", "notes", "assessed_at"])
            writer.writeheader()
            writer.writerows(results)
    print(f"\n  Report exported: {filename}")
    return filename


def demo_mode():
    """Run a quick demo with pre-filled answers to show the tool output."""
    import random
    results = []
    weights = {"Compliant": 0.5, "Partially Compliant": 0.25, "Non-Compliant": 0.2, "Not Applicable": 0.05}
    population = list(weights.keys())
    w = list(weights.values())
    for fw_name, fw_data in CONTROLS.items():
        for domain, controls in fw_data.items():
            for ctrl in controls:
                results.append({
                    "framework": fw_name,
                    "domain": domain,
                    "id": ctrl["id"],
                    "control": ctrl["control"],
                    "priority": ctrl["priority"],
                    "status": random.choices(population, w)[0],
                    "notes": "Auto-generated demo entry",
                    "assessed_at": datetime.now().strftime("%Y-%m-%d %H:%M")
                })
    print_summary(results)
    export_results(results, "json")
    export_results(results, "csv")


def main():
    clear()
    print_header()
    print("  Select an option:")
    print("  1. Run SAMA CSF Assessment")
    print("  2. Run NCA ECC Assessment")
    print("  3. Run Full Assessment (SAMA CSF + NCA ECC)")
    print("  4. Demo Mode (auto-fills results for testing)")
    print("  5. Exit")
    print()

    choice = input("  Enter choice: ").strip()
    all_results = []

    if choice == "1":
        all_results = run_assessment("SAMA CSF", CONTROLS["SAMA CSF"])
    elif choice == "2":
        all_results = run_assessment("NCA ECC", CONTROLS["NCA ECC"])
    elif choice == "3":
        all_results += run_assessment("SAMA CSF", CONTROLS["SAMA CSF"])
        all_results += run_assessment("NCA ECC", CONTROLS["NCA ECC"])
    elif choice == "4":
        print("\n  Running demo mode...\n")
        demo_mode()
        return
    elif choice == "5":
        print("\n  Goodbye.\n")
        return
    else:
        print("\n  Invalid choice.")
        return

    print_summary(all_results)

    fmt = input("  Export report as (1) JSON  (2) CSV  (3) Both: ").strip()
    if fmt == "1":
        export_results(all_results, "json")
    elif fmt == "2":
        export_results(all_results, "csv")
    elif fmt == "3":
        export_results(all_results, "json")
        export_results(all_results, "csv")


if __name__ == "__main__":
    main()
