import json
import os
from datetime import datetime

KB_FILE = "memory/spectre_kb.json"

def load_kb():
    """Load existing knowledge base or create new one."""
    if os.path.exists(KB_FILE):
        with open(KB_FILE, "r") as f:
            return json.load(f)
    return {
        "total_scans": 0,
        "total_attacks": 0,
        "successful_attacks": 0,
        "partial_attacks": 0,
        "failed_attacks": 0,
        "attack_patterns": {},
        "successful_payloads": [],
        "target_profiles": {},
        "evolution_log": [],
        "findings": []
    }

def save_kb(kb):
    """Save knowledge base to file."""
    os.makedirs("memory", exist_ok=True)
    with open(KB_FILE, "w") as f:
        json.dump(kb, f, indent=2)

def store_finding(profile, attack, attack_result, verdict):
    """
    Store complete attack finding in knowledge base.
    This is SPECTRE's memory — what makes it evolve.
    """
    kb = load_kb()

    # Update counters
    kb["total_attacks"] += 1
    result = verdict.get("verdict", "FAILED")
    if result == "SUCCESS":
        kb["successful_attacks"] += 1
    elif result == "PARTIAL":
        kb["partial_attacks"] += 1
    else:
        kb["failed_attacks"] += 1

    # Store attack pattern performance
    attack_type = attack.get("attack_type", "unknown")
    if attack_type not in kb["attack_patterns"]:
        kb["attack_patterns"][attack_type] = {
            "total": 0,
            "success": 0,
            "partial": 0,
            "failed": 0,
            "success_rate": 0.0
        }

    pattern = kb["attack_patterns"][attack_type]
    pattern["total"] += 1
    if result == "SUCCESS":
        pattern["success"] += 1
    elif result == "PARTIAL":
        pattern["partial"] += 1
    else:
        pattern["failed"] += 1
    pattern["success_rate"] = round(
        (pattern["success"] + pattern["partial"] * 0.5) / pattern["total"] * 100, 2
    )

    # Store successful payloads for evolution
    if result in ["SUCCESS", "PARTIAL"]:
        kb["successful_payloads"].append({
            "attack_type": attack_type,
            "payload": attack.get("payload", ""),
            "severity": verdict.get("severity_score", 0),
            "technique": attack.get("technique", ""),
            "timestamp": datetime.now().isoformat()
        })

    # Store complete finding
    finding = {
        "spectre_id": verdict.get("spectre_id", f"SPECTRE-2026-{kb['total_attacks']:03d}"),
        "timestamp": datetime.now().isoformat(),
        "target": profile.get("target", "unknown"),
        "attack_type": attack_type,
        "verdict": result,
        "severity_score": verdict.get("severity_score", 0),
        "cvss_rating": verdict.get("cvss_rating", "Unknown"),
        "owasp_category": verdict.get("owasp_category", "Unknown"),
        "what_was_exposed": verdict.get("what_was_exposed", "None"),
        "summary": verdict.get("summary", ""),
        "follow_up_attacks": verdict.get("follow_up_attacks", []),
        "payload_preview": attack.get("payload", "")[:200]
    }
    kb["findings"].append(finding)

    # Evolution log
    kb["evolution_log"].append({
        "timestamp": datetime.now().isoformat(),
        "event": f"Attack {result}: {attack_type}",
        "severity": verdict.get("severity_score", 0),
        "learned": verdict.get("follow_up_attacks", [])
    })

    save_kb(kb)

    print(f"\n[KB] Finding stored: {finding['spectre_id']}")
    print(f"[KB] Total attacks in memory: {kb['total_attacks']}")
    print(f"[KB] Success rate: {kb['successful_attacks']}/{kb['total_attacks']}")
    print(f"[KB] Pattern performance:")
    for ptype, stats in kb["attack_patterns"].items():
        print(f"     {ptype}: {stats['success_rate']}% success rate")

    return kb

def get_best_attacks(kb):
    """Return attack types ranked by success rate."""
    patterns = kb.get("attack_patterns", {})
    ranked = sorted(
        patterns.items(),
        key=lambda x: x[1]["success_rate"],
        reverse=True
    )
    return ranked

def get_evolution_insights(kb):
    """Get insights for evolving attack strategy."""
    insights = {
        "total_attacks": kb["total_attacks"],
        "overall_success_rate": round(
            (kb["successful_attacks"] + kb["partial_attacks"] * 0.5)
            / max(kb["total_attacks"], 1) * 100, 2
        ),
        "best_attack_type": None,
        "worst_attack_type": None,
        "total_findings": len(kb["findings"]),
        "critical_findings": len([
            f for f in kb["findings"]
            if f["severity_score"] >= 8
        ])
    }

    ranked = get_best_attacks(kb)
    if ranked:
        insights["best_attack_type"] = ranked[0][0]
        insights["worst_attack_type"] = ranked[-1][0]

    return insights


if __name__ == "__main__":
    # Test knowledge base
    mock_profile = {"target": "AI banking chatbot"}
    mock_attack = {
        "attack_type": "Social Engineering",
        "payload": "Test payload",
        "technique": "Pretexting"
    }
    mock_result = {"target_response": "I cannot help with that"}
    mock_verdict = {
        "verdict": "FAILED",
        "severity_score": 2,
        "cvss_rating": "Low",
        "owasp_category": "A05",
        "what_was_exposed": "None",
        "summary": "Attack failed",
        "follow_up_attacks": ["Phishing", "Pretexting"],
        "spectre_id": "SPECTRE-2026-001"
    }

    kb = store_finding(mock_profile, mock_attack, mock_result, mock_verdict)
    insights = get_evolution_insights(kb)

    print("\n[EVOLUTION INSIGHTS]:")
    print(json.dumps(insights, indent=2))