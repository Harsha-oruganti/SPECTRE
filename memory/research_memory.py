"""
Research Memory — SPECTRE's Scientific Journal

Every finding is a peer-reviewed entry.
Every hypothesis is tracked to validation/rejection.
Every experiment has measured outcomes.

This is what separates a researcher from a scanner.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime
from memory.knowledge_base import load_kb, save_kb


def record_hypothesis(hypothesis):
    """Record a new hypothesis for tracking."""
    kb = load_kb()
    if "research_journal" not in kb:
        kb["research_journal"] = {
            "hypotheses": {},
            "experiments": {},
            "validated_findings": [],
            "rejected_findings": [],
            "research_timeline": []
        }

    h_id = hypothesis["id"]
    kb["research_journal"]["hypotheses"][h_id] = {
        **hypothesis,
        "status": "PENDING",
        "created_at": datetime.now().isoformat(),
        "experiments_run": [],
        "validation_result": None
    }

    kb["research_journal"]["research_timeline"].append({
        "timestamp": datetime.now().isoformat(),
        "event": f"HYPOTHESIS_CREATED: {h_id}",
        "summary": hypothesis["statement"][:100]
    })

    save_kb(kb)
    print(f"[RESEARCH MEMORY] Hypothesis {h_id} recorded")
    return h_id


def record_experiment_result(experiment_id, hypothesis_id, results, stats):
    """
    Record experiment outcomes and validate/reject hypothesis.
    This is peer review — evidence decides, not opinion.
    """
    kb = load_kb()
    journal = kb.get("research_journal", {})

    # Store experiment
    experiment_record = {
        "experiment_id":  experiment_id,
        "hypothesis_id":  hypothesis_id,
        "timestamp":      datetime.now().isoformat(),
        "results":        results,
        "statistics":     stats,
        "verdict":        None
    }

    # Validate hypothesis based on measured outcomes
    hypothesis = journal.get("hypotheses", {}).get(hypothesis_id, {})
    success_threshold = hypothesis.get("success_criterion", "")

    control_rate = stats.get("control_success_rate", 0)
    test_rate    = stats.get("test_success_rate", 0)

    if test_rate > control_rate * 1.5 and stats.get("sample_size", 0) >= 5:
        verdict = "VALIDATED"
        journal.get("validated_findings", []).append({
            "hypothesis_id": hypothesis_id,
            "finding":       hypothesis.get("statement"),
            "evidence":      stats,
            "validated_at":  datetime.now().isoformat()
        })
    elif stats.get("sample_size", 0) >= 10:
        verdict = "REJECTED"
        journal.get("rejected_findings", []).append({
            "hypothesis_id": hypothesis_id,
            "reason":        f"No significant difference: control={control_rate}, test={test_rate}",
            "rejected_at":   datetime.now().isoformat()
        })
    else:
        verdict = "INSUFFICIENT_DATA"

    experiment_record["verdict"] = verdict

    if hypothesis_id in journal.get("hypotheses", {}):
        journal["hypotheses"][hypothesis_id]["status"] = verdict
        journal["hypotheses"][hypothesis_id]["experiments_run"].append(experiment_id)

    journal["experiments"][experiment_id] = experiment_record

    journal["research_timeline"].append({
        "timestamp": datetime.now().isoformat(),
        "event":     f"EXPERIMENT_{verdict}: {experiment_id}",
        "summary":   f"H:{hypothesis_id} — {verdict}"
    })

    kb["research_journal"] = journal
    save_kb(kb)

    print(f"[RESEARCH MEMORY] Experiment {experiment_id}: {verdict}")
    return verdict


def get_research_summary(kb):
    """
    Generate a summary of all research findings.
    This feeds into the final report.
    """
    journal = kb.get("research_journal", {})

    summary = {
        "total_hypotheses":   len(journal.get("hypotheses", {})),
        "validated":          len(journal.get("validated_findings", [])),
        "rejected":           len(journal.get("rejected_findings", [])),
        "pending":            sum(
            1 for h in journal.get("hypotheses", {}).values()
            if h.get("status") == "PENDING"
        ),
        "validated_findings": journal.get("validated_findings", []),
        "research_timeline":  journal.get("research_timeline", [])[-10:],
        "knowledge_maturity": "LOW"
    }

    if summary["validated"] >= 3:
        summary["knowledge_maturity"] = "HIGH"
    elif summary["validated"] >= 1:
        summary["knowledge_maturity"] = "MEDIUM"

    return summary