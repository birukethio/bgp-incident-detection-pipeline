from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "external_validation" / "proposed_cohort_v1"


def test_proposed_cohort_obeys_preinference_gates():
    cohort = pd.read_csv(OUT / "proposed_final_external_cohort_v1.csv")
    assert len(cohort) > 0
    assert cohort["external_id"].is_unique
    assert set(cohort["archive_eligibility"]) == {"ELIGIBLE"}
    assert set(cohort["original_corpus_overlap"]) == {"NO"}
    assert set(cohort["pilot_overlap"]) == {"NO"}


def test_screening_contains_no_model_output_fields():
    screening = pd.read_csv(OUT / "external_candidate_screening_v1.csv")
    forbidden = ("prediction", "probability", "confidence", "score_margin")
    assert not [column for column in screening.columns if any(token in column.lower() for token in forbidden)]


def test_all_pilot_incidents_remain_excluded():
    screening = pd.read_csv(OUT / "external_candidate_screening_v1.csv")
    pilot = screening[screening["pilot_overlap"] == "YES"]
    assert len(pilot) == 9
    assert set(pilot["final_screening_disposition"]) == {"PILOT_EXCLUDED"}


def test_accepted_candidates_have_all_required_archives():
    screening = pd.read_csv(OUT / "external_candidate_screening_v1.csv")
    accepted = screening[screening["final_screening_disposition"] == "ACCEPTED"]
    assert set(accepted["routeviews_availability"]) == {"AVAILABLE"}
    assert set(accepted["caida_historical_availability"]) == {"AVAILABLE"}
    assert set(accepted["rpki_historical_availability"]) == {"AVAILABLE"}


def test_evidence_ledger_uses_no_cloudflare_deciding_source():
    evidence = pd.read_csv(OUT / "external_source_evidence_ledger_v1.csv")
    assert set(evidence["cloudflare_primary_or_deciding_source"]) == {"NO"}
