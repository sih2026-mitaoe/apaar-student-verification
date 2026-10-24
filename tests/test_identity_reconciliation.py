from backend.identity_reconciliation import reconcile_records, mask_identifier, RULESET_VERSION


def test_cross_institution_exact_identifier_match_masks_external_identifier():
    records = [
        {"id": 1, "institution": "Campus A", "institution_student_id": "A-10001", "full_name": "Aarav Sharma", "apaar_id": "SYN-APAAR-10001", "archived_at": None, "email": "local@example.test"},
        {"id": 2, "institution": "Campus B", "institution_student_id": "B-99876", "full_name": "Aarav Sharma", "apaar_id": " syn-apaar-10001 ", "archived_at": None, "email": "private@example.test"},
    ]
    result = reconcile_records(records, "Campus A")
    assert len(result) == 1
    assert result[0]["signal"] == "IDENTIFIER_AND_NAME_MATCH"
    assert result[0]["other_student_id_masked"] == "•••• 9876"
    assert "private@example.test" not in str(result[0])
    assert "SYN-APAAR-10001" not in str(result[0])
    assert result[0]["ruleset_version"] == RULESET_VERSION


def test_same_identifier_with_name_conflict_requires_review_signal():
    records = [
        {"id": 1, "institution": "Campus A", "institution_student_id": "A-1", "full_name": "Aarav Sharma", "apaar_id": "SYN-1", "archived_at": None},
        {"id": 2, "institution": "Campus B", "institution_student_id": "B-2", "full_name": "Meera Patil", "apaar_id": "SYN-1", "archived_at": None},
    ]
    result = reconcile_records(records, "Campus A")
    assert len(result) == 1
    assert result[0]["signal"] == "IDENTIFIER_MATCH_NAME_CONFLICT"
    assert result[0]["name_match"] is False
    assert "review" in result[0]["explanation"].lower()


def test_no_name_only_cross_institution_match_and_no_archived_records():
    records = [
        {"id": 1, "institution": "Campus A", "institution_student_id": "A-1", "full_name": "Aarav Sharma", "apaar_id": "SYN-1", "archived_at": None},
        {"id": 2, "institution": "Campus B", "institution_student_id": "B-2", "full_name": "Aarav Sharma", "apaar_id": "SYN-2", "archived_at": None},
        {"id": 3, "institution": "Campus B", "institution_student_id": "B-3", "full_name": "Aarav Sharma", "apaar_id": "SYN-1", "archived_at": "2026-01-01"},
    ]
    assert reconcile_records(records, "Campus A") == []
    assert mask_identifier("") == "Not provided"
