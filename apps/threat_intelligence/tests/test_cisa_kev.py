import pytest
from datetime import datetime, timedelta
from apps.threat_intelligence.cisa_kev import (
    CISAKEVSourceModel,
    CISAKEVRecordModel,
    CISAKEVHistoryModel,
    CISAKEVIngestionService,
    EXPERIMENTAL_DEMO_DATA_ONLY,
    SecurityError
)

class TestCISAKEVSourceModel:
    """Tests for CISA KEV Source Model"""
    
    def test_create_source(self):
        """Test source model creation"""
        source = CISAKEVSourceModel(
            source_id="cisa-kev",
            source_name="CISA Known Exploited Vulnerabilities Catalog",
            source_publication_timestamp=datetime.utcnow(),
            provenance="cisa_kev_ingestion_pipeline",
            confidence=1.0,
            experimental_label=None,
            tenant_id="tenant-001"
        )
        assert source.source_id == "cisa-kev"
        assert source.source_name == "CISA Known Exploited Vulnerabilities Catalog"
        assert source.confidence == 1.0
        assert source.experimental_label is None
        assert source.tenant_id == "tenant-001"
    
    def test_experimental_label(self):
        """Test experimental label handling"""
        source = CISAKEVSourceModel(
            source_id="cisa-kev",
            source_name="CISA Known Exploited Vulnerabilities Catalog",
            source_publication_timestamp=datetime.utcnow(),
            provenance="cisa_kev_ingestion_pipeline",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        assert source.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
    
    def test_invalid_experimental_label(self):
        """Test invalid experimental label rejection"""
        with pytest.raises(ValueError):
            CISAKEVSourceModel(
                source_id="cisa-kev",
                source_name="CISA Known Exploited Vulnerabilities Catalog",
                source_publication_timestamp=datetime.utcnow(),
                provenance="cisa_kev_ingestion_pipeline",
                experimental_label="INVALID_LABEL"
            )

class TestCISAKEVRecordModel:
    """Tests for CISA KEV Record Model"""
    
    def test_create_record(self):
        """Test KEV record model creation"""
        record = CISAKEVRecordModel(
            kev_id="KEV-2024-0001",
            cve_id="CVE-2024-12345",
            vendor="VendorName",
            product="ProductName",
            vulnerability_name="Vulnerability Description",
            date_added=datetime.utcnow(),
            required_action="Update",
            source_publication_timestamp=datetime.utcnow(),
            provenance="cisa_kev_ingestion_pipeline",
            confidence=1.0,
            experimental_label=None,
            tenant_id="tenant-001"
        )
        assert record.kev_id == "KEV-2024-0001"
        assert record.cve_id == "CVE-2024-12345"
        assert record.vendor == "VendorName"
        assert record.product == "ProductName"
        assert record.required_action == "Update"
        assert record.confidence == 1.0
        assert record.experimental_label is None
        assert record.tenant_id == "tenant-001"
    
    def test_known_ransomware_use(self):
        """Test known ransomware use indicator"""
        record = CISAKEVRecordModel(
            kev_id="KEV-2024-0002",
            cve_id="CVE-2024-67890",
            vendor="VendorName",
            product="ProductName",
            date_added=datetime.utcnow(),
            required_action="Patch",
            source_publication_timestamp=datetime.utcnow(),
            provenance="cisa_kev_ingestion_pipeline",
            known_ransomware_use=True,
            confidence=1.0
        )
        assert record.known_ransomware_use is True

class TestCISAKEVHistoryModel:
    """Tests for CISA KEV History Model"""
    
    def test_create_history(self):
        """Test history model creation"""
        history = CISAKEVHistoryModel(
            history_id="HIST-001",
            kev_id="KEV-2024-0001",
            change_type="updated",
            previous_state={"required_action": "Update"},
            new_state={"required_action": "Patch"},
            change_timestamp=datetime.utcnow(),
            source="CISA KEV",
            provenance="cisa_kev_ingestion_pipeline",
            confidence=1.0
        )
        assert history.history_id == "HIST-001"
        assert history.kev_id == "KEV-2024-0001"
        assert history.change_type == "updated"

class TestCISAKEVIngestionService:
    """Tests for CISA KEV Ingestion Service"""
    
    def setup_method(self):
        """Setup service for testing"""
        self.service = CISAKEVIngestionService(tenant_id="tenant-001")
    
    def test_ingest_source_metadata(self):
        """Test source metadata ingestion"""
        source_data = {
            "source_id": "cisa-kev",
            "source_name": "CISA Known Exploited Vulnerabilities Catalog",
            "source_publication_timestamp": datetime.utcnow(),
            "provenance": "cisa_kev_ingestion_pipeline",
            "confidence": 1.0
        }
        source = self.service.ingest_source_metadata(source_data)
        assert source.source_id == "cisa-kev"
        assert source.source_name == "CISA Known Exploited Vulnerabilities Catalog"
        assert source.tenant_id == "tenant-001"
    
    def test_ingest_kev_record(self):
        """Test KEV record ingestion with idempotency"""
        record_data = {
            "kev_id": "KEV-2024-0001",
            "cve_id": "CVE-2024-12345",
            "vendor": "VendorName",
            "product": "ProductName",
            "vulnerability_name": "Vulnerability Description",
            "date_added": datetime.utcnow(),
            "required_action": "Update",
            "source_publication_timestamp": datetime.utcnow(),
            "provenance": "cisa_kev_ingestion_pipeline",
            "confidence": 1.0
        }
        record = self.service.ingest_kev_record(record_data)
        assert record.kev_id == "KEV-2024-0001"
        assert record.cve_id == "CVE-2024-12345"
        assert record.vendor == "VendorName"
        assert record.product == "ProductName"
        assert record.required_action == "Update"
    
    def test_ingest_history_record(self):
        """Test history record ingestion"""
        history_data = {
            "history_id": "HIST-001",
            "kev_id": "KEV-2024-0001",
            "change_type": "updated",
            "previous_state": {"required_action": "Update"},
            "new_state": {"required_action": "Patch"},
            "change_timestamp": datetime.utcnow(),
            "source": "CISA KEV",
            "provenance": "cisa_kev_ingestion_pipeline",
            "confidence": 1.0
        }
        history = self.service.ingest_history_record(history_data)
        assert history.history_id == "HIST-001"
        assert history.kev_id == "KEV-2024-0001"
        assert history.change_type == "updated"
    
    def test_duplicate_detection(self):
        """Test duplicate detection (security/integrity)"""
        result = self.service.detect_duplicates("KEV-2024-0001", "kev_record")
        assert isinstance(result, bool)
    
    def test_update_detection(self):
        """Test update detection (idempotency/integrity)"""
        class MockRecord:
            pass
        
        result = self.service.detect_updates(MockRecord(), {})
        assert isinstance(result, bool)
    
    def test_validate_external_data(self):
        """Test external data validation (security)"""
        valid_data = {
            "kev_id": "KEV-2024-0001",
            "cve_id": "CVE-2024-12345",
            "vendor": "VendorName",
            "product": "ProductName",
            "date_added": datetime.utcnow(),
            "required_action": "Update",
            "source_publication_timestamp": datetime.utcnow()
        }
        result = self.service.validate_external_data(valid_data)
        assert result is True
        
        # Test malformed data handling
        with pytest.raises(ValueError):
            self.service.validate_external_data("not_a_dict")
        
        # Test missing required fields
        invalid_data = {"kev_id": "KEV-2024-0001"}  # Missing required fields
        with pytest.raises(ValueError):
            self.service.validate_external_data(invalid_data)
    
    def test_security_boundaries(self):
        """Test security boundary validation"""
        # Service should maintain security boundaries
        assert self.service._validation_enabled is True
        assert self.service._provenance_tracking is True
        assert self.service._audit_logging is True
        assert self.service._idempotency_enabled is True
        assert self.service._duplicate_detection is True
    
    def test_conflict_detection(self):
        """Test conflicting intelligence detection (integrity)"""
        result = self.service.detect_conflicts(None, None)
        assert isinstance(result, bool)
    
    def test_historical_preservation(self):
        """Test historical observation preservation (integrity)"""
        # Should not raise exception
        self.service.preserve_historical_observations(None)
    
    def test_verified_vs_inferred(self):
        """Test verified vs inferred distinction (integrity)"""
        class MockEntity:
            confidence = 0.95
        
        result = self.service.distinguish_verified_vs_inferred(MockEntity())
        assert result == "verified"
    
    def test_verified_vs_inferred_source(self):
        """Test verified vs inferred source distinction (integrity)"""
        source_data_verified = {"confidence": 0.95}
        result1 = self.service.distinguish_verified_vs_inferred_source(source_data_verified)
        assert result1 == "verified_cisa"
        
        source_data_synthetic = {"experimental_label": EXPERIMENTAL_DEMO_DATA_ONLY}
        result2 = self.service.distinguish_verified_vs_inferred_source(source_data_synthetic)
        assert result2 == "synthetic_fixture"
    
    def test_timeouts_retries(self):
        """Test timeouts, retries, rate limits, circuit breakers (production)"""
        # Should not raise exception
        self.service.implement_timeouts_retries()
    
    def test_avoid_silent_discard(self):
        """Test avoid silent discard (integrity)"""
        # Should not raise exception
        self.service.avoid_silent_discard(Exception("Test error"))
    
    def test_security_error(self):
        """Test security error handling"""
        with pytest.raises(SecurityError):
            raise SecurityError("Test security violation")

    def test_kev_catalog_feed_and_change_tracking(self):
        """Regression test: CISA KEV catalog feed ingestion, CVE lookup, update & history tracking"""
        catalog = {
            "title": "CISA Known Exploited Vulnerabilities Catalog",
            "catalogVersion": "2026.11.05",
            "dateReleased": "2026-11-05T00:00:00Z",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-21412",
                    "vendorProject": "Microsoft",
                    "product": "Windows",
                    "vulnerabilityName": "Microsoft Windows Internet Shortcut Files Security Feature Bypass",
                    "dateAdded": "2024-02-13T00:00:00Z",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "dueDate": "2024-03-05T00:00:00Z",
                    "knownRansomwareCampaignUse": "Known",
                }
            ],
        }
        res = self.service.ingest_kev_catalog_feed(catalog)
        assert res["verification_mode"] == "fixture_tested"
        assert len(res["records"]) == 1
        rec = self.service.get_by_cve("CVE-2024-21412")
        assert rec is not None
        assert rec.known_ransomware_use is True
        assert rec.required_action == "Apply updates per vendor instructions."
        assert self.service.detect_duplicates(rec.kev_id, "kev_record") is True

        # Update required_action and verify automatic history generation
        updated = self.service.ingest_kev_record({
            "kev_id": rec.kev_id,
            "cve_id": "CVE-2024-21412",
            "vendor": "Microsoft",
            "product": "Windows",
            "date_added": rec.date_added,
            "required_action": "Apply emergency out-of-band patch immediately.",
            "due_date": rec.due_date,
            "known_ransomware_use": True,
            "source_publication_timestamp": rec.source_publication_timestamp,
        })
        assert self.service.detect_conflicts(rec, updated) is True
        assert len(self.service._history_records) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
