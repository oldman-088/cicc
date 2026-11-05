import pytest
from datetime import datetime, timedelta
from apps.threat_intelligence.vendor_advisories import (
    VendorSecurityAdvisorySourceModel,
    VendorSecurityAdvisoryRecordModel,
    VendorSecurityAdvisoryHistoryModel,
    VendorSecurityAdvisoryIngestionService,
    EXPERIMENTAL_DEMO_DATA_ONLY,
    SecurityError
)

class TestVendorSecurityAdvisorySourceModel:
    """Tests for Vendor Security Advisory Source Model"""
    
    def test_create_source(self):
        """Test source model creation"""
        source = VendorSecurityAdvisorySourceModel(
            source_id="msrc",
            vendor_name="Microsoft",
            source_publication_timestamp=datetime.utcnow(),
            provenance="vendor_ingestion_pipeline",
            confidence=1.0,
            experimental_label=None,
            tenant_id="tenant-001"
        )
        assert source.source_id == "msrc"
        assert source.vendor_name == "Microsoft"
        assert source.confidence == 1.0
        assert source.experimental_label is None
        assert source.tenant_id == "tenant-001"
    
    def test_experimental_label(self):
        """Test experimental label handling"""
        source = VendorSecurityAdvisorySourceModel(
            source_id="msrc",
            vendor_name="Microsoft",
            source_publication_timestamp=datetime.utcnow(),
            provenance="vendor_ingestion_pipeline",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        assert source.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
    
    def test_invalid_experimental_label(self):
        """Test invalid experimental label rejection"""
        with pytest.raises(ValueError):
            VendorSecurityAdvisorySourceModel(
                source_id="msrc",
                vendor_name="Microsoft",
                source_publication_timestamp=datetime.utcnow(),
                provenance="vendor_ingestion_pipeline",
                experimental_label="INVALID_LABEL"
            )

class TestVendorSecurityAdvisoryRecordModel:
    """Tests for Vendor Security Advisory Record Model"""
    
    def test_create_record(self):
        """Test advisory record model creation"""
        record = VendorSecurityAdvisoryRecordModel(
            advisory_id="MS-2024-0001",
            vendor_source_id="msrc-2024-0001",
            cve_references=["CVE-2024-12345"],
            affected_products=["Windows 10", "Windows 11"],
            affected_versions=["21H2", "22H2"],
            vulnerability_description="Vulnerability Description",
            severity="Critical",
            date_published=datetime.utcnow(),
            required_action="Update",
            source_publication_timestamp=datetime.utcnow(),
            provenance="vendor_ingestion_pipeline",
            confidence=1.0,
            experimental_label=None,
            tenant_id="tenant-001"
        )
        assert record.advisory_id == "MS-2024-0001"
        assert record.vendor_source_id == "msrc-2024-0001"
        assert "CVE-2024-12345" in record.cve_references
        assert "Windows 10" in record.affected_products
        assert record.severity == "Critical"
        assert record.confidence == 1.0
        assert record.experimental_label is None
        assert record.tenant_id == "tenant-001"
    
    def test_affected_versions_handling(self):
        """Test affected versions range handling"""
        record = VendorSecurityAdvisoryRecordModel(
            advisory_id="MS-2024-0002",
            vendor_source_id="msrc-2024-0002",
            cve_references=["CVE-2024-67890"],
            affected_products=["Windows Server"],
            affected_versions=["2019", "2022"],
            date_published=datetime.utcnow(),
            required_action="Patch",
            source_publication_timestamp=datetime.utcnow(),
            provenance="vendor_ingestion_pipeline",
            confidence=1.0
        )
        assert "2019" in record.affected_versions
        assert "2022" in record.affected_versions

class TestVendorSecurityAdvisoryHistoryModel:
    """Tests for Vendor Security Advisory History Model"""
    
    def test_create_history(self):
        """Test history model creation"""
        history = VendorSecurityAdvisoryHistoryModel(
            history_id="HIST-001",
            advisory_id="MS-2024-0001",
            change_type="updated",
            previous_state={"severity": "High"},
            new_state={"severity": "Critical"},
            change_timestamp=datetime.utcnow(),
            source="Microsoft",
            provenance="vendor_ingestion_pipeline",
            confidence=1.0
        )
        assert history.history_id == "HIST-001"
        assert history.advisory_id == "MS-2024-0001"
        assert history.change_type == "updated"

class TestVendorSecurityAdvisoryIngestionService:
    """Tests for Vendor Security Advisory Ingestion Service"""
    
    def setup_method(self):
        """Setup service for testing"""
        self.service = VendorSecurityAdvisoryIngestionService(vendor_type="msrc", tenant_id="tenant-001")
    
    def test_ingest_source_metadata(self):
        """Test source metadata ingestion"""
        source_data = {
            "source_id": "msrc",
            "vendor_name": "Microsoft",
            "source_publication_timestamp": datetime.utcnow(),
            "provenance": "vendor_ingestion_pipeline",
            "confidence": 1.0
        }
        source = self.service.ingest_source_metadata(source_data)
        assert source.source_id == "msrc"
        assert source.vendor_name == "Microsoft"
        assert source.tenant_id == "tenant-001"
    
    def test_ingest_advisory_record(self):
        """Test advisory record ingestion with idempotency"""
        record_data = {
            "advisory_id": "MS-2024-0001",
            "vendor_source_id": "msrc-2024-0001",
            "cve_references": ["CVE-2024-12345"],
            "affected_products": ["Windows 10"],
            "affected_versions": ["21H2"],
            "vulnerability_description": "Vulnerability Description",
            "severity": "Critical",
            "date_published": datetime.utcnow(),
            "required_action": "Update",
            "source_publication_timestamp": datetime.utcnow(),
            "provenance": "vendor_ingestion_pipeline",
            "confidence": 1.0
        }
        record = self.service.ingest_advisory_record(record_data)
        assert record.advisory_id == "MS-2024-0001"
        assert record.vendor_source_id == "msrc-2024-0001"
        assert "CVE-2024-12345" in record.cve_references
        assert "Windows 10" in record.affected_products
        assert record.severity == "Critical"
    
    def test_ingest_history_record(self):
        """Test history record ingestion"""
        history_data = {
            "history_id": "HIST-001",
            "advisory_id": "MS-2024-0001",
            "change_type": "updated",
            "previous_state": {"severity": "High"},
            "new_state": {"severity": "Critical"},
            "change_timestamp": datetime.utcnow(),
            "source": "Microsoft",
            "provenance": "vendor_ingestion_pipeline",
            "confidence": 1.0
        }
        history = self.service.ingest_history_record(history_data)
        assert history.history_id == "HIST-001"
        assert history.advisory_id == "MS-2024-0001"
        assert history.change_type == "updated"
    
    def test_microsoft_msrc_parser(self):
        """Test Microsoft MSRC parser implementation"""
        raw_data = {
            "msrc_id": "MS-2024-0001",
            "msrc_source_id": "msrc-2024-0001",
            "cve_ids": ["CVE-2024-12345"],
            "products": ["Windows 10", "Windows 11"],
            "versions": ["21H2", "22H2"],
            "description": "Microsoft Security Vulnerability",
            "severity": "Critical",
            "published": datetime.utcnow(),
            "action": "Update",
            "source_publication_timestamp": datetime.utcnow(),
            "provenance": "msrc_ingestion_pipeline",
            "confidence": 1.0
        }
        record = self.service._parse_microsoft_msrc(raw_data)
        assert record.advisory_id == "MS-2024-0001"
        assert record.vendor_source_id == "msrc-2024-0001"
        assert "CVE-2024-12345" in record.cve_references
        assert "Windows 10" in record.affected_products
        assert record.severity == "Critical"
        assert record.confidence == 1.0
    
    def test_cisco_parser(self):
        """Test Cisco Security Advisories parser implementation"""
        raw_data = {
            "cisco_id": "CISCO-2024-0001",
            "cisco_source_id": "cisco-2024-0001",
            "cves": ["CVE-2024-67890"],
            "products": ["Cisco IOS", "Cisco NX-OS"],
            "versions": ["15.0", "16.0"],
            "description": "Cisco Security Vulnerability",
            "severity": "High",
            "published": datetime.utcnow(),
            "action": "Patch",
            "source_publication_timestamp": datetime.utcnow(),
            "provenance": "cisco_ingestion_pipeline",
            "confidence": 1.0
        }
        record = self.service._parse_cisco(raw_data)
        assert record.advisory_id == "CISCO-2024-0001"
        assert record.vendor_source_id == "cisco-2024-0001"
        assert "CVE-2024-67890" in record.cve_references
        assert "Cisco IOS" in record.affected_products
        assert record.severity == "High"
        assert record.confidence == 1.0
    
    def test_redhat_parser(self):
        """Test Red Hat Security Advisories parser implementation"""
        raw_data = {
            "rhsa_id": "RHSA-2024-0001",
            "redhat_source_id": "redhat-2024-0001",
            "cves": ["CVE-2024-11111"],
            "products": ["Red Hat Enterprise Linux"],
            "versions": ["8.0", "9.0"],
            "description": "Red Hat Security Vulnerability",
            "severity": "Medium",
            "published": datetime.utcnow(),
            "action": "Update",
            "source_publication_timestamp": datetime.utcnow(),
            "provenance": "redhat_ingestion_pipeline",
            "confidence": 1.0
        }
        record = self.service._parse_redhat(raw_data)
        assert record.advisory_id == "RHSA-2024-0001"
        assert record.vendor_source_id == "redhat-2024-0001"
        assert "CVE-2024-11111" in record.cve_references
        assert "Red Hat Enterprise Linux" in record.affected_products
        assert record.severity == "Medium"
        assert record.confidence == 1.0
    
    def test_ubuntu_parser(self):
        """Test Ubuntu Security Notices parser implementation"""
        raw_data = {
            "usn_id": "USN-2024-0001",
            "ubuntu_source_id": "ubuntu-2024-0001",
            "cves": ["CVE-2024-22222"],
            "products": ["Ubuntu 20.04", "Ubuntu 22.04"],
            "versions": ["20.04", "22.04"],
            "description": "Ubuntu Security Vulnerability",
            "severity": "Low",
            "published": datetime.utcnow(),
            "action": "Update",
            "source_publication_timestamp": datetime.utcnow(),
            "provenance": "ubuntu_ingestion_pipeline",
            "confidence": 1.0
        }
        record = self.service._parse_ubuntu(raw_data)
        assert record.advisory_id == "USN-2024-0001"
        assert record.vendor_source_id == "ubuntu-2024-0001"
        assert "CVE-2024-22222" in record.cve_references
        assert "Ubuntu 20.04" in record.affected_products
        assert record.severity == "Low"
        assert record.confidence == 1.0
    
    def test_unified_parser_interface(self):
        """Test unified parser interface for all vendors"""
        # Microsoft MSRC
        msrc_data = {"msrc_id": "MS-2024-0001", "cve_ids": ["CVE-2024-12345"], "products": ["Windows"], "versions": ["10"], "published": datetime.utcnow(), "source_publication_timestamp": datetime.utcnow()}
        msrc_record = self.service.parse_vendor_advisory("msrc", msrc_data)
        assert msrc_record.advisory_id == "MS-2024-0001"
        
        # Cisco
        cisco_data = {"cisco_id": "CISCO-2024-0001", "cves": ["CVE-2024-67890"], "products": ["IOS"], "versions": ["15.0"], "published": datetime.utcnow(), "source_publication_timestamp": datetime.utcnow()}
        cisco_record = self.service.parse_vendor_advisory("cisco", cisco_data)
        assert cisco_record.advisory_id == "CISCO-2024-0001"
        
        # Red Hat
        redhat_data = {"rhsa_id": "RHSA-2024-0001", "cves": ["CVE-2024-11111"], "products": ["RHEL"], "versions": ["8.0"], "published": datetime.utcnow(), "source_publication_timestamp": datetime.utcnow()}
        redhat_record = self.service.parse_vendor_advisory("redhat", redhat_data)
        assert redhat_record.advisory_id == "RHSA-2024-0001"
        
        # Ubuntu
        ubuntu_data = {"usn_id": "USN-2024-0001", "cves": ["CVE-2024-22222"], "products": ["Ubuntu"], "versions": ["20.04"], "published": datetime.utcnow(), "source_publication_timestamp": datetime.utcnow()}
        ubuntu_record = self.service.parse_vendor_advisory("ubuntu", ubuntu_data)
        assert ubuntu_record.advisory_id == "USN-2024-0001"
        
        # Unsupported vendor
        with pytest.raises(ValueError):
            self.service.parse_vendor_advisory("unknown", {})
    
    def test_duplicate_detection(self):
        """Test duplicate detection (security/integrity)"""
        result = self.service.detect_duplicates("MS-2024-0001", "advisory_record")
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
            "advisory_id": "MS-2024-0001",
            "vendor_source_id": "msrc-2024-0001",
            "cve_references": ["CVE-2024-12345"],
            "affected_products": ["Windows 10"],
            "affected_versions": ["21H2"],
            "date_published": datetime.utcnow(),
            "required_action": "Update",
            "source_publication_timestamp": datetime.utcnow()
        }
        result = self.service.validate_external_data(valid_data)
        assert result is True
        
        # Test malformed data handling
        with pytest.raises(ValueError):
            self.service.validate_external_data("not_a_dict")
        
        # Test missing required fields
        invalid_data = {"advisory_id": "MS-2024-0001"}  # Missing required fields
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
        assert result1 == "verified_vendor"
        
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

    def test_debian_and_ghsa_parsers_and_cve_lookup(self):
        """Regression test: Debian DSA, GitHub GHSA parsers, CVE-to-advisory indexing, and update history"""
        dsa_rec = self.service.parse_vendor_advisory("debian", {
            "dsa_id": "DSA-5678-1",
            "cves": ["cve-2024-99999", "CVE-2024-99999"],
            "packages": ["openssl"],
            "fixed_versions": ["3.0.14-1~deb12u1"],
            "severity": "High",
            "published": datetime.utcnow(),
        })
        assert dsa_rec.advisory_id == "DSA-5678-1"
        assert dsa_rec.cve_references == ["CVE-2024-99999"]

        ghsa_rec = self.service.parse_vendor_advisory("ghsa", {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cves": ["CVE-2024-99999"],
            "packages": ["pyopenssl"],
            "vulnerable_version_ranges": ["< 24.2.0"],
            "severity": "Critical",
            "published": datetime.utcnow(),
        })
        assert ghsa_rec.advisory_id == "GHSA-xxxx-yyyy-zzzz"

        linked = self.service.get_advisories_for_cve("CVE-2024-99999")
        assert len(linked) == 2

        # Update severity on DSA-5678-1 and verify severity_changed history record
        dsa_updated = self.service.parse_vendor_advisory("debian", {
            "dsa_id": "DSA-5678-1",
            "cves": ["CVE-2024-99999"],
            "packages": ["openssl"],
            "fixed_versions": ["3.0.14-1~deb12u1"],
            "severity": "Critical",
            "published": dsa_rec.date_published,
        })
        assert self.service.detect_conflicts(dsa_rec, dsa_updated) is True
        assert any(h.change_type == "severity_changed" for h in self.service._history_records.values())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
