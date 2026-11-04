"""Configuration and credential handling.

Every test here that looks paranoid is guarding a specific historical incident
class: a key in a traceback, a key in a startup log, a deployment typo that
silently reverts to a default, or a demo deployment that starts pulling real
provider data because a key happened to be set.
"""

from __future__ import annotations

import json
import logging
import traceback
from datetime import timedelta

import pytest

from vuln_intel.config import (
    ENV_PREFIX,
    ENV_VARS,
    Secret,
    Settings,
    redact_environment,
)
from vuln_intel.errors import ValidationError
from vuln_intel.schema import Origin

KEY = "9f2c1d7e-4b3a-4c5d-8e9f-0a1b2c3d4e5f"


class TestSecretNeverRenders:
    def test_repr_str_and_format_are_masked(self):
        secret = Secret(KEY)
        assert KEY not in repr(secret)
        assert KEY not in str(secret)
        assert KEY not in f"{secret}"
        assert KEY not in "{}".format(secret)  # noqa: UP032 - testing .format
        assert KEY not in f"{secret:>40}"

    def test_container_rendering_is_masked(self):
        secret = Secret(KEY)
        assert KEY not in repr([secret])
        assert KEY not in repr({"api_key": secret})
        assert KEY not in str({"api_key": secret})

    def test_traceback_does_not_contain_the_value(self):
        secret = Secret(KEY)
        try:
            raise RuntimeError(f"connection failed for {secret}")
        except RuntimeError:
            rendered = traceback.format_exc()
        assert KEY not in rendered

    def test_log_output_does_not_contain_the_value(self, caplog):
        secret = Secret(KEY)
        with caplog.at_level(logging.DEBUG):
            logging.getLogger("cicc").debug("using key %s", secret)
        assert KEY not in caplog.text

    def test_json_serialisation_does_not_contain_the_value(self):
        payload = json.dumps({"api_key": str(Secret(KEY))})
        assert KEY not in payload

    def test_reveal_is_the_only_way_to_get_the_value(self):
        assert Secret(KEY).reveal() == KEY

    def test_truthiness_reflects_presence(self):
        assert Secret(KEY)
        assert not Secret()

    def test_empty_secret_renders_empty_not_masked(self):
        assert str(Secret()) == ""
        assert "unset" in repr(Secret())


class TestSettingsFromEnvironment:
    def test_defaults_are_safe(self):
        settings = Settings.from_env({})
        assert settings.live_collection is False
        assert settings.epss_enabled is False
        assert settings.origin is Origin.LIVE
        assert settings.nvd_page_size == 200

    def test_documented_variables_are_all_readable(self):
        """Every documented variable must actually be honoured."""
        env = {
            ENV_PREFIX + "LIVE_COLLECTION": "true",
            ENV_PREFIX + "NVD_API_KEY": KEY,
            ENV_PREFIX + "NVD_PAGE_SIZE": "50",
            ENV_PREFIX + "NVD_MAX_PAGES": "3",
            ENV_PREFIX + "HTTP_TIMEOUT": "12.5",
            ENV_PREFIX + "KEV_MAX_AGE_DAYS": "5",
            ENV_PREFIX + "EPSS_ENABLED": "true",
            ENV_PREFIX + "CHECKPOINT_PATH": "/var/lib/cicc/ckpt.json",
            ENV_PREFIX + "ORIGIN": "live",
            ENV_PREFIX + "TENANT_ID": "tenant-a",
        }
        settings = Settings.from_env(env)
        assert settings.live_collection is True
        assert settings.nvd_api_key.reveal() == KEY
        assert settings.nvd_page_size == 50
        assert settings.nvd_max_pages == 3
        assert settings.http_timeout == 12.5
        assert settings.kev_max_age == timedelta(days=5)
        assert settings.epss_enabled is True
        assert settings.checkpoint_path is not None
        assert settings.tenant_id == "tenant-a"
        # Documented set and implemented set must not drift apart.
        for name in ENV_VARS:
            assert ENV_PREFIX + name in env

    @pytest.mark.parametrize("raw", ["true", "TRUE", "1", "yes", "on"])
    def test_boolean_truthy_spellings(self, raw):
        assert Settings.from_env({ENV_PREFIX + "EPSS_ENABLED": raw}).epss_enabled is True

    @pytest.mark.parametrize("raw", ["false", "FALSE", "0", "no", "off"])
    def test_boolean_falsey_spellings(self, raw):
        assert Settings.from_env({ENV_PREFIX + "EPSS_ENABLED": raw}).epss_enabled is False

    def test_invalid_boolean_names_the_variable(self):
        with pytest.raises(ValidationError) as excinfo:
            Settings.from_env({ENV_PREFIX + "EPSS_ENABLED": "maybe"})
        assert "EPSS_ENABLED" in str(excinfo.value)

    def test_misspelled_variable_is_unknown_not_silently_applied(self):
        # A typo must not take effect *and* must not be silently dropped.
        settings = Settings.from_env({ENV_PREFIX + "EPS_ENABLED": "true"})
        assert settings.epss_enabled is False
        assert settings.unknown

    def test_out_of_range_page_size_is_rejected(self):
        with pytest.raises(ValidationError):
            Settings.from_env({ENV_PREFIX + "NVD_PAGE_SIZE": "0"})
        with pytest.raises(ValidationError):
            Settings.from_env({ENV_PREFIX + "NVD_PAGE_SIZE": "2001"})

    def test_non_integer_value_does_not_echo_the_value(self):
        """A mistyped credential pasted into the wrong variable must not surface."""
        with pytest.raises(ValidationError) as excinfo:
            Settings.from_env({ENV_PREFIX + "NVD_PAGE_SIZE": KEY})
        assert KEY not in str(excinfo.value)

    def test_invalid_origin_is_rejected(self):
        with pytest.raises(ValidationError):
            Settings.from_env({ENV_PREFIX + "ORIGIN": "production-ish"})

    def test_unknown_variables_are_reported_not_swallowed(self):
        settings = Settings.from_env({ENV_PREFIX + "NVD_APIKEY": KEY})
        assert settings.unknown == (ENV_PREFIX + "NVD_APIKEY",)
        assert any("unrecognised" in w for w in settings.warnings())

    def test_strict_mode_rejects_unknown_variables(self):
        with pytest.raises(ValidationError):
            Settings.from_env({ENV_PREFIX + "TYPO": "x"}, strict=True)

    def test_unrelated_environment_variables_are_ignored(self):
        settings = Settings.from_env({"PATH": "/usr/bin", "HOME": "/root"})
        assert settings.unknown == ()


class TestUnsafeCombinations:
    def test_live_collection_with_a_demo_origin_is_refused(self):
        """Collecting real data while labelling it demo would misrepresent it."""
        with pytest.raises(ValidationError) as excinfo:
            Settings.from_env(
                {
                    ENV_PREFIX + "LIVE_COLLECTION": "true",
                    ENV_PREFIX + "ORIGIN": "fixture",
                }
            )
        assert "ORIGIN" in str(excinfo.value)

    def test_implausibly_short_api_key_is_rejected(self):
        with pytest.raises(ValidationError):
            Settings.from_env(
                {ENV_PREFIX + "LIVE_COLLECTION": "true", ENV_PREFIX + "NVD_API_KEY": "abc"}
            )

    def test_require_live_refuses_when_disabled(self):
        with pytest.raises(ValidationError) as excinfo:
            Settings.from_env({}).require_live()
        assert "LIVE_COLLECTION" in str(excinfo.value)

    def test_require_live_passes_when_enabled(self):
        Settings.from_env({ENV_PREFIX + "LIVE_COLLECTION": "1"}).require_live()


class TestDescribeAndRedact:
    def test_describe_masks_the_key_and_is_json_safe(self):
        settings = Settings.from_env(
            {ENV_PREFIX + "LIVE_COLLECTION": "true", ENV_PREFIX + "NVD_API_KEY": KEY}
        )
        described = settings.describe()
        assert KEY not in json.dumps(described)
        assert described["nvd_api_key"] == "***"

    def test_describe_shows_unset_explicitly(self):
        assert Settings.from_env({}).describe()["nvd_api_key"] == "(unset)"

    def test_redact_environment_masks_only_our_secret(self):
        redacted = redact_environment(
            {ENV_PREFIX + "NVD_API_KEY": KEY, ENV_PREFIX + "TENANT_ID": "t1", "PATH": "/bin"}
        )
        assert redacted[ENV_PREFIX + "NVD_API_KEY"] == "***"
        assert redacted[ENV_PREFIX + "TENANT_ID"] == "t1"
        assert "PATH" not in redacted

    def test_no_key_warning_when_key_present(self):
        settings = Settings.from_env(
            {ENV_PREFIX + "LIVE_COLLECTION": "1", ENV_PREFIX + "NVD_API_KEY": KEY}
        )
        assert not any("no NVD API key" in w for w in settings.warnings())

    def test_throughput_warning_when_live_without_a_key(self):
        settings = Settings.from_env({ENV_PREFIX + "LIVE_COLLECTION": "1"})
        assert any("5 requests/30s" in w for w in settings.warnings())

    def test_disabled_notice_is_stated(self):
        assert any("disabled" in w for w in Settings.from_env({}).warnings())
