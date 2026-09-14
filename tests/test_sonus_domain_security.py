import unittest

from deep_tests.security_model import BoundaryViolation, normalize_relative_path, validate_outbound_url


class SonusDomainSecurityTests(unittest.TestCase):
    def test_audio_segment_paths_reject_encoded_escape(self) -> None:
        for value in ("segments/%2e%2e/key", "fft/%252E%252E/secret", "%2e%2E/audio.raw"):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                normalize_relative_path(value)

    def test_audio_upload_urls_reject_authority_confusion(self) -> None:
        allowed = {"audio.example.test"}
        for value in (
            "//audio.example.test/upload",
            "https://audio.example.test@attacker.invalid/upload",
            "https://attacker.invalid/audio.example.test/upload",
        ):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                validate_outbound_url(value, allowed)


if __name__ == "__main__":
    unittest.main()
