import contextlib
import io
import unittest
import urllib.error
from unittest.mock import patch

import proto_pollute


class FakeResponse:
    def __init__(self, body, status=200):
        self.body = body.encode()
        self.status = status
        self.read_limit = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self, limit):
        self.read_limit = limit
        return self.body[:limit]


class URLValidationTests(unittest.TestCase):
    def test_accepts_absolute_http_and_https_urls(self):
        self.assertEqual(
            proto_pollute.validate_url("http://localhost/api"),
            "http://localhost/api",
        )
        self.assertEqual(
            proto_pollute.validate_url("https://example.test/api"),
            "https://example.test/api",
        )

    def test_rejects_invalid_or_oversized_urls(self):
        credential_url = "http://" + "user" + ":" + "pass" + "@example.test/"
        invalid_urls = (
            "example.test/api",
            "ftp://example.test/api",
            "http:///missing-host",
            "http://user:pass@example.test/",
            "http://[invalid/",
            "http://example.test/has space",
            "http://example.test/\n",
            "http://example.test/" + "x" * proto_pollute.MAX_URL_LENGTH,
            credential_url,
        )
        for url in invalid_urls:
            with self.subTest(url=url[:40]):
                with self.assertRaises(ValueError):
                    proto_pollute.validate_url(url)

    def test_timeout_must_be_finite_and_bounded(self):
        for timeout in (0, -1, 60.1, float("inf"), float("nan")):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    proto_pollute.validate_timeout(timeout)
        self.assertEqual(proto_pollute.validate_timeout(0.1), 0.1)
        self.assertEqual(proto_pollute.validate_timeout(60), 60)


class ProbeTests(unittest.TestCase):
    def test_reflection_is_reported_as_heuristic_and_response_is_bounded(self):
        response = FakeResponse("marker")
        with patch.object(proto_pollute.urllib.request, "urlopen", return_value=response) as urlopen, \
             patch.object(proto_pollute, "rand_marker", return_value="marker"), \
             contextlib.redirect_stdout(io.StringIO()):
            results = proto_pollute.test_json_pollution("http://localhost/api", {}, 2)

        self.assertEqual(len(results), 4)
        self.assertTrue(
            all(item["classification"] == "heuristic_candidate" for item in results)
        )
        self.assertTrue(all("vulnerable" not in item for item in results))
        self.assertEqual(response.read_limit, proto_pollute.MAX_RESPONSE_BYTES)
        self.assertEqual(urlopen.call_count, 4)

    def test_query_probes_preserve_fragment_and_bound_generated_url(self):
        response = FakeResponse("markeraaa")
        with patch.object(proto_pollute.urllib.request, "urlopen", return_value=response) as urlopen, \
             patch.object(
                 proto_pollute,
                 "rand_marker",
                 side_effect=["markeraaa", "keyaaaaa"] * 3,
             ):
            results = proto_pollute.test_qs_pollution(
                "http://localhost/api?old=1#section", {}, 2
            )

        probe_url = urlopen.call_args.args[0].full_url
        parsed = proto_pollute.urllib.parse.urlsplit(probe_url)
        self.assertEqual(parsed.fragment, "section")
        self.assertTrue(parsed.query.startswith("old=1&__proto__"))
        self.assertLessEqual(len(probe_url), proto_pollute.MAX_URL_LENGTH)
        self.assertEqual(len(results), 3)
        self.assertTrue(
            all(item["classification"] == "heuristic_candidate" for item in results)
        )
        self.assertTrue(all("vulnerable" not in item for item in results))

    def test_query_probe_url_limit_is_checked_before_request(self):
        prefix = "http://localhost/"
        url = prefix + "a" * (proto_pollute.MAX_URL_LENGTH - len(prefix) - 1)
        with patch.object(proto_pollute.urllib.request, "urlopen") as urlopen:
            with self.assertRaisesRegex(ValueError, "query probe URL exceeds"):
                proto_pollute.test_qs_pollution(url, {}, 2)
        urlopen.assert_not_called()

    def test_network_failures_are_not_suppressed(self):
        with patch.object(
            proto_pollute.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("offline"),
        ):
            with self.assertRaises(urllib.error.URLError):
                proto_pollute.test_qs_pollution("http://localhost/api", {}, 2)

    def test_cli_reports_invalid_url_without_making_a_request(self):
        stderr = io.StringIO()
        with patch.object(proto_pollute.urllib.request, "urlopen") as urlopen, \
             contextlib.redirect_stderr(stderr):
            status = proto_pollute.main(["file:///etc/passwd"])

        self.assertEqual(status, 2)
        self.assertIn("Assessment failed", stderr.getvalue())
        urlopen.assert_not_called()

    def test_cli_reports_network_failure_with_nonzero_status(self):
        stderr = io.StringIO()
        with patch.object(
            proto_pollute.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("offline"),
        ), contextlib.redirect_stderr(stderr):
            status = proto_pollute.main(["http://localhost/api"])

        self.assertEqual(status, 2)
        self.assertIn("Assessment failed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
