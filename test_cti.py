#!/usr/bin/env python3
"""
Unit tests for cti.py - ThreatFeed Collector
Refactored version following t_wada's testing methodology
"""

import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
import sys
import os

# Add the parent directory to the path to import cti
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cti


class TestIsRecent(unittest.TestCase):
    """Test cases for is_recent function"""

    def setUp(self):
        self.cutoff_date = datetime(2024, 1, 1, 0, 0, 0)

    def test_should_return_true_when_date_is_after_cutoff(self):
        """Recent date should return True"""
        result = cti.is_recent("2024-01-02T00:00:00Z", self.cutoff_date)
        self.assertTrue(result)

    def test_should_return_false_when_date_is_before_cutoff(self):
        """Old date should return False"""
        result = cti.is_recent("2023-12-31T23:59:59Z", self.cutoff_date)
        self.assertFalse(result)

    def test_should_return_true_when_date_equals_cutoff(self):
        """Date equal to cutoff should return True"""
        result = cti.is_recent("2024-01-01T00:00:00Z", self.cutoff_date)
        self.assertTrue(result)

    def test_should_return_true_when_date_is_invalid(self):
        """Invalid date should return True (default behavior)"""
        for invalid_date in ["", None, "invalid-date"]:
            with self.subTest(invalid_date=invalid_date):
                result = cti.is_recent(invalid_date, self.cutoff_date)
                self.assertTrue(result)

    def test_should_handle_timezone_aware_dates(self):
        """Timezone aware dates should be handled correctly"""
        result = cti.is_recent("2024-01-02T00:00:00+09:00", self.cutoff_date)
        self.assertTrue(result)


class TestIsIPv4Strict(unittest.TestCase):
    """Test cases for is_ipv4_strict function"""

    def test_should_return_true_for_global_public_ip(self):
        """Public global IP should return True"""
        result = cti.is_ipv4_strict("8.8.8.8")
        self.assertTrue(result)

    def test_should_return_false_for_private_ips(self):
        """Private IPs should return False"""
        private_ips = ["10.0.0.1", "192.168.1.1", "172.16.1.1", "127.0.0.1"]
        for ip in private_ips:
            with self.subTest(ip=ip):
                result = cti.is_ipv4_strict(ip)
                self.assertFalse(result)

    def test_should_return_false_for_special_ips(self):
        """Special purpose IPs should return False"""
        special_ips = ["169.254.1.1", "256.256.256.256", "not.an.ip.address"]
        for ip in special_ips:
            with self.subTest(ip=ip):
                result = cti.is_ipv4_strict(ip)
                self.assertFalse(result)


class TestIsSuspiciousDomain(unittest.TestCase):
    """Test cases for is_suspicious_domain function"""

    @patch.object(cti.WARNING_LIST, 'search', return_value=False)
    def test_should_return_true_for_unknown_domain(self, mock_search):
        """Unknown domain should return True"""
        result = cti.is_suspicious_domain("malicious-site.com")
        self.assertTrue(result)

    @patch.object(cti.WARNING_LIST, 'search', return_value=False)
    def test_should_return_false_for_common_domains(self, mock_search):
        """Common domains should return False"""
        common_domains = ["google.com", "microsoft.com", "mail.google.com", "GOOGLE.COM"]
        for domain in common_domains:
            with self.subTest(domain=domain):
                result = cti.is_suspicious_domain(domain)
                self.assertFalse(result)

    @patch.object(cti.WARNING_LIST, 'search', return_value=True)
    def test_should_return_false_for_warning_list_domain(self, mock_search):
        """Domain in warning list should return False"""
        result = cti.is_suspicious_domain("example.com")
        self.assertFalse(result)


class TestIsSuspiciousUrl(unittest.TestCase):
    """Test cases for is_suspicious_url function"""

    @patch.object(cti.WARNING_LIST, 'search', return_value=False)
    def test_should_return_true_for_unknown_url(self, mock_search):
        """URL with unknown domain should return True"""
        result = cti.is_suspicious_url("https://malicious-site.com/path")
        self.assertTrue(result)

    @patch.object(cti.WARNING_LIST, 'search', return_value=False)
    def test_should_return_false_for_common_domain_urls(self, mock_search):
        """URLs with common domains should return False"""
        common_urls = ["https://www.google.com/search", "https://github.com/user/repo"]
        for url in common_urls:
            with self.subTest(url=url):
                result = cti.is_suspicious_url(url)
                self.assertFalse(result)

    @patch.object(cti.WARNING_LIST, 'search', return_value=True)
    def test_should_return_false_for_warning_list_url(self, mock_search):
        """URL in warning list should return False"""
        result = cti.is_suspicious_url("https://malicious-site.com/path")
        self.assertFalse(result)


class TestIsValidUrl(unittest.TestCase):
    """Test cases for is_valid_url function"""

    def test_should_return_true_for_valid_urls(self):
        """Valid URLs should return True"""
        valid_urls = ["http://example.com", "https://example.com/path", "ftp://example.com/file"]
        for url in valid_urls:
            with self.subTest(url=url):
                result = cti.is_valid_url(url)
                self.assertTrue(result)

    def test_should_return_false_for_invalid_urls(self):
        """Invalid URLs should return False"""
        invalid_urls = ["https://redacted.com", "https://localhost", "invalid://example.com", "not-a-url"]
        for url in invalid_urls:
            with self.subTest(url=url):
                result = cti.is_valid_url(url)
                self.assertFalse(result)


class TestExtractIOCs(unittest.TestCase):
    """Test cases for extract_iocs function"""

    @patch.object(cti, 'is_suspicious_url', return_value=True)
    @patch.object(cti, 'is_valid_url', return_value=True)
    def test_should_extract_urls_from_text(self, mock_valid_url, mock_suspicious_url):
        """Should extract valid suspicious URLs from text"""
        text = "Visit https://malicious-site.com for more info"
        result = cti.extract_iocs(text)
        self.assertIn("https://malicious-site.com", result['urls'])

    @patch.object(cti, 'is_ipv4_strict', return_value=True)
    def test_should_extract_ip_addresses_from_text(self, mock_ipv4):
        """Should extract valid public IP addresses from text"""
        text = "Connect to 8.8.8.8 for DNS"
        result = cti.extract_iocs(text)
        self.assertIn("8.8.8.8", result['ips'])

    def test_should_extract_hashes_from_text(self):
        """Should extract valid hashes from text"""
        text = "File hash: d41d8cd98f00b204e9800998ecf8427e (MD5)"
        result = cti.extract_iocs(text)
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", result['hashes'])

    def test_should_return_empty_sets_for_invalid_input(self):
        """Should return empty sets when input is invalid"""
        for invalid_input in [None, ""]:
            with self.subTest(input=invalid_input):
                result = cti.extract_iocs(invalid_input)
                self.assertEqual(len(result['urls']), 0)
                self.assertEqual(len(result['ips']), 0)
                self.assertEqual(len(result['fqdns']), 0)
                self.assertEqual(len(result['hashes']), 0)

    def test_should_filter_invalid_hash_lengths(self):
        """Should filter hashes with invalid lengths"""
        text = "Invalid hash: 123abc (too short)"
        result = cti.extract_iocs(text)
        self.assertEqual(len(result['hashes']), 0)


class TestProcessFeed(unittest.TestCase):
    """Test cases for process_feed function"""

    @patch('cti.requests.get')
    def test_should_handle_network_errors_gracefully(self, mock_get):
        """Should handle network errors without crashing"""
        mock_get.side_effect = Exception("Network error")

        cutoff_date = datetime(2024, 1, 1)
        result = cti.process_feed("Test Vendor", "https://invalid-url.com/rss", cutoff_date)

        self.assertEqual(len(result), 0)


class TestToYyyyMmDd(unittest.TestCase):
    """Test cases for to_yyyy_mm_dd function"""

    def test_should_convert_valid_date_formats(self):
        """Should convert various valid date formats to YYYY-MM-DD"""
        test_cases = [
            ("2024-01-02T12:30:45Z", "2024-01-02"),
            ("Tue, 02 Jan 2024 12:30:45 GMT", "2024-01-02")
        ]

        for input_date, expected in test_cases:
            with self.subTest(input_date=input_date):
                result = cti.to_yyyy_mm_dd(input_date)
                self.assertEqual(result, expected)

    @patch('cti.datetime')
    def test_should_return_current_date_for_invalid_input(self, mock_datetime):
        """Should return current date for invalid input"""
        mock_datetime.utcnow.return_value.strftime.return_value = "2024-01-01"
        result = cti.to_yyyy_mm_dd("invalid-date")
        self.assertEqual(result, "2024-01-01")


class TestCreateMispEvent(unittest.TestCase):
    """Test cases for create_misp_event function"""

    def setUp(self):
        self.article = {
            'title': 'Test Article',
            'date': '2024-01-01T00:00:00Z',
            'url': 'https://example.com/article',
            'vendor': 'Test Vendor'
        }
        self.iocs = {
            'urls': {'https://malicious.com'},
            'ips': {'8.8.8.8'},
            'fqdns': {'malicious.domain'},
            'hashes': {'d41d8cd98f00b204e9800998ecf8427e'}
        }

    @patch('cti.MISPEvent')
    def test_should_create_misp_event_with_iocs(self, mock_misp_event):
        """Should create MISP event with IOCs"""
        mock_misp = Mock()
        mock_misp.search.return_value = []  # No existing events
        mock_event_instance = Mock()
        mock_misp_event.return_value = mock_event_instance

        result = cti.create_misp_event(mock_misp, self.article, self.iocs)

        self.assertTrue(result)
        mock_misp.add_event.assert_called_once()
        mock_event_instance.add_attribute.assert_called()

    def test_should_skip_existing_event_with_same_title(self):
        """Should skip creating event if same title already exists"""
        mock_misp = Mock()
        mock_misp.search.return_value = [{'id': '123'}]  # Existing event found

        result = cti.create_misp_event(mock_misp, self.article, self.iocs)

        self.assertFalse(result)
        mock_misp.add_event.assert_not_called()

    def test_should_handle_misp_errors_gracefully(self):
        """Should handle MISP API errors without crashing"""
        mock_misp = Mock()
        mock_misp.search.side_effect = Exception("MISP API error")

        # Should not raise exception
        result = cti.create_misp_event(mock_misp, self.article, self.iocs)
        self.assertIsInstance(result, bool)


class TestExtractContent(unittest.TestCase):
    """Test cases for extract_content function"""

    @patch('cti.requests.get')
    def test_should_extract_content_from_url(self, mock_get):
        """Should extract text content from URL and remove scripts"""
        mock_get.return_value.text = "<html><body><p>Test content</p><script>alert('test');</script></body></html>"

        entry = {'link': 'https://example.com/article'}
        result = cti.extract_content(entry)

        self.assertIn('Test content', result)
        self.assertNotIn('alert', result)  # Script should be removed

    @patch('cti.requests.get')
    def test_should_handle_request_errors(self, mock_get):
        """Should handle HTTP request errors gracefully"""
        mock_get.side_effect = Exception("Network error")

        entry = {'link': 'https://invalid-url.com/article'}
        result = cti.extract_content(entry)

        self.assertEqual(result, "")

    def test_should_return_empty_string_for_missing_link(self):
        """Should return empty string when entry has no link"""
        entry = {}
        result = cti.extract_content(entry)

        self.assertEqual(result, "")


if __name__ == '__main__':
    unittest.main(verbosity=2)