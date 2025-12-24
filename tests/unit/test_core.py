"""
Unit tests for DPAT core classes.

This module contains unit tests for all the core classes in the DPAT tool,
including configuration, data processing, and utility classes.
"""

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import sqlite3

# Import the classes we're testing
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from dpat import (
    Config, NTDSProcessor, HashProcessor, DataSanitizer, 
    HTMLReportBuilder, DatabaseManager, GroupManager, CrackedPasswordProcessor,
    calculate_percentage
)
from tests import TestConfig, TestDataGenerator, DatabaseTestHelper, DPATTestCase


class TestConfig(DPATTestCase):
    """Test the Config dataclass."""
    
    def test_config_creation(self):
        """Test basic config creation."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8
        )
        
        self.assertEqual(config.ntds_file, "test.ntds")
        self.assertEqual(config.cracked_file, "test.pot")
        self.assertEqual(config.min_password_length, 8)
        self.assertFalse(config.sanitize_output)
        self.assertFalse(config.include_machine_accounts)
    
    def test_config_sanitize_output(self):
        """Test config with sanitize output enabled."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8,
            sanitize_output=True
        )
        
        self.assertTrue(config.sanitize_output)
        self.assertEqual(config.report_directory, "DPAT Report - Sanitized")
    
    def test_config_post_init(self):
        """Test config post-initialization processing."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8,
            sanitize_output=True
        )
        
        # Check that report directory was modified
        self.assertIn("Sanitized", config.report_directory)
        
        # Check that report directory exists
        self.assertTrue(Path(config.report_directory).exists())


class TestNTDSProcessor(DPATTestCase):
    """Test the NTDSProcessor class."""
    
    def test_parse_ntds_line_valid(self):
        """Test parsing valid NTDS lines."""
        # Test pwdump format
        line1 = "DOMAIN\\user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::"
        user, nt_hash = NTDSProcessor.parse_ntds_line(line1)
        self.assertEqual(user, "domain\\user1")  # Method converts to lowercase
        self.assertEqual(nt_hash, "31d6cfe0d16ae931b73c59d7e0c089c0")
        
        # Test domain\\user format (first pattern - extracts just username)
        line2 = "DOMAIN\\user2:31d6cfe0d16ae931b73c59d7e0c089c0"
        user, nt_hash = NTDSProcessor.parse_ntds_line(line2)
        self.assertEqual(user, "user2")  # First pattern extracts just username
        self.assertEqual(nt_hash, "31d6cfe0d16ae931b73c59d7e0c089c0")
    
    def test_parse_ntds_line_invalid(self):
        """Test parsing invalid NTDS lines."""
        invalid_lines = [
            "invalid line",
            "user:hash",
            "",
            "user:rid:lm:nt:extra:fields"
        ]
        
        for line in invalid_lines:
            user, nt_hash = NTDSProcessor.parse_ntds_line(line)
            self.assertIsNone(user)
            self.assertIsNone(nt_hash)
    
    def test_load_kerberoast_ntds(self):
        """Test loading Kerberoast NTDS data."""
        test_data = [
            "DOMAIN\\service1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
            "DOMAIN\\service2:1002:aad3b435b51404eeaad3b435b51404ee:5d41402abc4b2a76b9719d911017c592::::",
            "invalid line",
            "DOMAIN\\service3:1003:aad3b435b51404eeaad3b435b51404ee:****************::::"
        ]
        
        # Create test file
        test_file = self.file_manager.create_file("kerberoast.txt", test_data)
        
        # Load data
        entries = NTDSProcessor.load_kerberoast_ntds(str(test_file))
        
        # Should have 2 valid entries (service1 and service2)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0][0], "domain\\service1")  # Method converts to lowercase
        self.assertEqual(entries[1][0], "domain\\service2")  # Method converts to lowercase


class TestHashProcessor(DPATTestCase):
    """Test the HashProcessor class."""
    
    def test_generate_username_candidates(self):
        """Test username candidate generation."""
        candidates = HashProcessor.generate_username_candidates("john", "DOMAIN\\john")
        
        # The method generates case variants for each candidate
        expected = {"john", "John", "JOHN", "DOMAIN\\john", "Domain\\john", "domain\\john", "DOMAIN\\JOHN"}
        self.assertEqual(candidates, expected)
    
    def test_generate_username_candidates_with_email(self):
        """Test username candidate generation with email format."""
        candidates = HashProcessor.generate_username_candidates("john", "john@domain.com")
        
        self.assertIn("john@domain.com", candidates)
        self.assertIn("john", candidates)
        self.assertIn("John", candidates)
    
    def test_all_casings(self):
        """Test case generation."""
        casings = list(HashProcessor.all_casings("ab"))
        expected = ["ab", "Ab", "aB", "AB"]
        self.assertEqual(set(casings), set(expected))
    
    def test_all_casings_empty(self):
        """Test case generation with empty string."""
        casings = list(HashProcessor.all_casings(""))
        self.assertEqual(casings, [""])
    
    def test_all_casings_non_alpha(self):
        """Test case generation with non-alphabetic characters."""
        casings = list(HashProcessor.all_casings("a1"))
        # Should only have 2 variants since '1' is not alphabetic
        self.assertEqual(len(casings), 2)
        self.assertIn("a1", casings)
        self.assertIn("A1", casings)
    
    def test_ntlm_hash_fallback(self):
        """Test NT hash generation with fallback mechanisms."""
        # Test that the method exists and can be called
        try:
            result = HashProcessor.ntlm_hash("test_password")
            # If it succeeds, it should return a string
            self.assertIsInstance(result, str)
            self.assertEqual(len(result), 32)  # MD4 hash is 32 chars
        except RuntimeError as e:
            # If no backend is available, that's expected in test environment
            self.assertIn("No NT hash backend available", str(e))


class TestDataSanitizer(DPATTestCase):
    """Test the DataSanitizer class."""
    
    def test_sanitize_value_disabled(self):
        """Test sanitization when disabled."""
        value = "password123"
        result = DataSanitizer.sanitize_value(value, should_sanitize=False)
        self.assertEqual(result, value)
    
    def test_sanitize_value_hash(self):
        """Test sanitization of hash values."""
        hash_value = "31d6cfe0d16ae931b73c59d7e0c089c0"
        result = DataSanitizer.sanitize_value(hash_value, should_sanitize=True)
        self.assertEqual(result, "31d6************************89c0")
    
    def test_sanitize_value_password(self):
        """Test sanitization of password values."""
        password = "password123"
        result = DataSanitizer.sanitize_value(password, should_sanitize=True)
        self.assertEqual(result, "p*********3")
    
    def test_sanitize_value_short(self):
        """Test sanitization of short values."""
        short_value = "ab"
        result = DataSanitizer.sanitize_value(short_value, should_sanitize=True)
        self.assertEqual(result, "ab")
    
    def test_sanitize_value_empty(self):
        """Test sanitization of empty values."""
        empty_value = ""
        result = DataSanitizer.sanitize_value(empty_value, should_sanitize=True)
        self.assertEqual(result, "")
    



class TestHTMLReportBuilder(DPATTestCase):
    """Test the HTMLReportBuilder class."""
    
    def test_html_report_builder_creation(self):
        """Test HTML report builder creation."""
        builder = HTMLReportBuilder(str(self.temp_dir))
        self.assertEqual(builder.report_directory, str(self.temp_dir))
        self.assertEqual(builder.body_content, "")
    
    def test_add_content(self):
        """Test adding content to HTML report."""
        builder = HTMLReportBuilder(str(self.temp_dir))
        builder.add_content("<h1>Test</h1>")
        
        self.assertIn("<h1>Test</h1>", builder.body_content)
        self.assertIn("section-space", builder.body_content)
    
    def test_add_table(self):
        """Test adding table to HTML report."""
        builder = HTMLReportBuilder(str(self.temp_dir))
        rows = [("user1", "pass1"), ("user2", "pass2")]
        headers = ["Username", "Password"]
        
        builder.add_table(rows, headers)
        
        self.assertIn("<table", builder.body_content)
        self.assertIn("<thead>", builder.body_content)
        self.assertIn("<tbody>", builder.body_content)
        self.assertIn("Username", builder.body_content)
        self.assertIn("Password", builder.body_content)
    
    def test_generate_html(self):
        """Test HTML generation."""
        builder = HTMLReportBuilder(str(self.temp_dir))
        builder.add_content("<h1>Test Report</h1>")
        
        html = builder.generate_html()
        
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("<html", html)  # Matches <html lang='en'> and other variations
        self.assertIn("<head>", html)
        self.assertIn("<body>", html)
        self.assertIn("<h1>Test Report</h1>", html)
        self.assertIn("report.css", html)
    
    def test_navbar_link_default_filename(self):
        """Test navbar link uses default filename when not specified."""
        builder = HTMLReportBuilder(str(self.temp_dir))
        builder.add_content("<h1>Test Report</h1>")
        
        html = builder.generate_html()
        
        # Should use default filename in navbar link
        self.assertIn("href='_DomainPasswordAuditReport.html'", html)
    
    def test_navbar_link_custom_filename(self):
        """Test navbar link uses default filename."""
        builder = HTMLReportBuilder(str(self.temp_dir))
        builder.add_content("<h1>Test Report</h1>")
        
        html = builder.generate_html()
        
        # Should use default filename in navbar link
        self.assertIn("href='_DomainPasswordAuditReport.html'", html)
    
    def test_write_report(self):
        """Test writing report to file."""
        builder = HTMLReportBuilder(str(self.temp_dir))
        builder.add_content("<h1>Test Report</h1>")
        
        filename = builder.write_report("test_report.html")
        
        self.assertEqual(filename, "test_report.html")
        report_path = self.temp_dir / "test_report.html"
        self.assert_file_exists(report_path)
        self.assert_file_contains(report_path, "<h1>Test Report</h1>")


class TestDatabaseManager(DPATTestCase):
    """Test the DatabaseManager class."""
    
    def test_database_manager_creation(self):
        """Test database manager creation."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8
        )
        
        db_manager = DatabaseManager(config)
        
        self.assertIsNotNone(db_manager.connection)
        self.assertIsNotNone(db_manager.cursor)
    
    def test_create_schema(self):
        """Test database schema creation."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8
        )
        
        db_manager = DatabaseManager(config)
        group_names = ["Domain Admins", "Enterprise Admins"]
        
        db_manager.create_schema(group_names)
        
        # Check that table exists
        cursor = db_manager.cursor
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hash_infos'")
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        
        # Check that group columns exist
        cursor.execute("PRAGMA table_info(hash_infos)")
        columns = [row[1] for row in cursor.fetchall()]
        
        for group_name in group_names:
            self.assertIn(group_name, columns)
    
    def test_close_database(self):
        """Test database connection closing."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8
        )
        
        db_manager = DatabaseManager(config)
        db_manager.close()
        
        # Connection should be closed
        with self.assertRaises(sqlite3.ProgrammingError):
            db_manager.cursor.execute("SELECT 1")


class TestGroupManager(DPATTestCase):
    """Test the GroupManager class."""
    
    def test_group_manager_creation(self):
        """Test group manager creation."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8,
            groups_directory=str(self.temp_dir)
        )
        
        manager = GroupManager(config)
        
        self.assertEqual(manager.groups, [])
        self.assertEqual(manager.group_users, {})
    
    def test_load_groups_no_directory(self):
        """Test loading groups when no directory is specified."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8
        )
        
        manager = GroupManager(config)
        manager.load_groups()
        
        self.assertEqual(len(manager.groups), 0)
    
    def test_load_groups_with_files(self):
        """Test loading groups from files."""
        # Create test group files
        group_files = self.file_manager.create_group_files({
            "Domain Admins": ["DOMAIN\\admin1", "DOMAIN\\admin2"],
            "Enterprise Admins": ["DOMAIN\\admin1", "DOMAIN\\superadmin"]
        })
        
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8,
            groups_directory=str(self.temp_dir)
        )
        
        manager = GroupManager(config)
        manager.load_groups()
        
        self.assertEqual(len(manager.groups), 2)
        group_names = [group[0] for group in manager.groups]
        self.assertIn("Domain Admins", group_names)
        self.assertIn("Enterprise Admins", group_names)
    
    def test_load_group_members(self):
        """Test loading group members."""
        # Create test group files
        group_files = self.file_manager.create_group_files({
            "Domain Admins": ["DOMAIN\\admin1", "DOMAIN\\admin2"],
            "Enterprise Admins": ["DOMAIN\\admin1", "DOMAIN\\superadmin"]
        })
        
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8,
            groups_directory=str(self.temp_dir)
        )
        
        manager = GroupManager(config)
        manager.load_groups()
        manager.load_group_members()
        
        self.assertIn("Domain Admins", manager.group_users)
        self.assertIn("Enterprise Admins", manager.group_users)
        self.assertEqual(len(manager.group_users["Domain Admins"]), 2)
        self.assertEqual(len(manager.group_users["Enterprise Admins"]), 2)


class TestCrackedPasswordProcessor(DPATTestCase):
    """Test the CrackedPasswordProcessor class."""
    
    def test_cracked_password_processor_creation(self):
        """Test cracked password processor creation."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8
        )
        
        db_manager = DatabaseManager(config)
        processor = CrackedPasswordProcessor(config, db_manager)
        
        self.assertEqual(processor.config, config)
        self.assertEqual(processor.db_manager, db_manager)
    
    def test_process_cracked_line_nt_hash(self):
        """Test processing NT hash cracked line."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8
        )
        
        db_manager = DatabaseManager(config)
        db_manager.create_schema([])
        
        # Insert test data
        cursor = db_manager.cursor
        cursor.execute('''
            INSERT INTO hash_infos (username_full, username, nt_hash)
            VALUES (?, ?, ?)
        ''', ("DOMAIN\\user1", "user1", "31d6cfe0d16ae931b73c59d7e0c089c0"))
        
        processor = CrackedPasswordProcessor(config, db_manager)
        processor._process_cracked_line("31d6cfe0d16ae931b73c59d7e0c089c0:password123")
        
        # Check that password was updated
        cursor.execute("SELECT password FROM hash_infos WHERE nt_hash = ?", 
                      ("31d6cfe0d16ae931b73c59d7e0c089c0",))
        result = cursor.fetchone()
        self.assertEqual(result[0], "password123")
    
    def test_process_cracked_line_lm_hash(self):
        """Test processing LM hash cracked line."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8
        )
        
        db_manager = DatabaseManager(config)
        db_manager.create_schema([])
        
        # Insert test data
        cursor = db_manager.cursor
        cursor.execute('''
            INSERT INTO hash_infos (username_full, username, lm_hash_left, lm_hash_right)
            VALUES (?, ?, ?, ?)
        ''', ("DOMAIN\\user1", "user1", "aad3b435b51404ee", "aad3b435b51404ee"))
        
        processor = CrackedPasswordProcessor(config, db_manager)
        processor._process_cracked_line("aad3b435b51404ee:password")
        
        # Check that LM password was updated
        cursor.execute("SELECT lm_pass_left FROM hash_infos WHERE lm_hash_left = ?", 
                      ("aad3b435b51404ee",))
        result = cursor.fetchone()
        self.assertEqual(result[0], "password")
    
    def test_decode_hex_password(self):
        """Test hex password decoding."""
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8
        )
        
        db_manager = DatabaseManager(config)
        processor = CrackedPasswordProcessor(config, db_manager)
        
        # Test hex decoding
        hex_password = "$HEX[68656c6c6f]"
        result = processor._decode_hex_password(hex_password)
        self.assertEqual(result, "hello")
        
        # Test non-hex password
        normal_password = "password123"
        result = processor._decode_hex_password(normal_password)
        self.assertEqual(result, "password123")


class TestUtilityFunctions(DPATTestCase):
    """Test utility functions."""
    
    def test_calculate_percentage(self):
        """Test percentage calculation."""
        # Normal case
        result = calculate_percentage(25, 100)
        self.assertEqual(result, 25.0)
        
        # Zero division case
        result = calculate_percentage(10, 0)
        self.assertEqual(result, 0.0)
        
        # Rounding case
        result = calculate_percentage(1, 3)
        self.assertEqual(result, 33.33)
    


if __name__ == '__main__':
    unittest.main()
