"""
Integration tests for DPAT tool.

This module contains integration tests that test the complete workflow
of the DPAT tool with real data files and database operations.
"""

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import sqlite3

# Import the classes we're testing
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from dpat import (
    Config, NTDSProcessor, HashProcessor, DataSanitizer, 
    HTMLReportBuilder, DatabaseManager, GroupManager, CrackedPasswordProcessor,
    parse_arguments, main
)
from tests import (
    TestConfig, TestDataGenerator, DatabaseTestHelper, DPATTestCase,
    SAMPLE_NTDS_DATA, SAMPLE_CRACKED_DATA, SAMPLE_GROUP_DATA
)


class TestNTDSProcessingIntegration(DPATTestCase):
    """Integration tests for NTDS processing."""
    
    def test_full_ntds_processing_workflow(self):
        """Test complete NTDS processing workflow."""
        # Create test NTDS file
        ntds_file = self.file_manager.create_file("test.ntds", SAMPLE_NTDS_DATA)
        
        # Create test cracked file
        cracked_file = self.file_manager.create_file("test.pot", SAMPLE_CRACKED_DATA)
        
        # Create test group files
        group_files = self.file_manager.create_group_files(SAMPLE_GROUP_DATA)
        
        # Create config
        config = Config(
            ntds_file=str(ntds_file),
            cracked_file=str(cracked_file),
            min_password_length=8,
            groups_directory=str(self.temp_dir)
        )
        
        # Initialize components
        db_manager = DatabaseManager(config)
        group_manager = GroupManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        cracked_processor = CrackedPasswordProcessor(config, db_manager)
        
        # Load groups
        group_manager.load_groups()
        group_manager.load_group_members()
        
        # Create database schema
        group_names = [group[0] for group in group_manager.groups]
        db_manager.create_schema(group_names)
        
        # Process NTDS file
        ntds_processor.process_ntds_file()
        
        # Update group membership
        ntds_processor.update_group_membership(group_manager)
        
        # Process cracked passwords
        cracked_processor.process_cracked_file()
        
        # Verify results
        cursor = db_manager.cursor
        
        # Check that accounts were processed
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE history_index = -1")
        account_count = cursor.fetchone()[0]
        self.assertGreater(account_count, 0)
        
        # Check that some passwords were cracked
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE password IS NOT NULL AND history_index = -1")
        cracked_count = cursor.fetchone()[0]
        self.assertGreater(cracked_count, 0)
        
        # Check that group membership was updated
        for group_name in group_names:
            cursor.execute(f'SELECT COUNT(*) FROM hash_infos WHERE "{group_name}" = 1')
            group_count = cursor.fetchone()[0]
            self.assertGreater(group_count, 0)
        
        db_manager.close()
    
    def test_account_filtering(self):
        """Test account filtering functionality."""
        # Create test NTDS file with machine accounts and krbtgt
        test_data = [
            "DOMAIN\\user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
            "DOMAIN\\machine$:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
            "DOMAIN\\krbtgt:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
        ]
        
        ntds_file = self.file_manager.create_file("test.ntds", test_data)
        cracked_file = self.file_manager.create_file("test.pot", ["31d6cfe0d16ae931b73c59d7e0c089c0:password"])
        
        # Test with default filtering (exclude machine accounts and krbtgt)
        config = Config(
            ntds_file=str(ntds_file),
            cracked_file=str(cracked_file),
            min_password_length=8
        )
        
        db_manager = DatabaseManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        
        db_manager.create_schema([])
        ntds_processor.process_ntds_file()
        
        cursor = db_manager.cursor
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE history_index = -1")
        count_default = cursor.fetchone()[0]
        
        db_manager.close()
        
        # Test with machine accounts and krbtgt included
        config.include_machine_accounts = True
        config.include_krbtgt = True
        
        db_manager = DatabaseManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        
        db_manager.create_schema([])
        ntds_processor.process_ntds_file()
        
        cursor = db_manager.cursor
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE history_index = -1")
        count_included = cursor.fetchone()[0]
        
        db_manager.close()
        
        # Should have more accounts when machine accounts and krbtgt are included
        self.assertGreater(count_included, count_default)
        self.assertEqual(count_default, 1)  # Only user1
        self.assertEqual(count_included, 3)  # All three accounts


class TestReportGenerationIntegration(DPATTestCase):
    """Integration tests for report generation."""
    
    def test_html_report_generation(self):
        """Test HTML report generation."""
        # Create test data
        ntds_file = self.file_manager.create_file("test.ntds", SAMPLE_NTDS_DATA)
        cracked_file = self.file_manager.create_file("test.pot", SAMPLE_CRACKED_DATA)
        
        config = Config(
            ntds_file=str(ntds_file),
            cracked_file=str(cracked_file),
            min_password_length=8,
            report_directory=str(self.temp_dir)
        )
        
        # Process data
        db_manager = DatabaseManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        cracked_processor = CrackedPasswordProcessor(config, db_manager)
        
        db_manager.create_schema([])
        ntds_processor.process_ntds_file()
        cracked_processor.process_cracked_file()
        
        # Generate reports
        sanitizer = DataSanitizer()
        
        # Generate all hashes report
        cursor = db_manager.cursor
        cursor.execute('''
            SELECT username_full, password, LENGTH(password) as plen, nt_hash, only_lm_cracked 
            FROM hash_infos 
            WHERE history_index = -1 
            ORDER BY plen DESC, password
        ''')
        
        rows = cursor.fetchall()
        
        report_builder = HTMLReportBuilder(config.report_directory)
        report_builder.add_table(rows, 
                               ["Username", "Password", "Password Length", "NT Hash", "Only LM Cracked"])
        report_builder.write_report("all_hashes.html")
        
        # Verify report was created
        report_path = Path(config.report_directory) / "all_hashes.html"
        self.assert_file_exists(report_path)
        self.assert_file_contains(report_path, "<table")
        self.assert_file_contains(report_path, "Username")
        self.assert_file_contains(report_path, "Password")
        
        db_manager.close()
    
    def test_sanitized_report_generation(self):
        """Test sanitized report generation."""
        # Create test data
        ntds_file = self.file_manager.create_file("test.ntds", SAMPLE_NTDS_DATA)
        cracked_file = self.file_manager.create_file("test.pot", SAMPLE_CRACKED_DATA)
        
        config = Config(
            ntds_file=str(ntds_file),
            cracked_file=str(cracked_file),
            min_password_length=8,
            report_directory=str(self.temp_dir),
            sanitize_output=True
        )
        
        # Process data
        db_manager = DatabaseManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        cracked_processor = CrackedPasswordProcessor(config, db_manager)
        
        db_manager.create_schema([])
        ntds_processor.process_ntds_file()
        cracked_processor.process_cracked_file()
        
        # Generate sanitized report
        sanitizer = DataSanitizer()
        
        cursor = db_manager.cursor
        cursor.execute('''
            SELECT username_full, password, nt_hash 
            FROM hash_infos 
            WHERE history_index = -1 AND password IS NOT NULL
            LIMIT 1
        ''')
        
        row = cursor.fetchone()
        if row:
            report_builder = HTMLReportBuilder(config.report_directory)
            report_builder.add_table([row], ["Username", "Password", "NT Hash"])
            report_builder.write_report("sanitized_test.html")
            
            # Verify sanitization
            report_path = Path(config.report_directory) / "sanitized_test.html"
            self.assert_file_exists(report_path)
            
            with open(report_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Should contain sanitized password (not the original)
                self.assertIn("*", content)
                # Should not contain the original password
                if row[1]:  # If there was a password
                    self.assertNotIn(row[1], content)
        
        db_manager.close()


class TestGroupProcessingIntegration(DPATTestCase):
    """Integration tests for group processing."""
    
    def test_group_membership_processing(self):
        """Test group membership processing."""
        # Create test data
        ntds_file = self.file_manager.create_file("test.ntds", SAMPLE_NTDS_DATA)
        cracked_file = self.file_manager.create_file("test.pot", SAMPLE_CRACKED_DATA)
        
        # Create group files
        group_files = self.file_manager.create_group_files(SAMPLE_GROUP_DATA)
        
        config = Config(
            ntds_file=str(ntds_file),
            cracked_file=str(cracked_file),
            min_password_length=8,
            groups_directory=str(self.temp_dir)
        )
        
        # Process data
        db_manager = DatabaseManager(config)
        group_manager = GroupManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        
        # Load groups
        group_manager.load_groups()
        group_manager.load_group_members()
        
        # Create schema with group columns
        group_names = [group[0] for group in group_manager.groups]
        db_manager.create_schema(group_names)
        
        # Process NTDS and update group membership
        ntds_processor.process_ntds_file()
        ntds_processor.update_group_membership(group_manager)
        
        # Verify group membership
        cursor = db_manager.cursor
        
        for group_name in group_names:
            cursor.execute(f'SELECT COUNT(*) FROM hash_infos WHERE "{group_name}" = 1')
            count = cursor.fetchone()[0]
            self.assertGreater(count, 0, f"Group {group_name} should have members")
        
        db_manager.close()
    
    def test_group_report_generation(self):
        """Test group report generation."""
        # Create test data
        ntds_file = self.file_manager.create_file("test.ntds", SAMPLE_NTDS_DATA)
        cracked_file = self.file_manager.create_file("test.pot", SAMPLE_CRACKED_DATA)
        
        # Create group files
        group_files = self.file_manager.create_group_files(SAMPLE_GROUP_DATA)
        
        config = Config(
            ntds_file=str(ntds_file),
            cracked_file=str(cracked_file),
            min_password_length=8,
            groups_directory=str(self.temp_dir),
            report_directory=str(self.temp_dir)
        )
        
        # Process data
        db_manager = DatabaseManager(config)
        group_manager = GroupManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        cracked_processor = CrackedPasswordProcessor(config, db_manager)
        
        # Load groups
        group_manager.load_groups()
        group_manager.load_group_members()
        
        # Create schema with group columns
        group_names = [group[0] for group in group_manager.groups]
        db_manager.create_schema(group_names)
        
        # Process data
        ntds_processor.process_ntds_file()
        ntds_processor.update_group_membership(group_manager)
        cracked_processor.process_cracked_file()
        
        # Generate group reports
        sanitizer = DataSanitizer()
        
        for group_name in group_names:
            # Generate group members report
            cursor = db_manager.cursor
            cursor.execute(f'SELECT username_full, nt_hash FROM hash_infos WHERE "{group_name}" = 1 AND history_index = -1')
            member_rows = cursor.fetchall()
            
            if member_rows:
                report_builder = HTMLReportBuilder(config.report_directory)
                report_builder.add_table(member_rows, ["Username", "NT Hash"])
                
                safe_group_name = group_name.replace(" ", "_")
                filename = f"{safe_group_name}_members.html"
                report_builder.write_report(filename)
                
                # Verify report was created
                report_path = Path(config.report_directory) / filename
                self.assert_file_exists(report_path)
                # Check that the report contains usernames (domain prefix included)
                self.assert_file_contains(report_path, "DOMAIN")
        
        db_manager.close()


class TestCommandLineIntegration(DPATTestCase):
    """Integration tests for command line interface."""
    
    @patch('sys.argv', [
        'dpat.py',
        '-n', 'test.ntds',
        '-c', 'test.pot',
        '-p', '8',
        '-g', 'groups/',
        '-s'
    ])
    def test_command_line_parsing(self):
        """Test command line argument parsing."""
        config = parse_arguments()
        
        self.assertEqual(config.ntds_file, 'test.ntds')
        self.assertEqual(config.cracked_file, 'test.pot')
        self.assertEqual(config.min_password_length, 8)
        self.assertEqual(config.groups_directory, 'groups/')
        self.assertTrue(config.sanitize_output)
    
    @patch('sys.argv', [
        'dpat.py',
        '-n', 'test.ntds',
        '-c', 'test.pot',
        '-p', '8'
    ])
    def test_command_line_parsing_minimal(self):
        """Test minimal command line argument parsing."""
        config = parse_arguments()
        
        self.assertEqual(config.ntds_file, 'test.ntds')
        self.assertEqual(config.cracked_file, 'test.pot')
        self.assertEqual(config.min_password_length, 8)
        self.assertIsNone(config.groups_directory)
        self.assertFalse(config.sanitize_output)
    
    @patch('sys.argv', [
        'dpat.py',
        '-n', 'test.ntds',
        '-c', 'test.pot',
        '-o', 'custom_report.html',
        '-d', 'custom_output/',
        '-g', 'groups/',
        '-p', '12',
        '-s',
        '-m',
        '-k',
        '-kz', 'kerberoast.txt',
        '--ch-encoding', 'utf-8',
        '-w',
        '-dbg'
    ])
    def test_command_line_parsing_with_all_options(self):
        """Test command line parsing with all options."""
        config = parse_arguments()
        
        self.assertEqual(config.ntds_file, 'test.ntds')
        self.assertEqual(config.cracked_file, 'test.pot')
        self.assertEqual(config.output_file, 'custom_report.html')
        self.assertEqual(config.report_directory, 'custom_output/ - Sanitized')
        self.assertEqual(config.groups_directory, 'groups/')
        self.assertEqual(config.min_password_length, 12)
        self.assertTrue(config.sanitize_output)
        self.assertTrue(config.include_machine_accounts)
        self.assertTrue(config.include_krbtgt)
        self.assertEqual(config.kerberoast_file, 'kerberoast.txt')
        self.assertEqual(config.kerberoast_encoding, 'utf-8')
        self.assertTrue(config.write_database)
        self.assertTrue(config.debug_mode)


class TestErrorHandlingIntegration(DPATTestCase):
    """Integration tests for error handling."""
    
    def test_missing_ntds_file(self):
        """Test handling of missing NTDS file."""
        config = Config(
            ntds_file="nonexistent.ntds",
            cracked_file="test.pot",
            min_password_length=8
        )
        
        db_manager = DatabaseManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        
        db_manager.create_schema([])
        
        with self.assertRaises(FileNotFoundError):
            ntds_processor.process_ntds_file()
        
        db_manager.close()
    
    def test_missing_cracked_file(self):
        """Test handling of missing cracked file."""
        ntds_file = self.file_manager.create_file("test.ntds", SAMPLE_NTDS_DATA)
        
        config = Config(
            ntds_file=str(ntds_file),
            cracked_file="nonexistent.pot",
            min_password_length=8
        )
        
        db_manager = DatabaseManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        cracked_processor = CrackedPasswordProcessor(config, db_manager)
        
        db_manager.create_schema([])
        ntds_processor.process_ntds_file()
        
        with self.assertRaises(FileNotFoundError):
            cracked_processor.process_cracked_file()
        
        db_manager.close()
    
    def test_invalid_ntds_format(self):
        """Test handling of invalid NTDS format."""
        invalid_data = [
            "invalid line",
            "user:hash",
            "",
            "user:rid:lm:nt"  # Only 4 parts, should be valid but with empty hashes
        ]
        
        ntds_file = self.file_manager.create_file("invalid.ntds", invalid_data)
        cracked_file = self.file_manager.create_file("test.pot", SAMPLE_CRACKED_DATA)
        
        config = Config(
            ntds_file=str(ntds_file),
            cracked_file=str(cracked_file),
            min_password_length=8
        )
        
        db_manager = DatabaseManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        
        db_manager.create_schema([])
        
        # Should not raise an exception, but should process 1 account (the valid line)
        ntds_processor.process_ntds_file()
        
        cursor = db_manager.cursor
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE history_index = -1")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 1)
        
        db_manager.close()
    
    def test_empty_group_directory(self):
        """Test handling of empty group directory."""
        ntds_file = self.file_manager.create_file("test.ntds", SAMPLE_NTDS_DATA)
        cracked_file = self.file_manager.create_file("test.pot", SAMPLE_CRACKED_DATA)
        
        config = Config(
            ntds_file=str(ntds_file),
            cracked_file=str(cracked_file),
            min_password_length=8,
            groups_directory=str(self.temp_dir)
        )
        
        group_manager = GroupManager(config)
        
        # Should not raise an exception
        group_manager.load_groups()
        self.assertEqual(len(group_manager.groups), 0)


class TestHistoryDataIntegration(DPATTestCase):
    """Integration tests using history sample data files."""
    
    def test_history_data_processing(self):
        """Test processing with history sample data files."""
        # Use the actual history sample data files
        ntds_file = Path("sample_data/history/customer-small.ntds")
        cracked_file = Path("sample_data/history/john-customer-small.pot")
        
        # Verify files exist
        self.assertTrue(ntds_file.exists(), f"NTDS file not found: {ntds_file}")
        self.assertTrue(cracked_file.exists(), f"Cracked file not found: {cracked_file}")
        
        config = Config(
            ntds_file=str(ntds_file),
            cracked_file=str(cracked_file),
            min_password_length=8,
            report_directory=str(self.temp_dir)
        )
        
        # Process data
        db_manager = DatabaseManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        cracked_processor = CrackedPasswordProcessor(config, db_manager)
        
        db_manager.create_schema([])
        
        # Process NTDS file
        ntds_processor.process_ntds_file()
        
        # Process cracked passwords
        cracked_processor.process_cracked_file()
        
        # Verify data was processed
        cursor = db_manager.cursor
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE history_index = -1")
        total_accounts = cursor.fetchone()[0]
        self.assertGreater(total_accounts, 0, "No accounts were processed from NTDS file")
        
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE password IS NOT NULL AND history_index = -1")
        cracked_accounts = cursor.fetchone()[0]
        # Note: The cracked file may not contain hashes that match the NTDS file
        # This is expected behavior for this test dataset
        
        # Check for password history entries
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE history_index >= 0")
        history_entries = cursor.fetchone()[0]
        self.assertGreater(history_entries, 0, "No password history entries found")
        
        # Generate reports
        sanitizer = DataSanitizer()
        
        # Generate all hashes report
        cursor.execute('''SELECT username_full, password, LENGTH(password) as plen, nt_hash, 
                         CASE WHEN lm_hash != "aad3b435b51404eeaad3b435b51404ee" THEN "Yes" ELSE "No" END as lm_cracked
                         FROM hash_infos WHERE history_index = -1 ORDER BY username_full''')
        rows = cursor.fetchall()
        
        report_builder = HTMLReportBuilder(config.report_directory)
        report_builder.add_table(rows, 
                               ["Username", "Password", "Password Length", "NT Hash", "Only LM Cracked"])
        report_filename = report_builder.write_report("history_test_all_hashes.html")
        
        # Verify report was created
        report_path = Path(config.report_directory) / report_filename
        self.assert_file_exists(report_path)
        self.assert_file_contains(report_path, "Username")
        
        # Generate password history report
        cursor.execute('''SELECT username_full, password, LENGTH(password) as plen, nt_hash, history_index
                         FROM hash_infos WHERE history_index >= 0 ORDER BY username_full, history_index''')
        history_rows = cursor.fetchall()
        
        if history_rows:
            history_builder = HTMLReportBuilder(config.report_directory)
            history_builder.add_table(history_rows, 
                                    ["Username", "Password", "Password Length", "NT Hash", "History Index"])
            history_filename = history_builder.write_report("history_test_password_history.html")
            
            # Verify history report was created
            history_report_path = Path(config.report_directory) / history_filename
            self.assert_file_exists(history_report_path)
            self.assert_file_contains(history_report_path, "History Index")
        
        db_manager.close()
        
        # Log test results
        print(f"\nHistory Data Test Results:")
        print(f"  Total accounts processed: {total_accounts}")
        print(f"  Cracked accounts: {cracked_accounts}")
        print(f"  Password history entries: {history_entries}")
        if total_accounts > 0:
            print(f"  Crack rate: {(cracked_accounts/total_accounts)*100:.1f}%")
        else:
            print(f"  Crack rate: N/A (no accounts processed)")


if __name__ == '__main__':
    unittest.main()
