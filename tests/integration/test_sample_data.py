"""
Integration tests using real sample data files.

This module contains integration tests that use the actual sample data files
from the sample_data directory to test DPAT functionality with real-world data.
"""

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import sqlite3
import os

# Import the classes we're testing
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dpat import (
    Config, NTDSProcessor, HashProcessor, DataSanitizer, 
    HTMLReportBuilder, DatabaseManager, GroupManager, CrackedPasswordProcessor,
    parse_arguments, main
)
from tests import (
    TestConfig, TestDataGenerator, DatabaseTestHelper, DPATTestCase,
    SAMPLE_NTDS_DATA, SAMPLE_CRACKED_DATA, SAMPLE_GROUP_DATA
)


class TestSampleDataIntegration(DPATTestCase):
    """Integration tests using real sample data files."""
    
    def setUp(self):
        """Set up test environment with sample data paths."""
        super().setUp()
        
        # Get the project root directory (DPAT directory)
        self.project_root = Path(__file__).parent.parent.parent
        self.sample_data_dir = self.project_root / "sample_data"
        
        # Verify sample data files exist
        self.ntds_file = self.sample_data_dir / "customer.ntds"
        self.cracked_file = self.sample_data_dir / "oclHashcat.pot"
        self.domain_admins_file = self.sample_data_dir / "Domain Admins.txt"
        self.enterprise_admins_file = self.sample_data_dir / "Enterprise Admins.txt"
        self.powerview_file = self.sample_data_dir / "Enterprise Admins PowerView Output.txt"
        
        # Verify files exist
        self.assertTrue(self.ntds_file.exists(), f"NTDS file not found: {self.ntds_file}")
        self.assertTrue(self.cracked_file.exists(), f"Cracked file not found: {self.cracked_file}")
        self.assertTrue(self.domain_admins_file.exists(), f"Domain Admins file not found: {self.domain_admins_file}")
        self.assertTrue(self.enterprise_admins_file.exists(), f"Enterprise Admins file not found: {self.enterprise_admins_file}")
        self.assertTrue(self.powerview_file.exists(), f"PowerView file not found: {self.powerview_file}")
    
    def test_sample_data_ntds_processing(self):
        """Test processing the real customer.ntds file."""
        config = Config(
            ntds_file=str(self.ntds_file),
            cracked_file=str(self.cracked_file),
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
        
        # Verify results
        cursor = db_manager.cursor
        
        # Check that accounts were processed
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE history_index = -1")
        account_count = cursor.fetchone()[0]
        self.assertGreater(account_count, 0, "Should have processed accounts from customer.ntds")
        
        # Check that some passwords were cracked
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE password IS NOT NULL AND history_index = -1")
        cracked_count = cursor.fetchone()[0]
        self.assertGreater(cracked_count, 0, "Should have cracked passwords from oclHashcat.pot")
        
        # Check for specific known cracked passwords
        cursor.execute("SELECT username_full, password FROM hash_infos WHERE password = 'password' AND history_index = -1")
        password_results = cursor.fetchall()
        self.assertGreater(len(password_results), 0, "Should have found 'password' in cracked data")
        
        db_manager.close()
    
    def test_sample_data_with_groups(self):
        """Test processing with Domain Admins and Enterprise Admins group files."""
        # Create a groups directory with the sample group files
        groups_dir = self.temp_dir / "groups"
        groups_dir.mkdir()
        
        # Copy group files to test directory
        import shutil
        shutil.copy2(self.domain_admins_file, groups_dir / "Domain Admins.txt")
        shutil.copy2(self.enterprise_admins_file, groups_dir / "Enterprise Admins.txt")
        
        config = Config(
            ntds_file=str(self.ntds_file),
            cracked_file=str(self.cracked_file),
            min_password_length=8,
            groups_directory=str(groups_dir),
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
        
        # Verify group processing
        cursor = db_manager.cursor
        
        # Check that groups were loaded
        self.assertGreater(len(group_manager.groups), 0, "Should have loaded group files")
        self.assertIn("Domain Admins", [group[0] for group in group_manager.groups])
        self.assertIn("Enterprise Admins", [group[0] for group in group_manager.groups])
        
        # Check that group members were loaded
        self.assertIn("Domain Admins", group_manager.group_users)
        self.assertIn("Enterprise Admins", group_manager.group_users)
        
        # Check that group membership was updated in database
        cursor.execute('SELECT COUNT(*) FROM hash_infos WHERE "Domain Admins" = 1')
        domain_admins_count = cursor.fetchone()[0]
        self.assertGreater(domain_admins_count, 0, "Should have Domain Admins members")
        
        cursor.execute('SELECT COUNT(*) FROM hash_infos WHERE "Enterprise Admins" = 1')
        enterprise_admins_count = cursor.fetchone()[0]
        self.assertGreater(enterprise_admins_count, 0, "Should have Enterprise Admins members")
        
        # Verify specific admin accounts are in the database
        cursor.execute('SELECT username_full FROM hash_infos WHERE "Domain Admins" = 1 LIMIT 5')
        domain_admin_users = [row[0] for row in cursor.fetchall()]
        self.assertGreater(len(domain_admin_users), 0, "Should have Domain Admin users")
        
        # Check that admin users have -admin suffix
        admin_users_with_suffix = [user for user in domain_admin_users if user.endswith('-admin')]
        self.assertGreater(len(admin_users_with_suffix), 0, "Should have users with -admin suffix")
        
        db_manager.close()
    
    def test_sample_data_powerview_format(self):
        """Test processing PowerView formatted group file."""
        # Create a groups directory with the PowerView file
        groups_dir = self.temp_dir / "groups"
        groups_dir.mkdir()
        
        # Copy PowerView file to test directory and convert to UTF-8
        import shutil
        powerview_dest = groups_dir / "Enterprise Admins PowerView.txt"
        
        # Read the PowerView file with UTF-16 encoding and write as UTF-8
        with open(self.powerview_file, 'r', encoding='utf-16') as f:
            content = f.read()
        
        # Remove leading empty lines to ensure first line is not empty
        lines = content.split('\n')
        while lines and not lines[0].strip():
            lines.pop(0)
        content = '\n'.join(lines)
        
        with open(powerview_dest, 'w', encoding='utf-8') as f:
            f.write(content)
        
        config = Config(
            ntds_file=str(self.ntds_file),
            cracked_file=str(self.cracked_file),
            min_password_length=8,
            groups_directory=str(groups_dir),
            report_directory=str(self.temp_dir),
            kerberoast_encoding='utf-8'  # Use UTF-8 for group files
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
        
        # Verify PowerView processing
        cursor = db_manager.cursor
        
        # Check that PowerView group was loaded
        powerview_groups = [group[0] for group in group_manager.groups if "PowerView" in group[0]]
        self.assertGreater(len(powerview_groups), 0, "Should have loaded PowerView group")
        
        # Check that PowerView group has members
        powerview_group_name = powerview_groups[0]
        self.assertIn(powerview_group_name, group_manager.group_users)
        
        # Check that PowerView group membership was updated in database
        cursor.execute(f'SELECT COUNT(*) FROM hash_infos WHERE "{powerview_group_name}" = 1')
        powerview_count = cursor.fetchone()[0]
        self.assertGreater(powerview_count, 0, "Should have PowerView group members")
        
        # Verify specific PowerView members are in the database
        cursor.execute(f'SELECT username_full FROM hash_infos WHERE "{powerview_group_name}" = 1 LIMIT 5')
        powerview_users = [row[0] for row in cursor.fetchall()]
        self.assertGreater(len(powerview_users), 0, "Should have PowerView users")
        
        db_manager.close()
    
    def test_sample_data_report_generation(self):
        """Test HTML report generation with sample data."""
        config = Config(
            ntds_file=str(self.ntds_file),
            cracked_file=str(self.cracked_file),
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
        report_builder.write_report("sample_data_report.html")
        
        # Verify report was created
        report_path = Path(config.report_directory) / "sample_data_report.html"
        self.assert_file_exists(report_path)
        self.assert_file_contains(report_path, "<table")
        self.assert_file_contains(report_path, "Username")
        self.assert_file_contains(report_path, "Password")
        
        # Check that report contains actual data
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Should contain some of the actual usernames from the sample data
            self.assertIn("child.domain.com", content)
            self.assertIn("parent.domain.com", content)
        
        db_manager.close()
    
    def test_sample_data_sanitized_reports(self):
        """Test sanitized report generation with sample data."""
        config = Config(
            ntds_file=str(self.ntds_file),
            cracked_file=str(self.cracked_file),
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
            LIMIT 10
        ''')
        
        rows = cursor.fetchall()
        
        report_builder = HTMLReportBuilder(config.report_directory)
        report_builder.add_table(rows, ["Username", "Password", "NT Hash"])
        report_builder.write_report("sample_data_sanitized.html")
        
        # Verify sanitization
        report_path = Path(config.report_directory) / "sample_data_sanitized.html"
        self.assert_file_exists(report_path)
        
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Should contain sanitized passwords (asterisks)
            self.assertIn("*", content)
            # Should not contain the original passwords
            for row in rows:
                if row[1]:  # If there was a password
                    self.assertNotIn(row[1], content, f"Original password '{row[1]}' should be sanitized")
        
        db_manager.close()
    
    def test_sample_data_statistics(self):
        """Test statistics generation with sample data."""
        config = Config(
            ntds_file=str(self.ntds_file),
            cracked_file=str(self.cracked_file),
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
        
        # Generate statistics
        cursor = db_manager.cursor
        
        # Get basic statistics
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE history_index = -1")
        total_accounts = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE password IS NOT NULL AND history_index = -1")
        cracked_accounts = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM hash_infos WHERE password IS NULL AND history_index = -1")
        uncracked_accounts = cursor.fetchone()[0]
        
        # Verify statistics are reasonable
        self.assertGreater(total_accounts, 0, "Should have total accounts")
        self.assertGreater(cracked_accounts, 0, "Should have cracked accounts")
        self.assertGreater(uncracked_accounts, 0, "Should have uncracked accounts")
        self.assertEqual(total_accounts, cracked_accounts + uncracked_accounts, "Total should equal cracked + uncracked")
        
        # Check password length statistics
        cursor.execute('''
            SELECT LENGTH(password) as plen, COUNT(*) as count 
            FROM hash_infos 
            WHERE password IS NOT NULL AND history_index = -1 
            GROUP BY plen 
            ORDER BY plen
        ''')
        password_lengths = cursor.fetchall()
        
        self.assertGreater(len(password_lengths), 0, "Should have password length statistics")
        
        # Check for common weak passwords
        cursor.execute('''
            SELECT password, COUNT(*) as count 
            FROM hash_infos 
            WHERE password IS NOT NULL AND history_index = -1 
            GROUP BY password 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        common_passwords = cursor.fetchall()
        
        self.assertGreater(len(common_passwords), 0, "Should have common password statistics")
        
        # Verify some expected weak passwords are present
        weak_passwords = ['password', '12345', 'iloveyou', 'Password', 'PASSWORD']
        found_weak_passwords = [pwd for pwd, count in common_passwords if pwd.lower() in [w.lower() for w in weak_passwords]]
        self.assertGreater(len(found_weak_passwords), 0, "Should find some common weak passwords")
        
        db_manager.close()
    
    def test_sample_data_domain_analysis(self):
        """Test domain-specific analysis with sample data."""
        config = Config(
            ntds_file=str(self.ntds_file),
            cracked_file=str(self.cracked_file),
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
        
        # Analyze by domain
        cursor = db_manager.cursor
        
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN username_full LIKE 'child.domain.com\\%' THEN 'child.domain.com'
                    WHEN username_full LIKE 'parent.domain.com\\%' THEN 'parent.domain.com'
                    WHEN username_full LIKE 'sister.domain.com\\%' THEN 'sister.domain.com'
                    ELSE 'other'
                END as domain,
                COUNT(*) as total_accounts,
                COUNT(CASE WHEN password IS NOT NULL THEN 1 END) as cracked_accounts
            FROM hash_infos 
            WHERE history_index = -1 
            GROUP BY domain
            ORDER BY total_accounts DESC
        ''')
        
        domain_stats = cursor.fetchall()
        
        # Verify domain analysis
        self.assertGreater(len(domain_stats), 0, "Should have domain statistics")
        
        # Check that we have the expected domains
        domains = [row[0] for row in domain_stats]
        self.assertIn('child.domain.com', domains)
        self.assertIn('parent.domain.com', domains)
        self.assertIn('sister.domain.com', domains)
        
        # Verify each domain has accounts
        for domain, total, cracked in domain_stats:
            self.assertGreater(total, 0, f"Domain {domain} should have accounts")
            self.assertGreaterEqual(cracked, 0, f"Domain {domain} should have non-negative cracked count")
            self.assertLessEqual(cracked, total, f"Domain {domain} cracked count should not exceed total")
        
        db_manager.close()
    
    def test_sample_data_command_line_execution(self):
        """Test command line execution with sample data."""
        # This test simulates running DPAT from command line with sample data
        test_args = [
            'dpat.py',
            '-n', str(self.ntds_file),
            '-c', str(self.cracked_file),
            '-p', '8',
            '-d', str(self.temp_dir),
            '-o', 'sample_test_report.html'
        ]
        
        with patch('sys.argv', test_args):
            # This should not raise an exception
            try:
                config = parse_arguments()
                self.assertEqual(config.ntds_file, str(self.ntds_file))
                self.assertEqual(config.cracked_file, str(self.cracked_file))
                self.assertEqual(config.min_password_length, 8)
                self.assertEqual(config.report_directory, str(self.temp_dir))
                self.assertEqual(config.output_file, 'sample_test_report.html')
            except SystemExit:
                # parse_arguments might call sys.exit, which is expected
                pass
    
    def test_sample_data_with_groups_command_line(self):
        """Test command line execution with groups option."""
        # Create groups directory
        groups_dir = self.temp_dir / "groups"
        groups_dir.mkdir()
        
        # Copy group files
        import shutil
        shutil.copy2(self.domain_admins_file, groups_dir / "Domain Admins.txt")
        shutil.copy2(self.enterprise_admins_file, groups_dir / "Enterprise Admins.txt")
        
        test_args = [
            'dpat.py',
            '-n', str(self.ntds_file),
            '-c', str(self.cracked_file),
            '-p', '8',
            '-g', str(groups_dir),
            '-d', str(self.temp_dir),
            '-o', 'sample_groups_report.html'
        ]
        
        with patch('sys.argv', test_args):
            try:
                config = parse_arguments()
                self.assertEqual(config.ntds_file, str(self.ntds_file))
                self.assertEqual(config.cracked_file, str(self.cracked_file))
                self.assertEqual(config.min_password_length, 8)
                self.assertEqual(config.groups_directory, str(groups_dir))
                self.assertEqual(config.report_directory, str(self.temp_dir))
            except SystemExit:
                pass


if __name__ == '__main__':
    unittest.main()
