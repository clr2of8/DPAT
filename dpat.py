#!/usr/bin/env python3
"""
Domain Password Audit Tool (DPAT) - Refactored Version

A comprehensive tool for analyzing domain password security based on NTDS dumps
and password cracking results. This refactored version follows better coding
standards, improved maintainability, and comprehensive documentation.

Author: Carrie Roberts @OrOneEqualsOne
Author: Dylan Evans @fin3ss3g0d
License: See LICENSE file
"""

import argparse
import binascii
import html
import io
import logging
import os
import re
import sqlite3
import sys
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from shutil import copyfile
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration class to hold all application settings."""
    ntds_file: str
    cracked_file: str
    output_file: str = "_DomainPasswordAuditReport.html"
    report_directory: str = "DPAT Report"
    groups_directory: Optional[str] = None
    min_password_length: int = 8
    sanitize_output: bool = False
    include_machine_accounts: bool = False
    include_krbtgt: bool = False
    kerberoast_file: Optional[str] = None
    kerberoast_encoding: str = 'cp1252'
    write_database: bool = False
    debug_mode: bool = False
    speed_mode: bool = False
    no_prompt: bool = False

    def __post_init__(self):
        """Post-initialization processing."""
        if self.sanitize_output:
            self.report_directory += " - Sanitized"
        
        # Ensure report directory exists
        Path(self.report_directory).mkdir(parents=True, exist_ok=True)


class NTDSProcessor:
    """Handles parsing and processing of NTDS files."""
    
    # Regex patterns for different NTDS formats
    NTDS_PATTERNS = [
        # DOMAIN\user:rest format
    re.compile(r'^(?P<domain>[^\\]+)\\(?P<user>[^:]+):(?P<nt>[0-9A-Fa-f]{32}).*$', re.I),
        # pwdump style format
    re.compile(r'^(?P<user>[^:]+):(?P<rid>\d+):(?P<lm>[0-9A-Fa-f]{32}|\*):(?P<nt>[0-9A-Fa-f]{32}|\*):.*$', re.I),
]
    
    @staticmethod
    def parse_ntds_line(line: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Parse a single NTDS line and extract username and NT hash.
        
        Args:
            line: Raw line from NTDS file
            
        Returns:
            Tuple of (username, nt_hash) or (None, None) if parsing fails
        """
        for pattern in NTDSProcessor.NTDS_PATTERNS:
            match = pattern.match(line.strip())
            if match:
                return match.group('user').lower(), match.group('nt').lower()
        return None, None

    @staticmethod
    def load_kerberoast_ntds(file_path: str, encoding: str = 'cp1252', debug: bool = False) -> List[Tuple[str, str]]:
        """
        Load Kerberoastable accounts from NTDS file.
        
        Args:
            file_path: Path to the NTDS file
            encoding: File encoding
            debug: Enable debug output
            
        Returns:
            List of tuples containing (username_full, nt_hash)
        """
        kerb_entries = []
        try:
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                for line_num, raw_line in enumerate(f, 1):
                    user, nt_hash = NTDSProcessor.parse_ntds_line(raw_line)
                    if user and nt_hash and nt_hash != '*' * 32:
                        kerb_entries.append((user, nt_hash))
                        if debug:
                            logger.debug(f"[kerb DEBUG] line {line_num}: {user}:{nt_hash}")
                    elif debug:
                        logger.debug(f"[kerb DEBUG] line {line_num}: skipped")
        except Exception as e:
            logger.error(f"Error loading Kerberoast file {file_path}: {e}")
                
        return kerb_entries

    def __init__(self, config: Config, db_manager: 'DatabaseManager'):
        """
        Initialize NTDS processor.
        
        Args:
            config: Application configuration
            db_manager: Database manager instance
        """
        self.config = config
        self.db_manager = db_manager
        self.accounts_read = 0
        self.accounts_filtered = 0
    
    def process_ntds_file(self) -> None:
        """Process the main NTDS file and populate database."""
        logger.info(f"Reading NTDS file: {self.config.ntds_file}")
        
        try:
            with open(self.config.ntds_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    self._process_ntds_line(line.strip())
                    
            self._log_processing_stats()
            
        except Exception as e:
            logger.error(f"Error processing NTDS file: {e}")
            raise
    
    def _process_ntds_line(self, line: str) -> None:
        """
        Process a single line from the NTDS file.
        
        Args:
            line: Line from NTDS file
        """
        if not line or ':' not in line:
            return
        
        parts = line.split(':')
        if len(parts) < 4:
            return
        
        self.accounts_read += 1
        
        username_full = parts[0]
        lm_hash = parts[2]
        nt_hash = parts[3]
        
        # Split LM hash into left and right parts
        lm_hash_left = lm_hash[:16]
        lm_hash_right = lm_hash[16:32]
        
        # Extract username from full username
        username = username_full.split('\\')[-1]
        
        # Handle password history
        history_base_username = username_full
        history_index = -1
        
        history_pattern = r"(?i)(.*\\*.*)_history([0-9]+)$"
        history_match = re.search(history_pattern, username_full)
        if history_match:
            history_base_username = history_match.group(1)
            history_index = int(history_match.group(2))
        
        # Apply account filtering
        if self._should_include_account(username):
            self._insert_account_data(
                username_full, username, lm_hash, lm_hash_left, 
                lm_hash_right, nt_hash, history_index, history_base_username
            )
        else:
            self.accounts_filtered += 1
    
    def _should_include_account(self, username: str) -> bool:
        """
        Determine if an account should be included based on filtering rules.
        
        Args:
            username: Username to check
            
        Returns:
            True if account should be included
        """
        # Exclude machine accounts (ending with $) unless explicitly included
        if not self.config.include_machine_accounts and username.endswith("$"):
            return False
        
        # Exclude krbtgt account unless explicitly included
        if not self.config.include_krbtgt and username == "krbtgt":
            return False
        
        return True
    
    def _insert_account_data(self, username_full: str, username: str, lm_hash: str,
                           lm_hash_left: str, lm_hash_right: str, nt_hash: str,
                           history_index: int, history_base_username: str) -> None:
        """
        Insert account data into database.
        
        Args:
            username_full: Full username (domain\\user)
            username: Username only
            lm_hash: LM hash
            lm_hash_left: Left part of LM hash
            lm_hash_right: Right part of LM hash
            nt_hash: NT hash
            history_index: Password history index
            history_base_username: Base username for history
        """
        sql = """
            INSERT INTO hash_infos 
            (username_full, username, lm_hash, lm_hash_left, lm_hash_right, 
             nt_hash, history_index, history_base_username) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        self.db_manager.cursor.execute(sql, (
            username_full, username, lm_hash, lm_hash_left, 
            lm_hash_right, nt_hash, history_index, history_base_username
        ))
    
    def _log_processing_stats(self) -> None:
        """Log processing statistics."""
        # Get total accounts processed
        self.db_manager.cursor.execute('SELECT count(*) FROM hash_infos WHERE history_index = -1')
        total_accounts = self.db_manager.cursor.fetchone()[0]
        
        logger.info(f"Read {self.accounts_read} accounts from NTDS file")
        if self.accounts_filtered > 0:
            logger.info(f"Filtered out {self.accounts_filtered} accounts (machine accounts, krbtgt)")
        logger.info(f"Processing {total_accounts} accounts for analysis")
    
    def update_group_membership(self, group_manager: 'GroupManager') -> None:
        """
        Update group membership flags in database.
        
        Args:
            group_manager: Group manager instance
        """
        for group_name, users in group_manager.group_users.items():
            for user in users:
                sql = f'UPDATE hash_infos SET "{group_name}" = 1 WHERE username_full = ?'
                self.db_manager.cursor.execute(sql, (user,))


class HashProcessor:
    """Handles password hashing and cracking operations."""
    
    @staticmethod
    def ntlm_hash(password: str) -> str:
        """
        Generate NT hash (MD4 over UTF-16LE) of a password.
        
        Args:
            password: Password to hash
            
        Returns:
            Lowercase hexadecimal hash string
            
        Raises:
            RuntimeError: If no MD4 backend is available
        """
        data = password.encode('utf-16le')
        
        # Try different MD4 backends in order of preference
        try:
            # 1) pycryptodome → Crypto.* (preferred since we know it's installed)
            from Crypto.Hash import MD4
            return MD4.new(data).hexdigest().lower()
        except Exception as e:
            logger.debug(f"[DEBUG] PyCryptodome (Crypto) MD4 failed: {e}")
        
        try:
            # 2) pycryptodomex (alternative) → Cryptodome.*
            from Cryptodome.Hash import MD4
            return MD4.new(data).hexdigest().lower()
        except Exception as e:
            logger.debug(f"[DEBUG] PyCryptodomex (Cryptodome) MD4 failed: {e}")
        
        try:
            # 3) hashlib (often unavailable for MD4)
            import hashlib
            return hashlib.new('md4', data).hexdigest().lower()
        except Exception as e:
            logger.debug(f"[DEBUG] hashlib md4 unavailable: {e}")
        
        try:
            # 4) passlib
            from passlib.hash import nthash
            return nthash.hash(password).lower()
        except Exception as e:
            logger.debug(f"[DEBUG] passlib nthash failed: {e}")
        
        try:
            # 5) impacket
            from impacket.ntlm import compute_nthash
            return compute_nthash(password).hex().lower()
        except Exception as e:
            logger.debug(f"[DEBUG] impacket compute_nthash failed: {e}")
        
        raise RuntimeError("No NT hash backend available. Install pycryptodome (or pycryptodomex) / passlib / impacket.")

    @staticmethod
    def generate_username_candidates(username: str, username_full: Optional[str] = None) -> Set[str]:
        """
        Generate password candidates based on username patterns.
        
        Args:
            username: Base username
            username_full: Full username (domain\\user format)
            
        Returns:
            Set of possible password candidates
        """
        candidates = set()
        
        for val in (username, username_full):
            if not val:
                continue
                
            val = val.strip()
            if not val:
                continue
                
            candidates.add(val)
            
            # Extract username from domain\\user format
            if '\\' in val:
                candidates.add(val.split('\\', 1)[1])
            
            # Extract username from user@domain format
            if '@' in val:
                candidates.add(val.split('@', 1)[0])
        
        # Generate case variants
        final_candidates = set()
        for candidate in candidates:
            if candidate:
                final_candidates.update([
                    candidate,
                    candidate.lower(),
                    candidate.upper(),
                    candidate.capitalize()
                ])
        
        return final_candidates
    
    @staticmethod
    def all_casings(input_string: str):
        """
        Generate all possible case combinations of a string.
        
        Args:
            input_string: String to generate case variants for
            
        Yields:
            All possible case combinations
        """
        if not input_string:
            yield ""
        else:
            first_char = input_string[:1]
            if first_char.lower() == first_char.upper():
                # Non-alphabetic character
                for sub_casing in HashProcessor.all_casings(input_string[1:]):
                    yield first_char + sub_casing
            else:
                # Alphabetic character - generate both cases
                for sub_casing in HashProcessor.all_casings(input_string[1:]):
                    yield first_char.lower() + sub_casing
                    yield first_char.upper() + sub_casing


class DataSanitizer:
    """Handles sanitization of sensitive data in reports."""
    
    @staticmethod
    def sanitize_value(value: str, should_sanitize: bool = True) -> str:
        """
        Sanitize a password or hash value for display.
        
        Args:
            value: Value to sanitize
            should_sanitize: Whether to apply sanitization
            
        Returns:
            Sanitized or original value
        """
        if not should_sanitize:
            return value
            
        if not value:
            return value
            
        length = len(value)
        if length == 32:
            # For 32-char hashes: show first 4 and last 4 chars
            return value[:4] + "*" * (length - 8) + value[-4:]
        elif length > 2:
            # For other strings: show first and last char
            return value[0] + "*" * (length - 2) + value[-1]
        else:
            return value
    
    @staticmethod
    def sanitize_table_row(row: Tuple, password_indices: List[int], hash_indices: List[int], 
                          should_sanitize: bool = True) -> Tuple:
        """
        Sanitize passwords and hashes in table rows.
        
        Args:
            row: Table row tuple
            password_indices: Column indices containing passwords
            hash_indices: Column indices containing hashes
            should_sanitize: Whether to apply sanitization
            
        Returns:
            Sanitized row tuple
        """
        if not should_sanitize:
            return row
        
        sanitized_row = list(row)
        
        # Sanitize password columns
        for idx in password_indices:
            if idx < len(sanitized_row) and sanitized_row[idx] is not None:
                sanitized_row[idx] = DataSanitizer.sanitize_value(str(sanitized_row[idx]))
        
        # Sanitize hash columns
        for idx in hash_indices:
            if idx < len(sanitized_row) and sanitized_row[idx] is not None:
                sanitized_row[idx] = DataSanitizer.sanitize_value(str(sanitized_row[idx]))
        
        return tuple(sanitized_row)


class HTMLReportBuilder:
    """Builds HTML reports with proper structure and styling."""
    
    def __init__(self, report_directory: str):
        """
        Initialize HTML report builder.
        
        Args:
            report_directory: Directory to save reports
        """
        self.report_directory = report_directory
        self.body_content = ""
        self.charts_data = []  # Store chart data for later initialization
    
    def add_content(self, content: str) -> None:
        """
        Add content to the HTML body.
        
        Args:
            content: HTML content to add
        """
        self.body_content += content + "\n<div class='section-space'></div>\n"
    
    def add_table(self, rows: Sequence[Sequence], headers: Sequence[str] = (), 
                  cols_to_not_escape: Union[int, Sequence[int], None] = (),
                  caption: Optional[str] = None) -> None:
        """
        Add a table to the HTML report.
        
        Args:
            rows: Table data rows
            headers: Column headers
            cols_to_not_escape: Column indices to not HTML escape
            caption: Table caption
        """
        if cols_to_not_escape is None:
            cols_to_not_escape = set()
        elif isinstance(cols_to_not_escape, int):
            cols_to_not_escape = {cols_to_not_escape}
        else:
            cols_to_not_escape = set(cols_to_not_escape)
        
        html_parts = ["<div class='table-wrap'>", "<table class='table table-striped table-hover datatable'>"]
        
        if caption:
            html_parts.append(f"<caption>{html.escape(caption)}</caption>")
        
        # Header
        html_parts.append("<thead><tr>")
        for header in headers:
            html_parts.append(f"<th>{'' if header is None else html.escape(str(header))}</th>")
        html_parts.append("</tr></thead>")
        
        # Body
        html_parts.append("<tbody>")
        for row in rows:
            html_parts.append("<tr>")
            for idx, cell in enumerate(row):
                cell_data = "" if cell is None else str(cell)
                if idx not in cols_to_not_escape:
                    cell_data = html.escape(cell_data)
                html_parts.append(f"<td>{cell_data}</td>")
            html_parts.append("</tr>")
        html_parts.append("</tbody></table></div>")
        
        self.add_content("".join(html_parts))
    
    def add_chart(self, chart_id: str, chart_type: str, data: dict, options: dict = None) -> None:
        """
        Add a Chart.js chart to the HTML report.
        
        Args:
            chart_id: Unique ID for the chart canvas
            chart_type: Type of chart (bar, pie, line, etc.)
            data: Chart data configuration
            options: Chart options configuration
        """
        if options is None:
            options = {}
        
        # Convert Python booleans to JavaScript booleans
        import json
        data_json = json.dumps(data)
        options_json = json.dumps(options)
        
        # Set width based on chart type
        width = "50%" if chart_type == "pie" else "100%"
        
        chart_html = f"""
<div class='table-wrap' style='text-align: center;'>
    <div class='chart-container' style='position: relative; width: {width}; margin: 20px auto; display: inline-block;'>
        <canvas id='{chart_id}'></canvas>
    </div>
</div>
"""
        self.add_content(chart_html)
        
        # Store chart data for later initialization
        self.charts_data.append({
            'id': chart_id,
            'type': chart_type,
            'data': data_json,
            'options': options_json
        })
    
    def generate_html(self) -> str:
        """
        Generate complete HTML document.
        
        Returns:
            Complete HTML document string
        """
        import json
        return (
            "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
            "<meta charset='utf-8'>\n<meta name='viewport' content='width=device-width,initial-scale=1'>\n"
            "<title>DPAT Report</title>\n"
            "<!-- Bootstrap 5 CSS -->\n"
            "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>\n"
            "<!-- DataTables Bootstrap 5 CSS -->\n"
            "<link href='https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css' rel='stylesheet'>\n"
            "<!-- Custom CSS -->\n"
            "<link rel='stylesheet' href='report.css'>\n"
            "</head>\n<body>\n"
            "<!-- Immediate theme application script -->\n"
            "<script>\n"
            "  // Apply theme immediately when HTML is parsed (before DOM ready)\n"
            "  (function() {\n"
            "    const savedTheme = localStorage.getItem('theme');\n"
            "    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;\n"
            "    \n"
            "    let isDark;\n"
            "    if (savedTheme !== null) {\n"
            "      isDark = savedTheme === 'dark';\n"
            "    } else {\n"
            "      isDark = prefersDark;\n"
            "    }\n"
            "    \n"
            "    if (isDark) {\n"
            "      document.documentElement.classList.add('dark-theme');\n"
            "    } else {\n"
            "      document.documentElement.classList.add('light-theme');\n"
            "    }\n"
            "  })();\n"
            "</script>\n"
            "<!-- Bootstrap 5 Navbar -->\n"
            "<nav class='navbar navbar-expand-lg navbar-dark bg-primary fixed-top'>\n"
            "  <div class='container-fluid'>\n"
            "    <a class='navbar-brand fw-bold' href='_DomainPasswordAuditReport.html'><img src='DPAT icon.png' alt='DPAT' width='30' height='30' style='margin-right: 8px; vertical-align: middle;'>DPAT Report</a>\n"
            "    <button class='navbar-toggler' type='button' data-bs-toggle='collapse' data-bs-target='#navbarNav'>\n"
            "      <span class='navbar-toggler-icon'></span>\n"
            "    </button>\n"
            "    <div class='collapse navbar-collapse' id='navbarNav'>\n"
            "      <ul class='navbar-nav ms-auto'>\n"
            "        <li class='nav-item'>\n"
            "          <button id='theme-toggle' class='btn btn-outline-light btn-sm' aria-label='Toggle dark mode'>\n"
            "            <span class='theme-toggle-icon'>🌙</span>\n"
            "          </button>\n"
            "        </li>\n"
            "      </ul>\n"
            "    </div>\n"
            "  </div>\n"
            "</nav>\n"
            "<!-- Main content with top padding for fixed navbar -->\n"
            "<div class='main-content'>\n"
            + self.body_content +
            "</div>\n"
            "<!-- Bootstrap 5 JS -->\n"
            "<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'></script>\n"
            "<!-- jQuery (required for DataTables) -->\n"
            "<script src='https://code.jquery.com/jquery-3.7.0.min.js'></script>\n"
            "<!-- DataTables JS -->\n"
            "<script src='https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js'></script>\n"
            "<script src='https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js'></script>\n"
            "<!-- Chart.js -->\n"
            "<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>\n"
            "<script>\n"
            "// Dark mode toggle functionality and DataTables initialization\n"
            "document.addEventListener('DOMContentLoaded', function() {\n"
            "  const themeToggle = document.getElementById('theme-toggle');\n"
            "  const themeIcon = themeToggle.querySelector('.theme-toggle-icon');\n"
            "  \n"
            "  // Set initial toggle button icon based on current theme\n"
            "  const isCurrentlyDark = document.documentElement.classList.contains('dark-theme');\n"
            "  if (isCurrentlyDark) {\n"
            "    themeIcon.textContent = '☀️';\n"
            "  } else {\n"
            "    themeIcon.textContent = '🌙';\n"
            "  }\n"
            "  \n"
            "  // Function to initialize DataTables\n"
            "  function initializeDataTables() {\n"
            "    $('.datatable').each(function() {\n"
            "      var table = $(this);\n"
            "      var columnCount = table.find('thead th').length;\n"
            "      var rowCount = table.find('tbody tr').length;\n"
            "      \n"
            "      // Configure DataTables with column-specific settings\n"
            "      var columnDefs = [];\n"
            "      \n"
            "      // If this is a summary table (4 columns), disable sorting/searching on last column\n"
            "      if (columnCount === 4) {\n"
            "        columnDefs.push({\n"
            "          targets: 3, // More Info column\n"
            "          orderable: false,\n"
            "          searchable: false\n"
            "        });\n"
            "      }\n"
            "      \n"
            "      // Destroy existing DataTable if it exists\n"
            "      if ($.fn.DataTable.isDataTable(table)) {\n"
            "        table.DataTable().destroy();\n"
            "      }\n"
            "      \n"
            "      // Configure DataTables based on table size\n"
            "      var config = {\n"
            "        responsive: true,\n"
            "        order: [],\n"
            "        columnDefs: columnDefs,\n"
            "        language: {\n"
            "          search: 'Search:',\n"
            "          lengthMenu: 'Show _MENU_ entries',\n"
            "          info: 'Showing _START_ to _END_ of _TOTAL_ entries',\n"
            "          infoEmpty: 'Showing 0 to 0 of 0 entries',\n"
            "          infoFiltered: '(filtered from _MAX_ total entries)',\n"
            "          paginate: {\n"
            "            first: 'First',\n"
            "            last: 'Last',\n"
            "            next: 'Next',\n"
            "            previous: 'Previous'\n"
            "          }\n"
            "        }\n"
            "      };\n"
            "      \n"
            "      // For large tables (like all_hashes.html), use server-side processing simulation\n"
            "      if (rowCount > 10000) {\n"
            "        config.pageLength = 50;\n"
            "        config.lengthMenu = [[25, 50, 100, 500], [25, 50, 100, 500]];\n"
            "        config.deferRender = true; // Defer rendering for better performance\n"
            "        config.scrollY = '600px'; // Fixed height with scrolling\n"
            "        config.scrollCollapse = true;\n"
            "        config.paging = true;\n"
            "        config.processing = true; // Show processing indicator\n"
            "        config.language.processing = 'Loading data...';\n"
            "      } else {\n"
            "        config.pageLength = 25;\n"
            "        config.lengthMenu = [[10, 25, 50, 100, -1], [10, 25, 50, 100, 'All']];\n"
            "      }\n"
            "      \n"
            "      table.DataTable(config);\n"
            "    });\n"
            "  }\n"
            "  \n"
            "  // Toggle theme on button click\n"
            "  themeToggle.addEventListener('click', function() {\n"
            "    const isCurrentlyDark = document.documentElement.classList.contains('dark-theme');\n"
            "    \n"
            "    if (isCurrentlyDark) {\n"
            "      document.documentElement.classList.remove('dark-theme');\n"
            "      document.documentElement.classList.add('light-theme');\n"
            "      themeIcon.textContent = '🌙';\n"
            "      localStorage.setItem('theme', 'light');\n"
            "    } else {\n"
            "      document.documentElement.classList.remove('light-theme');\n"
            "      document.documentElement.classList.add('dark-theme');\n"
            "      themeIcon.textContent = '☀️';\n"
            "      localStorage.setItem('theme', 'dark');\n"
            "    }\n"
            "    \n"
            "    // Reinitialize DataTables after theme change to fix layout issues\n"
            "    setTimeout(function() {\n"
            "      initializeDataTables();\n"
            "    }, 100);\n"
            "  });\n"
            "  \n"
            "  // Initialize DataTables for all tables (with delay for large tables)\n"
            "  setTimeout(function() {\n"
            "    initializeDataTables();\n"
            "  }, 50); // Small delay to ensure theme is applied first\n"
            "  \n"
            "  // Initialize charts after Chart.js loads\n"
            "  function initializeCharts() {\n"
            "    if (typeof Chart !== 'undefined') {\n"
            "      const chartsData = " + json.dumps(self.charts_data) + ";\n"
            "      chartsData.forEach(function(chartConfig) {\n"
            "        const ctx = document.getElementById(chartConfig.id).getContext('2d');\n"
            "        new Chart(ctx, {\n"
            "          type: chartConfig.type,\n"
            "          data: JSON.parse(chartConfig.data),\n"
            "          options: JSON.parse(chartConfig.options)\n"
            "        });\n"
            "      });\n"
            "    } else {\n"
            "      // Chart.js not loaded yet, try again in 100ms\n"
            "      setTimeout(initializeCharts, 100);\n"
            "    }\n"
            "  }\n"
            "  \n"
            "  // Start chart initialization\n"
            "  initializeCharts();\n"
            "});\n"
            "</script>\n"
            "</body>\n</html>\n"
        )
    
    def write_report(self, filename: str) -> str:
        """
        Write HTML report to file.
        
        Args:
            filename: Output filename
            
        Returns:
            The filename that was written
        """
        file_path = Path(self.report_directory) / filename
        
        # Copy CSS file
        css_source = Path(__file__).parent / "report.css"
        css_dest = Path(self.report_directory) / "report.css"
        if css_source.exists():
            copyfile(css_source, css_dest)
        
        # Copy DPAT icon file
        icon_source = Path(__file__).parent / "img" / "DPAT icon.png"
        icon_dest = Path(self.report_directory) / "DPAT icon.png"
        if icon_source.exists():
            copyfile(icon_source, icon_dest)
        
        # Write HTML file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_html())
        
        logger.info(f"Report written: {file_path}")
        return filename


class DatabaseManager:
    """Manages SQLite database operations."""
    
    def __init__(self, config: Config):
        """
        Initialize database manager.
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.connection = None
        self.cursor = None
        self._connect()
    
    def _connect(self) -> None:
        """Establish database connection."""
        if self.config.write_database:
            db_path = "pass_audit.db"
            if os.path.exists(db_path):
                os.remove(db_path)
            self.connection = sqlite3.connect(db_path)
        elif self.config.speed_mode:
            self.connection = sqlite3.connect("pass_audit.db")
        else:
            self.connection = sqlite3.connect(':memory:')
        
        self.connection.text_factory = str
        self.cursor = self.connection.cursor()
        logger.info("Database connection established")
    
    def create_schema(self, group_names: List[str]) -> None:
        """
        Create database schema with group columns.
        
        Args:
            group_names: List of group names to create columns for
        """
        # Create main table
        self.cursor.execute('''
            CREATE TABLE hash_infos (
                username_full text collate nocase,
                username text collate nocase,
                lm_hash text,
                lm_hash_left text,
                lm_hash_right text,
                nt_hash text,
                password text,
                lm_pass_left text,
                lm_pass_right text,
                only_lm_cracked boolean,
                history_index int,
                history_base_username text
            )
        ''')
        
        # Create indexes
        indexes = [
            "CREATE INDEX index_nt_hash ON hash_infos (nt_hash)",
            "CREATE INDEX index_lm_hash_left ON hash_infos (lm_hash_left)",
            "CREATE INDEX index_lm_hash_right ON hash_infos (lm_hash_right)",
            "CREATE INDEX lm_hash ON hash_infos (lm_hash)",
            "CREATE INDEX username ON hash_infos (username)"
        ]
        
        for index_sql in indexes:
            self.cursor.execute(index_sql)
        
        # Create group columns
        for group_name in group_names:
            sql = f'ALTER TABLE hash_infos ADD COLUMN "{group_name}" boolean'
            self.cursor.execute(sql)
        
        logger.info(f"Database schema created with {len(group_names)} group columns")
    
    def close(self) -> None:
        """Close database connection."""
        if self.connection:
            self.connection.commit()
            self.connection.close()
            logger.info("Database connection closed")


class GroupManager:
    """Manages group membership processing and file handling."""
    
    def __init__(self, config: Config):
        """
        Initialize group manager.
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.groups = []  # List of (group_name, file_path) tuples
        self.group_users = {}  # Dict of {group_name: [usernames]}
    
    def load_groups(self) -> None:
        """Load group files from the specified directory."""
        if not self.config.groups_directory:
            logger.info("No groups directory specified")
            return
        
        group_dir = Path(self.config.groups_directory)
        if not group_dir.is_dir():
            logger.error(f"Groups directory does not exist: {group_dir}")
            return
        
        logger.info(f"Loading group files from: {group_dir}")
        
        # Files to exclude from group processing
        exclude_files = {'.ntds', '.pot', '.potfile', '.dit'}
        
        for file_path in sorted(group_dir.iterdir()):
            if file_path.is_file():
                # Skip non-group files
                if any(file_path.suffix.lower() in exclude_files for exclude in exclude_files):
                    logger.debug(f"Skipping non-group file: {file_path.name}")
                    continue
                    
                try:
                    self._process_group_file(file_path)
                except Exception as e:
                    logger.error(f"Error processing group file {file_path}: {e}")
    
    def _process_group_file(self, file_path: Path) -> None:
        """
        Process a single group file.
        
        Args:
            file_path: Path to the group file
        """
        logger.info(f"Processing group file: {file_path.name}")
        
        try:
            with open(file_path, 'r', encoding=self.config.kerberoast_encoding) as f:
                # Skip empty lines to find first non-empty line
                first_line = ""
                for line in f:
                    line = line.strip()
                    if line:
                        first_line = line
                        break
                
                logger.debug(f"First non-empty line: '{first_line}'")
                
                if first_line:
                    # Use filename (without extension) as group name
                    group_name = file_path.stem
                    self.groups.append((group_name, str(file_path)))
                    logger.info(f"Loaded group '{group_name}' from file: {file_path.name}")
                else:
                    logger.warning(f"Skipped empty file: {file_path.name}")
        except Exception as e:
            logger.error(f"Error reading group file {file_path}: {e}")
    
    def load_group_members(self) -> None:
        """Load members for each group."""
        for group_name, file_path in self.groups:
            try:
                users = self._load_group_members_from_file(file_path)
                self.group_users[group_name] = users
                logger.info(f"Group '{group_name}' has {len(users)} members")
            except Exception as e:
                logger.error(f"Error loading members for group '{group_name}': {e}")
                self.group_users[group_name] = []
    
    def _load_group_members_from_file(self, file_path: str) -> List[str]:
        """
        Load group members from a file.
        
        Args:
            file_path: Path to the group file
            
        Returns:
            List of usernames
        """
        users = []
        
        # Try different encodings
        encodings_to_try = ['utf-16', 'utf-8', self.config.kerberoast_encoding]
        
        for encoding in encodings_to_try:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    user_domain = ""
                    user_name = ""
                    
                    for line in f:
                        line = line.strip()
                        if not line:  # Skip empty lines
                            continue

                        if "MemberDomain" in line:
                            user_domain = line.split(":")[1].strip()
                        elif "MemberName" in line:
                            user_name = line.split(":")[1].strip()
                            users.append(f"{user_domain}\\{user_name}")
                    
                    if not users:
                        # Try simple username list format
                        f.seek(0)
                        for line in f:
                            username = line.strip()
                            if username and not username.startswith('\x00'):  # Skip null bytes
                                users.append(username)
                    
                    # If we got valid users, break out of encoding loop
                    if users and not any('\x00' in user for user in users[:3]):
                        break
                    else:
                        users = []  # Reset if we got invalid data
                        
            except Exception as e:
                logger.debug(f"Failed to read {file_path} with encoding {encoding}: {e}")
                users = []  # Reset on error
                continue

        if not users:
            logger.error(f"Could not read group file {file_path} with any encoding")
            
        return users


class CrackedPasswordProcessor:
    """Handles processing of cracked password files."""
    
    def __init__(self, config: Config, db_manager: DatabaseManager):
        """
        Initialize cracked password processor.
        
        Args:
            config: Application configuration
            db_manager: Database manager instance
        """
        self.config = config
        self.db_manager = db_manager
    
    def process_cracked_file(self) -> None:
        """Process the cracked password file."""
        logger.info(f"Reading cracked password file: {self.config.cracked_file}")
        
        try:
            with open(self.config.cracked_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    self._process_cracked_line(line.strip())
                    
        except Exception as e:
            logger.error(f"Error processing cracked file: {e}")
            raise
    
    def _process_cracked_line(self, line: str) -> None:
        """
        Process a single line from the cracked password file.
        
        Args:
            line: Line from cracked password file
        """
        if ':' not in line:
            return
        
        colon_index = line.find(':')
        hash_value = line[:colon_index]
        password = line[colon_index + 1:]
        
        # Handle John the Ripper format ($NT$ and $LM$ prefixes)
        is_jtr = False
        if hash_value.startswith('$NT$') or hash_value.startswith('$LM$'):
            hash_value = hash_value.lstrip('$NT$').lstrip('$LM$')
            is_jtr = True
        
        # Handle hex encoded passwords
        if re.match(r"\$HEX\[([^\]]+)", password) and not is_jtr:
            password = self._decode_hex_password(password)
        
        # Update database based on hash length
        hash_length = len(hash_value)
        if hash_length == 32:  # NT hash
            self._update_nt_hash_password(hash_value, password)
        elif hash_length == 16:  # LM hash
            self._update_lm_hash_password(hash_value, password)
    
    def _decode_hex_password(self, password: str) -> str:
        """
        Decode hex-encoded password.
        
        Args:
            password: Hex-encoded password string
            
        Returns:
            Decoded password string
        """
        try:
            hex_match = re.findall(r"\$HEX\[([^\]]+)", password)
            if hex_match:
                hex_data = binascii.unhexlify(hex_match[-1])
                return ''.join(chr(x) if isinstance(x, int) else x for x in hex_data)
        except Exception as e:
            logger.debug(f"Error decoding hex password: {e}")
        
        return password
    
    def _update_nt_hash_password(self, hash_value: str, password: str) -> None:
        """
        Update NT hash with cracked password.
        
        Args:
            hash_value: NT hash
            password: Cracked password
        """
        sql = "UPDATE hash_infos SET password = ? WHERE nt_hash = ?"
        self.db_manager.cursor.execute(sql, (password, hash_value))
    
    def _update_lm_hash_password(self, hash_value: str, password: str) -> None:
        """
        Update LM hash with cracked password.
        
        Args:
            hash_value: LM hash
            password: Cracked password
        """
        sql_left = "UPDATE hash_infos SET lm_pass_left = ? WHERE lm_hash_left = ?"
        sql_right = "UPDATE hash_infos SET lm_pass_right = ? WHERE lm_hash_right = ?"
        
        self.db_manager.cursor.execute(sql_left, (password, hash_value))
        self.db_manager.cursor.execute(sql_right, (password, hash_value))
    
    def perform_lm_cracking(self) -> None:
        """Perform additional LM-based NT hash cracking."""
        sql = '''
            SELECT nt_hash, lm_pass_left, lm_pass_right 
            FROM hash_infos 
            WHERE (lm_pass_left IS NOT NULL OR lm_pass_right IS NOT NULL) 
              AND password IS NULL 
              AND lm_hash != "aad3b435b51404eeaad3b435b51404ee" 
            GROUP BY nt_hash
        '''
        
        rows = self.db_manager.cursor.execute(sql).fetchall()
        count = len(rows)
        
        if count > 0:
            logger.info(f"Cracking {count} NT hashes where only LM hash was cracked")
            
            for nt_hash, lm_pass_left, lm_pass_right in rows:
                password = self._crack_nt_from_lm(nt_hash, lm_pass_left, lm_pass_right)
                if password:
                    self._update_cracked_password(nt_hash, password)
    
    def _crack_nt_from_lm(self, nt_hash: str, lm_pass_left: Optional[str], 
                          lm_pass_right: Optional[str]) -> Optional[str]:
        """
        Attempt to crack NT hash from LM password parts.
        
        Args:
            nt_hash: NT hash to crack
            lm_pass_left: Left part of LM password
            lm_pass_right: Right part of LM password
            
        Returns:
            Cracked password or None
        """
        lm_password = ""
        if lm_pass_left:
            lm_password += lm_pass_left
        if lm_pass_right:
            lm_password += lm_pass_right
        
        try:
            for password_guess in HashProcessor.all_casings(lm_password):
                try:
                    computed_hash = HashProcessor.ntlm_hash(password_guess)
                    if nt_hash.lower() == computed_hash.lower():
                        return password_guess
                except RuntimeError as e:
                    logger.error(f"NT hash backend unavailable for cracking: {e}")
                    break
        except Exception as e:
            logger.debug(f"Error during LM cracking: {e}")
        
        return None
    
    def _update_cracked_password(self, nt_hash: str, password: str) -> None:
        """
        Update database with cracked password.
        
        Args:
            nt_hash: NT hash
            password: Cracked password
        """
        sql = '''
            UPDATE hash_infos 
            SET only_lm_cracked = 1, password = ? 
            WHERE nt_hash = ?
        '''
        self.db_manager.cursor.execute(sql, (password, nt_hash))


def calculate_percentage(part: int, whole: int) -> float:
    """
    Calculate percentage with safe division.
    
    Args:
        part: Part value
        whole: Whole value
        
    Returns:
        Percentage as float, 0.0 if division by zero
    """
    try:
        return round((part / whole) * 100, 2)
    except ZeroDivisionError:
        return 0.0


def parse_arguments() -> Config:
    """
    Parse command line arguments and return configuration.
    
    Returns:
        Configuration object
    """
    parser = argparse.ArgumentParser(
        description='Domain Password Audit Tool - Analyzes NTDS dumps and password cracking results',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -n customer.ntds -c hashcat.potfile -p 8
  %(prog)s -n customer.ntds -c hashcat.potfile -p 8 -g groups/ -s
  %(prog)s -n customer.ntds -c hashcat.potfile -p 8 -kz kerberoast.txt
        """
    )
    
    parser.add_argument('-n', '--ntdsfile', required=True,
                       help='NTDS file name (output from SecretsDump.py)')
    parser.add_argument('-c', '--crackfile', required=True,
                       help='Password cracking output file (hashcat.potfile format)')
    parser.add_argument('-o', '--outputfile', default='_DomainPasswordAuditReport.html',
                       help='HTML report output filename (default: %(default)s)')
    parser.add_argument('-d', '--reportdirectory', default='DPAT Report',
                       help='Output directory for HTML reports (default: %(default)s)')
    parser.add_argument('-g', '--groupsdirectory',
                       help='Directory containing group membership files')
    parser.add_argument('-p', '--minpasslen', type=int, required=True,
                       help='Minimum password length defined in domain policy')
    parser.add_argument('-s', '--sanitize', action='store_true',
                       help='Sanitize passwords and hashes in reports')
    parser.add_argument('-m', '--machineaccts', action='store_true',
                       help='Include machine accounts in analysis')
    parser.add_argument('-k', '--krbtgt', action='store_true',
                       help='Include krbtgt account in analysis')
    parser.add_argument('-kz', '--kerbfile',
                       help='File containing Kerberoastable accounts')
    parser.add_argument('--ch-encoding', default='cp1252',
                       help='Encoding for Kerberoast files (default: %(default)s)')
    parser.add_argument('-w', '--writedb', action='store_true',
                       help='Write SQLite database to disk for inspection')
    parser.add_argument('-dbg', '--debug', action='store_true',
                       help='Enable debug output')
    parser.add_argument('--no-prompt', action='store_true',
                       help='Skip browser prompt (useful for testing/automation)')
    
    args = parser.parse_args()
    
    return Config(
        ntds_file=args.ntdsfile,
        cracked_file=args.crackfile,
        output_file=args.outputfile,
        report_directory=args.reportdirectory,
        groups_directory=args.groupsdirectory,
        min_password_length=args.minpasslen,
        sanitize_output=args.sanitize,
        include_machine_accounts=args.machineaccts,
        include_krbtgt=args.krbtgt,
        kerberoast_file=args.kerbfile,
        kerberoast_encoding=args.ch_encoding,
        write_database=args.writedb,
        debug_mode=args.debug,
        no_prompt=args.no_prompt
    )


def prompt_user_to_open_report(config: Config) -> None:
    """Prompt user to open the report in browser."""
    try:
        if config.no_prompt:
            # Skip browser prompt when --no-prompt is specified
            logger.info(f"Report available at: {os.path.join(config.report_directory, config.output_file)}")
            return
        
        # Default behavior: prompt user to open the report
        print('Would you like to open the report now? [Y/n]')
        while True:
            response = input().lower().strip()
            if response in ('', 'y', 'yes'):
                report_path = os.path.join("file://" + os.getcwd(), 
                                         config.report_directory, 
                                         config.output_file)
                webbrowser.open(report_path)
                break
            elif response in ('n', 'no'):
                break
            else:
                print("Please respond with y or n")
    except KeyboardInterrupt:
        logger.info("Report opening cancelled")


def main():
    """Main application entry point."""
    try:
        # Initialize groups summary entry variable
        groups_summary_entry = None
        
        # Parse configuration
        config = parse_arguments()
        
        # Set debug logging if requested
        if config.debug_mode:
            logging.getLogger().setLevel(logging.DEBUG)
        
        logger.info("DPAT - Domain Password Audit Tool (Refactored)")
        logger.info(f"Processing NTDS file: {config.ntds_file}")
        logger.info(f"Processing cracked file: {config.cracked_file}")
        
        # Initialize components
        db_manager = DatabaseManager(config)
        group_manager = GroupManager(config)
        ntds_processor = NTDSProcessor(config, db_manager)
        cracked_processor = CrackedPasswordProcessor(config, db_manager)
        sanitizer = DataSanitizer()
        
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
        
        # Check for LM hashes cracked where NT hash was not cracked BEFORE performing LM cracking
        db_manager.cursor.execute('''SELECT lm_hash, lm_pass_left, lm_pass_right, nt_hash 
                                    FROM hash_infos 
                                    WHERE (lm_pass_left IS NOT NULL OR lm_pass_right IS NOT NULL) 
                                    AND history_index = -1 
                                    AND password IS NULL 
                                    AND lm_hash != "aad3b435b51404eeaad3b435b51404ee" 
                                    GROUP BY lm_hash''')
        lm_cracked_nt_not_rows = db_manager.cursor.fetchall()
        
        # Store this for later use in the summary table
        lm_cracked_count = len(lm_cracked_nt_not_rows)
        
        # Now perform LM cracking
        cracked_processor.perform_lm_cracking()
        
        # Create groups summary entry if groups were processed
        if config.groups_directory and group_manager.groups:
            groups_summary_entry = (len(group_manager.groups), None, "Group Cracking Statistics", "groups_stats.html")
        
        # Generate comprehensive reports
        logger.info("Generating comprehensive reports...")
        
        # Get total hash count
        db_manager.cursor.execute('SELECT count(*) FROM hash_infos WHERE history_index = -1')
        total_hashes = db_manager.cursor.fetchone()[0]
        
        if total_hashes == 0:
            logger.warning("No password hashes found in NTDS file")
            logger.info("Exiting gracefully...")
            sys.exit(0)
        
        # Generate all hashes report
        sql = '''
            SELECT username_full, password, LENGTH(password) as plen, nt_hash, only_lm_cracked 
            FROM hash_infos 
            WHERE history_index = -1 
            ORDER BY plen DESC, password
        '''
        
        rows = db_manager.cursor.execute(sql).fetchall()
        sanitized_rows = [sanitizer.sanitize_table_row(row, [1], [3], config.sanitize_output) 
                         for row in rows]
        
        report_builder = HTMLReportBuilder(config.report_directory)
        report_builder.add_table(sanitized_rows, 
                               ["Username", "Password", "Password Length", "NT Hash", "Only LM Cracked"])
        report_builder.write_report("all_hashes.html")
        
        # Initialize summary table
        summary_table = []
        summary_table.append((len(rows), None, "Password Hashes", '<a href="all_hashes.html">Details</a>'))
        
        
        # Unique hashes
        db_manager.cursor.execute('SELECT count(DISTINCT nt_hash) FROM hash_infos WHERE history_index = -1')
        unique_hashes = db_manager.cursor.fetchone()[0]
        unique_percent = calculate_percentage(unique_hashes, total_hashes)
        summary_table.append((unique_hashes, unique_percent, "Unique Password Hashes", None))
        
        # Calculate total number of duplicate password hashes
        duplicate_hashes = total_hashes - unique_hashes
        duplicate_percent = calculate_percentage(duplicate_hashes, total_hashes)
        summary_table.append((duplicate_hashes, duplicate_percent, "Duplicate Password Hashes Identified Through Audit", None))
        
        # Cracked passwords
        db_manager.cursor.execute('SELECT count(*) FROM hash_infos WHERE password IS NOT NULL AND history_index = -1')
        cracked_count = db_manager.cursor.fetchone()[0]
        cracked_percent = calculate_percentage(cracked_count, total_hashes)
        summary_table.append((cracked_count, cracked_percent, "Passwords Discovered Through Cracking", None))
        
        # Number of UNIQUE passwords that were cracked
        db_manager.cursor.execute('''SELECT count(DISTINCT password) 
                                    FROM hash_infos 
                                    WHERE password IS NOT NULL AND history_index = -1''')
        unique_passwords_cracked = db_manager.cursor.fetchone()[0]
        unique_passwords_percent = calculate_percentage(unique_passwords_cracked, total_hashes)
        summary_table.append((unique_passwords_cracked, unique_passwords_percent, 
                            "Unique Passwords Discovered Through Cracking", None))
        
        # Kerberoastable Accounts
        if config.kerberoast_file:
            logger.info(f"Processing Kerberoastable file: {config.kerberoast_file}")
            kerb_rows = NTDSProcessor.load_kerberoast_ntds(config.kerberoast_file, config.kerberoast_encoding, config.debug_mode)
            
            if kerb_rows:
                # Extract unique usernames from kerberoast entries
                kerb_usernames = tuple({u for u, _ in kerb_rows})  # de-dupe set → tuple
                total_kerb_accts = len(kerb_usernames)
                placeholders = ",".join("?" * total_kerb_accts)
                
                db_manager.cursor.execute(f'''
                    SELECT username_full, nt_hash, password
                    FROM   hash_infos
                    WHERE  username_full IN ({placeholders})
                      AND  password IS NOT NULL
                      AND  history_index = -1
                ''', kerb_usernames)
                cracked_kerb_rows = db_manager.cursor.fetchall()
                
                if cracked_kerb_rows:
                    # Sanitize passwords and hashes in the data
                    sanitized_kerb_rows = [sanitizer.sanitize_table_row(row, [2], [1], config.sanitize_output) 
                                         for row in cracked_kerb_rows]  # password at index 2, nt_hash at index 1
                    
                    kerb_builder = HTMLReportBuilder(config.report_directory)
                    kerb_builder.add_table(sanitized_kerb_rows, 
                                         ["Username", "NT Hash", "Password"], cols_to_not_escape=2)
                    kerb_filename = kerb_builder.write_report("kerberoast_cracked.html")
                    
                    # Calculate percentage of roastable accounts that are cracked
                    kerb_percent = calculate_percentage(len(cracked_kerb_rows), total_hashes)
                    
                    summary_table.append((
                        len(cracked_kerb_rows), kerb_percent,
                        "Cracked Kerberoastable Accounts",
                        f'<a href="{kerb_filename}">Details</a>'
                    ))
                    logger.info(f"Kerberoast cracked report written: {kerb_filename} "
                              f"({len(cracked_kerb_rows)} / {total_hashes} = {kerb_percent}% cracked)")
                else:
                    logger.info("No Kerberoastable accounts were cracked.")
            else:
                logger.warning("Kerberoastable file contained no valid NTDS lines.")
        
        # Insert groups summary entry if groups were processed
        if groups_summary_entry is not None:
            # Create proper HTML link for groups summary entry
            groups_link = f'<a href="{groups_summary_entry[3]}">Details</a>'
            groups_entry_with_link = (groups_summary_entry[0], groups_summary_entry[1], groups_summary_entry[2], groups_link)
            summary_table.append(groups_entry_with_link)
        
        # Password Policy Violations
        db_manager.cursor.execute(f'SELECT count(*) FROM hash_infos WHERE LENGTH(password) < ? AND password IS NOT NULL AND history_index = -1', (config.min_password_length,))
        policy_violations = db_manager.cursor.fetchone()[0]
        policy_percent = calculate_percentage(policy_violations, cracked_count) if cracked_count > 0 else 0
        
        if policy_violations > 0:
            db_manager.cursor.execute(f'''SELECT username_full, password, LENGTH(password) as plen, nt_hash 
                                        FROM hash_infos 
                                        WHERE LENGTH(password) < ? AND password IS NOT NULL AND history_index = -1
                                        ORDER BY plen''', (config.min_password_length,))
            policy_rows = db_manager.cursor.fetchall()
            sanitized_policy_rows = [sanitizer.sanitize_table_row(row, [1], [3], config.sanitize_output) 
                                   for row in policy_rows]
            
            policy_builder = HTMLReportBuilder(config.report_directory)
            policy_builder.add_table(sanitized_policy_rows, 
                                   ["Username", "Password", "Password Length", "NT Hash"])
            policy_filename = policy_builder.write_report("password_policy_violations.html")
            summary_table.append((policy_violations, policy_percent, "Password Policy Violations", f'<a href="{policy_filename}">Details</a>'))
        
        # Username equals password (cracked)
        db_manager.cursor.execute('''SELECT username_full, password, LENGTH(password) as plen, nt_hash 
                                    FROM hash_infos 
                                    WHERE password IS NOT NULL AND history_index = -1 
                                    AND LOWER(username) = LOWER(password)''')
        username_password_rows = db_manager.cursor.fetchall()
        
        if username_password_rows:
            sanitized_up_rows = [sanitizer.sanitize_table_row(row, [1], [3], config.sanitize_output) 
                               for row in username_password_rows]
            
            up_builder = HTMLReportBuilder(config.report_directory)
            up_builder.add_table(sanitized_up_rows, 
                               ["Username", "Password", "Password Length", "NT Hash"])
            up_filename = up_builder.write_report("username_equals_password.html")
            up_percent = calculate_percentage(len(username_password_rows), cracked_count) if cracked_count > 0 else 0
            summary_table.append((len(username_password_rows), up_percent, "Accounts Using Username As Password", f'<a href="{up_filename}">Details</a>'))
        else:
            # Always show the row, even if there are no accounts
            up_percent = 0
            summary_table.append((0, up_percent, "Accounts Using Username As Password", None))
        
        # Username equals password (by hash comparison) - for non-cracked passwords
        hash_processor = HashProcessor()
        already_flagged = set()
        
        # Track users already found by the cracked password check to avoid duplicates
        if username_password_rows:
            already_flagged.update(row[0].split('\\')[-1] for row in username_password_rows)  # Extract username from username_full
        
        # Get all accounts with NT hashes for hash comparison
        db_manager.cursor.execute('''SELECT username_full, username, nt_hash, password 
                                    FROM hash_infos 
                                    WHERE history_index = -1 
                                    AND nt_hash IS NOT NULL 
                                    AND username IS NOT NULL''')
        hash_comparison_rows = db_manager.cursor.fetchall()
        
        offenders_hashed = []
        
        for username_full, username, nt_hash, cracked_password in hash_comparison_rows:
            # Skip if already flagged by cracked password check
            if username in already_flagged:
                continue
            
            # Quick check: if we have a cracked password, check equality one more time (case-insensitive)
            if cracked_password:
                if cracked_password.lower() == username.lower():
                    offenders_hashed.append((username_full, cracked_password, len(cracked_password), nt_hash))
                    continue
            
            # Generate username-based password candidates and compare by NT hash
            candidates = hash_processor.generate_username_candidates(username, username_full)
            
            try:
                target_hash = nt_hash.lower()
            except Exception:
                target_hash = nt_hash
            
            matched = False
            for candidate in candidates:
                try:
                    candidate_hash = hash_processor.ntlm_hash(candidate)
                    if candidate_hash.lower() == target_hash:
                        offenders_hashed.append((username_full, candidate, len(candidate), nt_hash))
                        matched = True
                        break
                except RuntimeError as e:
                    logger.debug(f"NT hash backend unavailable: {e}")
                    break
            
            if matched:
                already_flagged.add(username)  # Prevent duplicates
        
        if offenders_hashed:
            sanitized_hash_rows = [sanitizer.sanitize_table_row(row, [1], [3], config.sanitize_output) 
                                 for row in offenders_hashed]
            
            hash_builder = HTMLReportBuilder(config.report_directory)
            hash_builder.add_table(sanitized_hash_rows, 
                                 ["Username", "Derived Password (from username)", "Password Length", "NT Hash"])
            hash_filename = hash_builder.write_report("username_equals_password_by_hash.html")
            hash_percent = calculate_percentage(len(offenders_hashed), total_hashes)
            summary_table.append((len(offenders_hashed), hash_percent, "Accounts Using Username As Password Not Cracked (by hash)", f'<a href="{hash_filename}">Details</a>'))
        else:
            # Always show the row, even if there are no accounts
            summary_table.append((0, 0, "Accounts Using Username As Password Not Cracked (by hash)", None))
        
        # LM Hash Statistics
        db_manager.cursor.execute('SELECT count(*) FROM hash_infos WHERE lm_hash != "aad3b435b51404eeaad3b435b51404ee" AND history_index = -1')
        lm_hashes = db_manager.cursor.fetchone()[0]
        lm_percent = calculate_percentage(lm_hashes, total_hashes)
        summary_table.append((lm_hashes, lm_percent, "LM Hashes (Non-blank)", None))
        
        db_manager.cursor.execute('SELECT count(DISTINCT lm_hash) FROM hash_infos WHERE lm_hash != "aad3b435b51404eeaad3b435b51404ee" AND history_index = -1')
        unique_lm_hashes = db_manager.cursor.fetchone()[0]
        unique_lm_percent = calculate_percentage(unique_lm_hashes, total_hashes)
        summary_table.append((unique_lm_hashes, unique_lm_percent, "Unique LM Hashes (Non-blank)", None))
        
        # Passwords only cracked via LM
        db_manager.cursor.execute('''SELECT username_full, password, LENGTH(password) as plen, only_lm_cracked 
                                    FROM hash_infos 
                                    WHERE only_lm_cracked = 1 AND history_index = -1 
                                    ORDER BY plen''')
        lm_only_rows = db_manager.cursor.fetchall()
        
        if lm_only_rows:
            sanitized_lm_only_rows = [sanitizer.sanitize_table_row(row, [1], [], config.sanitize_output) 
                                     for row in lm_only_rows]
            
            lm_only_builder = HTMLReportBuilder(config.report_directory)
            lm_only_builder.add_table(sanitized_lm_only_rows, 
                                    ["Username", "Password", "Password Length", "Only LM Cracked"])
            lm_only_filename = lm_only_builder.write_report("users_only_cracked_through_lm.html")
            lm_only_percent = calculate_percentage(len(lm_only_rows), total_hashes)
            summary_table.append((len(lm_only_rows), lm_only_percent, "Passwords Only Cracked via LM Hash", f'<a href="{lm_only_filename}">Details</a>'))
        
        # Add LM hash analysis if we found any
        if lm_cracked_count > 0:
            # Generate the LM noncracked report
            sanitized_lm_rows = [sanitizer.sanitize_table_row(row, [1, 2], [0, 3], config.sanitize_output) 
                               for row in lm_cracked_nt_not_rows]
            
            lm_builder = HTMLReportBuilder(config.report_directory)
            lm_builder.add_table(sanitized_lm_rows, 
                               ["LM Hash", "Left Portion of Password", "Right Portion of Password", "NT Hash"])
            lm_filename = lm_builder.write_report("lm_noncracked.html")
            lm_cracked_percent = calculate_percentage(lm_cracked_count, total_hashes)
            summary_table.append((lm_cracked_count, lm_cracked_percent, "Unique LM Hashes Cracked Where NT Hash Was Not Cracked", f'<a href="{lm_filename}">Details</a>'))
        else:
            # Always show the row, even if there are no accounts
            summary_table.append((0, 0, "Unique LM Hashes Cracked Where NT Hash Was Not Cracked", None))
        
        # Top Password Statistics
        db_manager.cursor.execute('''SELECT password, COUNT(password) as count 
                                    FROM hash_infos 
                                    WHERE password IS NOT NULL AND history_index = -1 AND password != "" 
                                    GROUP BY password ORDER BY count DESC LIMIT 20''')
        top_password_rows = db_manager.cursor.fetchall()
        
        if top_password_rows:
            sanitized_top_rows = [sanitizer.sanitize_table_row(row, [0], [], config.sanitize_output) 
                                for row in top_password_rows]
            
            top_builder = HTMLReportBuilder(config.report_directory)
            top_builder.add_table(sanitized_top_rows, ["Password", "Count"])
            top_filename = top_builder.write_report("top_password_stats.html")
            summary_table.append((None, None, "Top Password Use Stats", f'<a href="{top_filename}">Details</a>'))
        
        # Password Length Statistics
        db_manager.cursor.execute('''SELECT LENGTH(password) as plen, COUNT(password) as count 
                                    FROM hash_infos 
                                    WHERE password IS NOT NULL AND history_index = -1 AND LENGTH(password) > 0 
                                    GROUP BY plen ORDER BY plen''')
        length_rows = db_manager.cursor.fetchall()
        
        if length_rows:
            # Create individual detail pages for each password length
            counter = 0
            for plen, count in length_rows:
                db_manager.cursor.execute('SELECT username_full FROM hash_infos WHERE history_index = -1 AND LENGTH(password) = ?', (plen,))
                usernames = db_manager.cursor.fetchall()
                
                length_detail_builder = HTMLReportBuilder(config.report_directory)
                length_detail_builder.add_table(usernames, [f"Users with a password length of {plen}"])
                detail_filename = length_detail_builder.write_report(f"{counter}length_usernames.html")
                
                # Add Details link to the row
                length_rows[counter] = (plen, count, f'<a href="{detail_filename}">Details</a>')
                counter += 1
            
            length_builder = HTMLReportBuilder(config.report_directory)
            length_builder.add_table(length_rows, ["Password Length", "Count", "Details"], cols_to_not_escape=2)
            
            # Add second table ordered by count DESC
            db_manager.cursor.execute('''SELECT COUNT(password) as count, LENGTH(password) as plen 
                                        FROM hash_infos 
                                        WHERE password IS NOT NULL AND history_index = -1 AND LENGTH(password) > 0 
                                        GROUP BY plen ORDER BY count DESC''')
            count_ordered_rows = db_manager.cursor.fetchall()
            length_builder.add_table(count_ordered_rows, ["Count", "Password Length"])
            
            length_filename = length_builder.write_report("password_length_stats.html")
            summary_table.append((None, None, "Password Length Stats", f'<a href="{length_filename}">Details</a>'))
        
        # Password Reuse Statistics
        db_manager.cursor.execute('''SELECT nt_hash, COUNT(nt_hash) as count, password 
                                    FROM hash_infos 
                                    WHERE nt_hash != "31d6cfe0d16ae931b73c59d7e0c089c0" AND history_index = -1 
                                    GROUP BY nt_hash ORDER BY count DESC LIMIT 20''')
        reuse_rows = db_manager.cursor.fetchall()
        
        if reuse_rows:
            # Process each reuse row to add details links
            processed_reuse_rows = []
            for counter, (nt_hash, hit_count, password) in enumerate(reuse_rows):
                # Get usernames sharing this hash
                db_manager.cursor.execute('''SELECT username_full FROM hash_infos 
                                            WHERE nt_hash = ? AND history_index = -1 
                                            ORDER BY username_full''', (nt_hash,))
                usernames = [row[0] for row in db_manager.cursor.fetchall()]
                
                # Create individual details page for this password reuse
                details_builder = HTMLReportBuilder(config.report_directory)
                # Convert usernames list to list of tuples for proper table formatting
                username_rows = [(username,) for username in usernames]
                
                # Create column header with hash and password info
                if password and password.strip():
                    column_header = f"Users Sharing Hash: {sanitizer.sanitize_value(nt_hash, config.sanitize_output)} Password: {sanitizer.sanitize_value(password, config.sanitize_output)}"
                else:
                    column_header = f"Users Sharing Hash: {sanitizer.sanitize_value(nt_hash, config.sanitize_output)} (Password Not Cracked)"
                
                details_builder.add_table(username_rows, [column_header])
                details_filename = details_builder.write_report(f"{counter}reuse_usernames.html")
                
                # Add details link to the row
                processed_reuse_rows.append((nt_hash, hit_count, password, f'<a href="{details_filename}">Details</a>'))
            
            sanitized_reuse_rows = [sanitizer.sanitize_table_row(row, [2], [0], config.sanitize_output) 
                                   for row in processed_reuse_rows]
            
            reuse_builder = HTMLReportBuilder(config.report_directory)
            reuse_builder.add_table(sanitized_reuse_rows, ["NT Hash", "Count", "Password", "Details"], cols_to_not_escape=3)
            reuse_filename = reuse_builder.write_report("password_reuse_stats.html")
            summary_table.append((None, None, "Password Reuse Stats", f'<a href="{reuse_filename}">Details</a>'))
        
        # Password History Statistics
        db_manager.cursor.execute('SELECT MAX(history_index) FROM hash_infos')
        max_history = db_manager.cursor.fetchone()[0]
        
        if max_history is not None and max_history >= 0:
            password_history_headers = ["Username", "Current Password"]
            column_names = ["cp"]
            command = 'SELECT * FROM ( SELECT history_base_username'
            
            for i in range(-1, max_history + 1):
                if i == -1:
                    column_names.append("cp")
                else:
                    password_history_headers.append(f"History {i}")
                    column_names.append(f"h{i}")
                command += f', MIN(CASE WHEN history_index = {i} THEN password END) {column_names[-1]}'
            
            command += ' FROM hash_infos GROUP BY history_base_username) WHERE coalesce(' + ",".join(column_names) + ') is not NULL'
            
            db_manager.cursor.execute(command)
            history_rows = db_manager.cursor.fetchall()
            
            if history_rows:
                history_builder = HTMLReportBuilder(config.report_directory)
                history_builder.add_table(history_rows, password_history_headers)
                history_filename = history_builder.write_report("password_history.html")
                summary_table.append((None, None, "Password History", f'<a href="{history_filename}">Details</a>'))
        else:
            history_builder = HTMLReportBuilder(config.report_directory)
            history_builder.body_content = "There was no history contained in the password files. If you would like to get the password history, run secretsdump.py with the flag \"-history\".<br><br>Sample secretsdump.py command: secretsdump.py -system registry/SYSTEM -ntds \"Active Directory/ntds.dit\" LOCAL -outputfile customer -history"
            history_filename = history_builder.write_report("password_history.html")
            summary_table.append((None, None, "Password History", f'<a href="{history_filename}">Details</a>'))
        
        # Generate main summary report
        summary_builder = HTMLReportBuilder(config.report_directory)
        
        # Add the summary table first
        summary_builder.add_table(summary_table, ("Count", "Percent", "Description", "More Info"), cols_to_not_escape=3)
        
        # Add charts after the summary table
        # Password Length Distribution Chart
        db_manager.cursor.execute('''SELECT LENGTH(password) as plen, COUNT(password) as count 
                                    FROM hash_infos 
                                    WHERE password IS NOT NULL AND history_index = -1 AND LENGTH(password) > 0 
                                    GROUP BY plen ORDER BY plen''')
        length_data = db_manager.cursor.fetchall()
        
        if length_data:
            length_labels = [str(plen) for plen, _ in length_data]
            length_counts = [count for _, count in length_data]
            
            length_chart_data = {
                "labels": length_labels,
                "datasets": [{
                    "label": "Number of Passwords",
                    "data": length_counts,
                    "backgroundColor": "rgba(54, 162, 235, 0.2)",
                    "borderColor": "rgba(54, 162, 235, 1)",
                    "borderWidth": 1
                }]
            }
            
            length_chart_options = {
                "responsive": True,
                "plugins": {
                    "title": {
                        "display": True,
                        "text": "Password Length Distribution"
                    },
                    "legend": {
                        "display": False
                    }
                },
                "scales": {
                    "x": {
                        "title": {
                            "display": True,
                            "text": "Password Length (characters)"
                        }
                    },
                    "y": {
                        "beginAtZero": True,
                        "title": {
                            "display": True,
                            "text": "Number of Passwords"
                        }
                    }
                }
            }
            
            summary_builder.add_chart("passwordLengthChart", "bar", length_chart_data, length_chart_options)
        
        # Password Cracking Success Chart
        cracked_count = next((row[0] for row in summary_table if "Passwords Discovered Through Cracking" in str(row[2])), 0)
        uncracked_count = total_hashes - cracked_count
        
        if total_hashes > 0:
            crack_chart_data = {
                "labels": ["Cracked Passwords", "Uncracked Passwords"],
                "datasets": [{
                    "data": [cracked_count, uncracked_count],
                    "backgroundColor": ["rgba(75, 192, 192, 0.2)", "rgba(255, 99, 132, 0.2)"],
                    "borderColor": ["rgba(75, 192, 192, 1)", "rgba(255, 99, 132, 1)"],
                    "borderWidth": 1
                }]
            }
            
            crack_chart_options = {
                "responsive": True,
                "plugins": {
                    "title": {
                        "display": True,
                        "text": "Password Cracking Success Rate"
                    }
                }
            }
            
            summary_builder.add_chart("crackingSuccessChart", "pie", crack_chart_data, crack_chart_options)
        
        # Top 10 Most Common Passwords Chart
        db_manager.cursor.execute('''SELECT password, COUNT(password) as count 
                                    FROM hash_infos 
                                    WHERE password IS NOT NULL AND history_index = -1 AND password != "" 
                                    GROUP BY password ORDER BY count DESC LIMIT 10''')
        top_passwords = db_manager.cursor.fetchall()
        
        if top_passwords:
            # Sanitize passwords for display
            sanitized_passwords = [sanitizer.sanitize_table_row((pwd,), [0], [], config.sanitize_output)[0] for pwd, _ in top_passwords]
            password_counts = [count for _, count in top_passwords]
            
            top_passwords_chart_data = {
                "labels": sanitized_passwords,
                "datasets": [{
                    "label": "Usage Count",
                    "data": password_counts,
                    "backgroundColor": "rgba(255, 159, 64, 0.2)",
                    "borderColor": "rgba(255, 159, 64, 1)",
                    "borderWidth": 1
                }]
            }
            
            top_passwords_chart_options = {
                "responsive": True,
                "plugins": {
                    "title": {
                        "display": True,
                        "text": "Top 10 Most Common Passwords"
                    },
                    "legend": {
                        "display": False
                    }
                },
                "scales": {
                    "x": {
                        "title": {
                            "display": True,
                            "text": "Password"
                        }
                    },
                    "y": {
                        "beginAtZero": True,
                        "title": {
                            "display": True,
                            "text": "Usage Count"
                        }
                    }
                }
            }
            
            summary_builder.add_chart("topPasswordsChart", "bar", top_passwords_chart_data, top_passwords_chart_options)
        
        summary_builder.write_report(config.output_file)
        
        # Generate group reports if groups are specified
        if group_manager.groups:
            logger.info("Generating group reports...")
            group_summary_rows = []
            group_page_headers = ["Group Name", "Total Members", "Cracked Members", "Cracked %", "Members Details", "Cracked Details"]
            
            for group_name, _ in group_manager.groups:
                # Get group member count
                db_manager.cursor.execute(f'SELECT count(*) FROM hash_infos WHERE "{group_name}" = 1 AND history_index = -1')
                num_groupmembers = db_manager.cursor.fetchone()[0]
                
                # Get cracked count for this group
                db_manager.cursor.execute(f'''SELECT count(*) FROM hash_infos 
                                            WHERE "{group_name}" = 1 AND password IS NOT NULL AND password != '' AND history_index = -1''')
                num_groupmembers_cracked = db_manager.cursor.fetchone()[0]
                
                # Calculate percentage
                percent_cracked = calculate_percentage(num_groupmembers_cracked, num_groupmembers)
                
                # Generate group members report
                db_manager.cursor.execute(f'''SELECT username_full, nt_hash, password, lm_hash
                                            FROM hash_infos 
                                            WHERE "{group_name}" = 1 AND history_index = -1
                                            ORDER BY username_full''')
                member_rows = db_manager.cursor.fetchall()
                
                # Process member data to show sharing information
                processed_member_rows = []
                for username_full, nt_hash, password, lm_hash in member_rows:
                    # Get all users sharing this hash
                    db_manager.cursor.execute('''SELECT username_full FROM hash_infos 
                                                WHERE nt_hash = ? AND history_index = -1 
                                                ORDER BY username_full''', (nt_hash,))
                    sharing_users = [row[0] for row in db_manager.cursor.fetchall()]
                    share_count = len(sharing_users)
                    
                    # Create a string of sharing users (one per line)
                    if share_count > 5:
                        sharing_text = "<br>".join(sharing_users[:5]) + f"<br>(and {share_count - 5} more)"
                    else:
                        sharing_text = "<br>".join(sharing_users)
                    
                    # Determine if LM hash is non-blank
                    lm_non_blank = "No" if lm_hash == "aad3b435b51404eeaad3b435b51404ee" else "Yes"
                    
                    processed_member_rows.append((username_full, nt_hash, sharing_text, share_count, password, lm_non_blank))
                
                # Sanitize member data
                sanitized_member_rows = [sanitizer.sanitize_table_row(row, [4], [1], config.sanitize_output) 
                                       for row in processed_member_rows]
                
                member_headers = ["Username", "NT Hash", "Users Sharing this Hash", "Share Count", "Password", "Non-Blank LM Hash?"]
                member_builder = HTMLReportBuilder(config.report_directory)
                member_builder.add_table(sanitized_member_rows, member_headers, cols_to_not_escape=2)
                
                # Sanitize group name for filename
                safe_group_name = re.sub(r'[<>:"/\\|?*]', '_', group_name)
                members_filename = member_builder.write_report(f"{safe_group_name}_members.html")
                
                # Generate cracked passwords report for this group
                db_manager.cursor.execute(f'''SELECT username_full, LENGTH(password) as plen, password, only_lm_cracked
                                            FROM hash_infos
                                            WHERE "{group_name}" = 1 AND password IS NOT NULL AND password != '' AND history_index = -1
                                            ORDER BY plen''')
                cracked_rows = db_manager.cursor.fetchall()
                
                # Sanitize cracked data
                sanitized_cracked_rows = [sanitizer.sanitize_table_row(row, [2], [], config.sanitize_output) 
                                        for row in cracked_rows]
                
                cracked_headers = [f'Username of "{group_name}" Member', "Password Length", "Password", "Only LM Cracked"]
                cracked_builder = HTMLReportBuilder(config.report_directory)
                cracked_builder.add_table(sanitized_cracked_rows, cracked_headers)
                cracked_filename = cracked_builder.write_report(f"{safe_group_name}_cracked_passwords.html")
                
                # Add to group summary
                group_summary_rows.append((
                    group_name,
                    num_groupmembers,
                    num_groupmembers_cracked,
                    f"{percent_cracked}%",
                    f'<a href="{members_filename}">Details</a>',
                    f'<a href="{cracked_filename}">Details</a>'
                ))
            
            # Generate groups summary page
            groups_builder = HTMLReportBuilder(config.report_directory)
            groups_builder.add_table(group_summary_rows, group_page_headers, cols_to_not_escape=(4, 5))
            groups_filename = groups_builder.write_report("groups_stats.html")
            
            # Groups summary entry is already properly created and inserted above
        
        # Close database
        db_manager.close()
        
        # Prompt user to open report
        prompt_user_to_open_report(config)
        
        logger.info("Processing completed successfully")
        
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if config.debug_mode:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()
