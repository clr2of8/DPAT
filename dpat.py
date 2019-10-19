#!/usr/bin/python

import webbrowser
import io
import os
import re
import argparse
import sqlite3
import sys
try:
    import html as htmllib
except ImportError:
    import cgi as htmllib  
import binascii
import hashlib
from distutils.util import strtobool
from pprint import pprint
filename_for_html_report = "_DomainPasswordAuditReport.html"
folder_for_html_report = "DPAT Report"
filename_for_db_on_disk = "pass_audit.db"
compare_groups = []

# This should be False as it is only a shortcut used during development
speed_it_up = False

parser = argparse.ArgumentParser(
    description='This script will perform a domain password audit based on an extracted NTDS file and password cracking output such as Hashcat.')
parser.add_argument('-n', '--ntdsfile',
                    help='NTDS file name (output from SecretsDump.py)', required=True)
parser.add_argument('-c', '--crackfile',
                    help='Password Cracking output in the default form output by Hashcat, such as hashcat.potfile', required=True)
parser.add_argument('-o', '--outputfile', help='The name of the HTML report output file, defaults to ' +
                    filename_for_html_report, required=False, default=filename_for_html_report)
parser.add_argument('-d', '--reportdirectory', help='Folder containing the output HTML files, defaults to ' +
                    folder_for_html_report, required=False, default=folder_for_html_report)
parser.add_argument('-w', '--writedb', help='Write the SQLite database info to disk for offline inspection instead of just in memory. Filename will be "' +
                    filename_for_db_on_disk + '"', default=False, required=False, action='store_true')
parser.add_argument('-s', '--sanitize', help='Sanitize the report by partially redacting passwords and hashes. Prepends the report directory with \"Sanitized - \"',
                    default=False, required=False, action='store_true')
parser.add_argument('-g', '--grouplists', help='The name of one or multiple files that contain lists of usernames in particular groups. The group names will be taken from the file name itself. The username list must be in the same format as found in the NTDS file such as some.ad.domain.com\\username or it can be in the format output by using the PowerView Get-NetGroupMember function. Example: -g "Domain Admins.txt" "Enterprise Admins.txt"', nargs='*', required=False)
parser.add_argument('-m', '--machineaccts', help='Include machine accounts when calculating statistics',
                    default=False, required=False, action='store_true')
args = parser.parse_args()

ntds_file = args.ntdsfile
cracked_file = args.crackfile
filename_for_html_report = args.outputfile
folder_for_html_report = args.reportdirectory
if args.sanitize:
    folder_for_html_report = folder_for_html_report + " - Sanitized"
if args.grouplists is not None:
    for groupfile in args.grouplists:
        compare_groups.append(
            (os.path.splitext(os.path.basename(groupfile))[0], groupfile))

# create report folder if it doesn't already exist
if not os.path.exists(folder_for_html_report):
    os.makedirs(folder_for_html_report)

# show only the first and last char of a password or a few more chars for a hash


def sanitize(pass_or_hash):
    if not args.sanitize:
        return pass_or_hash
    else:
        sanitized_string = pass_or_hash
        lenp = len(pass_or_hash)
        if lenp == 32:
            sanitized_string = pass_or_hash[0:4] + \
                "*"*(lenp-8) + pass_or_hash[lenp-5:lenp-1]
        elif lenp > 2:
            sanitized_string = pass_or_hash[0] + \
                "*"*(lenp-2) + pass_or_hash[lenp-1]
        return sanitized_string


class HtmlBuilder:
    bodyStr = ""

    def build_html_body_string(self, str):
        self.bodyStr += str + "</br>\n"

    def get_html(self):
        return "<!DOCTYPE html>\n" + "<html>\n<head>\n<style>\ntable, th, td {border: 1px solid black; border-collapse: collapse; text-align: center;} th, td {padding: 2px;}</style>\n</head>\n" + "<body>\n" + self.bodyStr + "</html>\n" + "</body>\n"

    def add_table_to_html(self, list, headers=[], col_to_not_escape=None):
        html = '<table border="1">\n'
        html += "<tr>"
        for header in headers:
            if header is not None:
                html += "<th>" + str(header) + "</th>"
            else:
                html += "<th></th>"
        html += "</tr>\n"
        for line in list:
            html += "<tr>"
            col_num = 0
            for column in line:
                if column is not None:
                    col_data = column
                    if (headers[col_num] == "Password" or headers[col_num] == "NT Hash" or headers[col_num] == "LM Hash" or headers[col_num] == "Left Portion of Password" or headers[col_num] == "Right Portion of Password"):
                        col_data = sanitize(column)
                    if col_num != col_to_not_escape:
                        col_data = htmllib.escape(str(col_data))
                    html += "<td>" + col_data + "</td>"
                else:
                    html += "<td></td>"
                col_num += 1
            html += "</tr>\n"
        html += "</table>"
        self.build_html_body_string(html)

    def write_html_report(self, filename):
        f = open(os.path.join(folder_for_html_report, filename), "w")
        f.write(self.get_html())
        f.close()
        return filename


hb = HtmlBuilder()
summary_table = []
summary_table_headers = ("Count", "Description", "More Info")

conn = sqlite3.connect(':memory:')
if args.writedb:
    if os.path.exists(filename_for_db_on_disk):
        os.remove(filename_for_db_on_disk)
    conn = sqlite3.connect(filename_for_db_on_disk)
if speed_it_up:
    conn = sqlite3.connect(filename_for_db_on_disk)
conn.text_factory = str
c = conn.cursor()

# nt2lmcrack functionality
# the all_casings functionality was taken from https://github.com/BBerastegui/foo/blob/master/casing.py


def all_casings(input_string):
    if not input_string:
        yield ""
    else:
        first = input_string[:1]
        if first.lower() == first.upper():
            for sub_casing in all_casings(input_string[1:]):
                yield first + sub_casing
        else:
            for sub_casing in all_casings(input_string[1:]):
                yield first.lower() + sub_casing
                yield first.upper() + sub_casing


def crack_it(nt_hash, lm_pass):
    asc = ""
    hexed = ""
    password = None
    for pwd_guess in all_casings(lm_pass):
        hash = hashlib.new('md4', pwd_guess.encode('utf-16le')).hexdigest()
        if nt_hash.lower() == hash.lower():
            password = pwd_guess
            break
    return password


if not speed_it_up:
    # Create tables and indices
    c.execute('''CREATE TABLE hash_infos
        (username_full text collate nocase, username text collate nocase, lm_hash text, lm_hash_left text, lm_hash_right text, nt_hash text, password text, lm_pass_left text, lm_pass_right text, only_lm_cracked boolean)''')
    c.execute("CREATE INDEX index_nt_hash ON hash_infos (nt_hash);")
    c.execute("CREATE INDEX index_lm_hash_left ON hash_infos (lm_hash_left);")
    c.execute("CREATE INDEX index_lm_hash_right ON hash_infos (lm_hash_right);")
    c.execute("CREATE INDEX lm_hash ON hash_infos (lm_hash);")
    c.execute("CREATE INDEX username ON hash_infos (username);")

    # Create boolean column for each group
    for group in compare_groups:
        sql = "ALTER TABLE hash_infos ADD COLUMN \"" + group[0] + "\" boolean"
        c.execute(sql)

    # Read users from each group; groups_users is a dictionary with key = group name and value = list of users
    groups_users = {}
    for group in compare_groups:
        user_domain = ""
        user_name = ""
        try:
            users = []
            fing = io.open(group[1], encoding='utf-16')
            for line in fing:
                if "MemberDomain" in line:
                    user_domain = (line.split(":")[1]).strip()
                if "MemberName" in line:
                    user_name = (line.split(":")[1]).strip()
                    users.append(user_domain + "\\" + user_name)
        except:
            print("Doesn't look like the Group Files are in the form output by PowerView, assuming the files are already in domain\\username list form")
            # If the users array is empty, assume the file was not in the PowerView PowerShell script output format that you get from running:
            # Get-NetGroupMember -GroupName "Enterprise Admins" -Domain "some.domain.com" -DomainController "DC01.some.domain.com" > Enterprise Admins.txt
            # You can list domain controllers for use in the above command with Get-NetForestDomain
            if len(users) == 0:
                fing = open(group[1])
                users = []
                for line in fing:
                    users.append(line.rstrip("\n"))
                fing.close()
        groups_users[group[0]] = users

    # Read in NTDS file
    fin = open(ntds_file)
    for line in fin:
        vals = line.rstrip("\n").split(':')
        if len(vals) == 1:
            continue
        usernameFull = vals[0]
        lm_hash = vals[2]
        lm_hash_left = lm_hash[0:16]
        lm_hash_right = lm_hash[16:32]
        nt_hash = vals[3]
        username = usernameFull.split('\\')[-1]
        # Exclude machine accounts (where account name ends in $) by default
        if args.machineaccts or not username.endswith("$"):
            c.execute("INSERT INTO hash_infos (username_full, username, lm_hash , lm_hash_left , lm_hash_right , nt_hash) VALUES (?,?,?,?,?,?)",
                    (usernameFull, username, lm_hash, lm_hash_left, lm_hash_right, nt_hash))
    fin.close()

    # update group membership flags
    for group in groups_users:
        for user in groups_users[group]:
            sql = "UPDATE hash_infos SET \"" + group + \
                "\" = 1 WHERE username_full = \"" + user + "\""
            c.execute(sql)

    # read in POT file
    fin = open(cracked_file)
    for lineT in fin:
        line = lineT.rstrip('\r\n')
        colon_index = line.find(":")
        hash = line[0:colon_index]
        # Stripping $NT$ and $LM$ that is included in John the Ripper output by default
        jtr = False
        if hash.startswith('$NT$') or hash.startswith('$LM$'):
            hash = hash.lstrip("$NT$")
            hash = hash.lstrip("$LM$")
            jtr = True
        password = line[colon_index+1:len(line)]
        lenxx = len(hash)
        if re.match("\$HEX\[([^\]]+)", password) and not jtr:
            hex2 = (binascii.unhexlify(re.findall("\$HEX\[([^\]]+)", password)[-1]))
            l = list()
            for x in list(hex2):
                if type(x) == int:
                    x = str(chr(x))
                l.append(x)
            password = ""
            password = password.join(l)
        if lenxx == 32:  # An NT hash
            c.execute("UPDATE hash_infos SET password = ? WHERE nt_hash = ?", (password, hash))
        elif lenxx == 16:  # An LM hash, either left or right
            c.execute("UPDATE hash_infos SET lm_pass_left = ? WHERE lm_hash_left = ?", (password, hash))
            c.execute("UPDATE hash_infos SET lm_pass_right = ? WHERE lm_hash_right = ?", (password, hash))
    fin.close()

    # Do additional LM cracking
    c.execute('SELECT nt_hash,lm_pass_left,lm_pass_right FROM hash_infos WHERE (lm_pass_left is not NULL or lm_pass_right is not NULL) and password is NULL and lm_hash is not "aad3b435b51404eeaad3b435b51404ee" group by nt_hash')
    list = c.fetchall()
    count = len(list)
    print("Cracking %d NT Hashes where only LM Hash was cracked (aka lm2ntcrack functionality)" % count)
    for pair in list:
        lm_pwd = ""
        if pair[1] is not None:
            lm_pwd += pair[1]
        if pair[2] is not None:
            lm_pwd += pair[2]
        password = crack_it(pair[0], lm_pwd)
        if password is not None:
            c.execute('UPDATE hash_infos SET only_lm_cracked = 1, password = \'' + password.replace("'", "''") + '\' WHERE nt_hash = \'' + pair[0] + '\'')
        count -= 1

# Total number of hashes in the NTDS file
c.execute('SELECT username_full,password,LENGTH(password) as plen,nt_hash,only_lm_cracked FROM hash_infos ORDER BY plen DESC, password')
list = c.fetchall()

num_hashes = len(list)
hbt = HtmlBuilder()
hbt.add_table_to_html(
    list, ["Username", "Password", "Password Length", "NT Hash", "Only LM Cracked"])
filename = hbt.write_html_report("all hashes.html")
summary_table.append((num_hashes, "Password Hashes",
                      "<a href=\"" + filename + "\">Details</a>"))

# Total number of UNIQUE hashes in the NTDS file
c.execute('SELECT count(DISTINCT nt_hash) FROM hash_infos')
num_unique_nt_hashes = c.fetchone()[0]
summary_table.append((num_unique_nt_hashes, "Unique Password Hashes", None))

# Number of users whose passwords were cracked
c.execute('SELECT count(*) FROM hash_infos where password is not NULL')
num_passwords_cracked = c.fetchone()[0]
summary_table.append(
    (num_passwords_cracked, "Passwords Discovered Through Cracking", None))

# Number of UNIQUE passwords that were cracked
c.execute(
    'SELECT count(Distinct password) FROM hash_infos where password is not NULL')
num_unique_passwords_cracked = c.fetchone()[0]
summary_table.append((num_unique_passwords_cracked,
                      "Unique Passwords Discovered Through Cracking", None))

# Percentage of all passwords cracked and percentage of unique passwords cracked
percent_cracked_unique = num_unique_passwords_cracked / \
    float(num_unique_nt_hashes)*100
percent_all_cracked = num_passwords_cracked/float(num_hashes)*100
summary_table.append(("%0.1f" % percent_all_cracked,
                      "Percent of Passwords Cracked", "<a href=\"" + filename + "\">Details</a>"))
summary_table.append(("%0.1f" % percent_cracked_unique,
                      "Percent of Unique Passwords Cracked", "<a href=\"" + filename + "\">Details</a>"))

# Group Membership Details and number of passwords cracked for each group
for group in compare_groups:
    c.execute(
        "SELECT username_full,nt_hash FROM hash_infos WHERE \"" + group[0] + "\" = 1")
    # this list contains the username_full and nt_hash of all users in this group
    list = c.fetchall()
    num_groupmembers = len(list)
    new_list = []
    for tuple in list:  # the tuple is (username_full, nt_hash, lm_hash)
        c.execute(
            "SELECT username_full FROM hash_infos WHERE nt_hash = \"" + tuple[1] + "\"")
        users_list = c.fetchall()
        if len(users_list) < 30:
            string_of_users = (', '.join(''.join(elems)
                                         for elems in users_list))
            new_tuple = tuple + (string_of_users,)
        else:
            new_tuple = tuple + ("Too Many to List",)
        new_tuple += (len(users_list),)
        c.execute(
            "SELECT password,lm_hash FROM hash_infos WHERE nt_hash = \"" + tuple[1] + "\" LIMIT 1")
        result = c.fetchone()
        new_tuple += (result[0],)
        # Is the LM Hash stored for this user?
        if result[1] != "aad3b435b51404eeaad3b435b51404ee":
            new_tuple += ("Yes",)
        else:
            new_tuple += ("No",)
        new_list.append(new_tuple)
    headers = ["Username", "NT Hash", "Users Sharing this Hash",
               "Share Count", "Password", "Non-Blank LM Hash?"]
    hbt = HtmlBuilder()
    hbt.add_table_to_html(new_list, headers)
    filename = hbt.write_html_report(group[0] + " members.html")
    summary_table.append((num_groupmembers, "Members of \"%s\" group" %
                          group[0], "<a href=\"" + filename + "\">Details</a>"))
    c.execute("SELECT username_full, LENGTH(password) as plen, password, only_lm_cracked FROM hash_infos WHERE \"" +
              group[0] + "\" = 1 and password is not NULL and password is not '' ORDER BY plen")
    group_cracked_list = c.fetchall()
    num_groupmembers_cracked = len(group_cracked_list)
    headers = ["Username of \"" + group[0] + "\" Member",
               "Password Length", "Password", "Only LM Cracked"]
    hbt = HtmlBuilder()
    hbt.add_table_to_html(group_cracked_list, headers)
    filename = hbt.write_html_report(group[0] + " cracked passwords.html")
    summary_table.append((num_groupmembers_cracked, "\"%s\" Passwords Cracked" %
                          group[0], "<a href=\"" + filename + "\">Details</a>"))

# Number of LM hashes in the NTDS file, excluding the blank value
c.execute('SELECT count(*) FROM hash_infos where lm_hash is not "aad3b435b51404eeaad3b435b51404ee"')
summary_table.append((c.fetchone()[0], "LM Hashes (Non-blank)", None))

# Number of UNIQUE LM hashes in the NTDS, excluding the blank value
c.execute('SELECT count(DISTINCT lm_hash) FROM hash_infos WHERE lm_hash is not "aad3b435b51404eeaad3b435b51404ee"')
summary_table.append((c.fetchone()[0], "Unique LM Hashes (Non-blank)", None))

# Number of passwords that are LM cracked for which you don't have the exact (case sensitive) password.
c.execute('SELECT lm_hash, lm_pass_left, lm_pass_right, nt_hash FROM hash_infos WHERE (lm_pass_left is not "" or lm_pass_right is not "") and password is NULL and lm_hash is not "aad3b435b51404eeaad3b435b51404ee" group by lm_hash')
list = c.fetchall()
num_lm_hashes_cracked_where_nt_hash_not_cracked = len(list)
output = "WARNING there were %d unique LM hashes for which you do not have the password." % num_lm_hashes_cracked_where_nt_hash_not_cracked
if num_lm_hashes_cracked_where_nt_hash_not_cracked != 0:
    hbt = HtmlBuilder()
    headers = ["LM Hash", "Left Portion of Password",
               "Right Portion of Password", "NT Hash"]
    hbt.add_table_to_html(list, headers)
    filename = hbt.write_html_report("lm_noncracked.html")
    hb.build_html_body_string(
        output + ' <a href="' + filename + '">Details</a>')
    output2 = "</br> Cracking these to their 7-character upcased representation is easy with Hashcat and this tool will determine the correct case and concatenate the two halves of the password for you!</br></br> Try this Hashcat command to crack all LM hashes:</br> <strong>./hashcat64.bin -m 3000 -a 3 customer.ntds -1 ?a ?1?1?1?1?1?1?1 --increment</strong></br></br> Or for John, try this:</br> <strong>john --format=LM customer.ntds</strong></br>"
    hb.build_html_body_string(output2)

# Count and List of passwords that were only able to be cracked because the LM hash was available, includes usernames
c.execute('SELECT username_full,password,LENGTH(password) as plen,only_lm_cracked FROM hash_infos WHERE only_lm_cracked = 1 ORDER BY plen')
list = c.fetchall()
hbt = HtmlBuilder()
headers = ["Username", "Password", "Password Length", "Only LM Cracked"]
hbt.add_table_to_html(list, headers)
filename = hbt.write_html_report("users_only_cracked_through_lm.html")
summary_table.append((len(list), "Passwords Only Cracked via LM Hash",
                      "<a href=\"" + filename + "\">Details</a>"))
c.execute('SELECT COUNT(DISTINCT nt_hash) FROM hash_infos WHERE only_lm_cracked = 1')
summary_table.append(
    (c.fetchone()[0], "Unique LM Hashes Cracked Where NT Hash was Not Cracked", None))

# Password length statistics
c.execute('SELECT LENGTH(password) as plen,COUNT(password) FROM hash_infos WHERE plen is not NULL and plen is not 0 GROUP BY plen ORDER BY plen')
list = c.fetchall()
counter = 0
for tuple in list:
    length = str(tuple[0])
    c.execute('SELECT username FROM hash_infos WHERE LENGTH(password) = ' + length)
    usernames = c.fetchall()
    hbt = HtmlBuilder()
    headers = ["Users with a password length of " + length]
    hbt.add_table_to_html(usernames, headers)
    filename = hbt.write_html_report(str(counter) + "length_usernames.html")
    list[counter] += ("<a href=\"" + filename + "\">Details</a>",)
    counter += 1
hbt = HtmlBuilder()
headers = ["Password Length", "Count", "Details"]
hbt.add_table_to_html(list, headers, 2)
c.execute('SELECT COUNT(password) as count, LENGTH(password) as plen FROM hash_infos WHERE plen is not NULL and plen is not 0 GROUP BY plen ORDER BY count DESC')
list = c.fetchall()
headers = ["Count", "Password Length"]
hbt.add_table_to_html(list, headers)
filename = hbt.write_html_report("password_length_stats.html")
summary_table.append((None, "Password Length Stats",
                      "<a href=\"" + filename + "\">Details</a>"))

# Top Ten Passwords Used
c.execute('SELECT password,COUNT(password) as count FROM hash_infos WHERE password is not NULL and password is not "" GROUP BY password ORDER BY count DESC LIMIT 20')
list = c.fetchall()
hbt = HtmlBuilder()
headers = ["Password", "Count"]
hbt.add_table_to_html(list, headers)
filename = hbt.write_html_report("top_password_stats.html")
summary_table.append((None, "Top Password Use Stats",
                      "<a href=\"" + filename + "\">Details</a>"))

# Password Reuse Statistics (based only on NT hash)
c.execute('SELECT nt_hash, COUNT(nt_hash) as count, password FROM hash_infos WHERE nt_hash is not "31d6cfe0d16ae931b73c59d7e0c089c0" GROUP BY nt_hash ORDER BY count DESC LIMIT 20')
list = c.fetchall()
counter = 0
for tuple in list:
    c.execute(
        'SELECT username FROM hash_infos WHERE nt_hash = \"' + tuple[0] + '\"')
    usernames = c.fetchall()
    password = tuple[2]
    if password is None:
        password = ""
    hbt = HtmlBuilder()
    headers = ["Users Sharing a Hash:Password of " +
               sanitize(tuple[0]) + ":" + sanitize(password)]
    hbt.add_table_to_html(usernames, headers)
    filename = hbt.write_html_report(str(counter) + "reuse_usernames.html")
    list[counter] += ("<a href=\"" + filename + "\">Details</a>",)
    counter += 1
hbt = HtmlBuilder()
headers = ["NT Hash", "Count", "Password", "Details"]
hbt.add_table_to_html(list, headers, 3)
filename = hbt.write_html_report("password_reuse_stats.html")
summary_table.append((None, "Password Reuse Stats",
                      "<a href=\"" + filename + "\">Details</a>"))

# Write out the main report page
hb.add_table_to_html(summary_table, summary_table_headers, 2)
hb.write_html_report(filename_for_html_report)
print("The Report has been written to the \"" + filename_for_html_report +
      "\" file in the \"" + folder_for_html_report + "\" directory")

# Save (commit) the changes and close the database connection
conn.commit()
conn.close()

try:
    input = raw_input
except NameError:
    pass

# prompt user to open the report
# the code to prompt user to open the file was borrowed from the EyeWitness tool https://github.com/ChrisTruncer/EyeWitness
print('Would you like to open the report now? [Y/n]')
while True:
    try:
        response = input().lower().rstrip('\r')
        if ((response is "") or (strtobool(response))):
            webbrowser.open(os.path.join("file://" + os.getcwd(),
                                         folder_for_html_report, filename_for_html_report))
            break
        else:
            break
    except ValueError:
        print("Please respond with y or n")
