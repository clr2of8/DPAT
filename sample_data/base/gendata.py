#!/usr/bin/python

import random,hashlib,binascii

f_first = open("base/first.txt")
f_last = open("base/last.txt")
f_passwords = open("base/subset-rockyou.txt")
f_das= open("Domain Admins.txt","w")

first_list=list(f_first)
count_first = 0
domains = [ "parent.domain.com","child.domain.com","sister.domain.com"]
domain_admins = {
    'Agnes.Aarons':'reallylongone',
    'Cliff.Adames':'PasswordsAreHardToRemember',
    'Alex.Revis':'57kdhfls*%2',
    'Gilbert.Settle':'Ford57andGolf',
    'Cory.Ruhoff':'NewPassword4Work',
    'Damian.Scarver':'domainAdminPass',
    'Oscar.Veyna':'ShirtsNSkins',
    'Rex.Vidot':'1997hereo',
    'Scot.Viles':'sparklesparkleZAP',
    'Burton.Vonner':'VonnerPass16',
    'Dayna.Wade':'Winter16',
    'Dustin.Wahlund':'Frank-did-it',
    'Earnestine.Waiau':'HappyTogether16',
    'Emerson.Wala':'Washington87',
    'Sallie.Zych':'77qwerty88',
    'Samuel.Zysk':'Zundk8*&^',
    'Rosalinda.Zusman':'Making Up Passwords is Hard',
    'Roman.Zurek':'goFigure8',
    'Celia.Mcintosh':'WikiWiki4What',
    'Celeste.Mcintire':'2beornot2be',
    'Cecil.Mcinnis':';kleknklk',
    'Brendan.Mcgriff':'DontForget1',
    'Booker.Mcgraph':'DaisyMisty1',
    'Bobbie.Mcgrane':'P@sswo0rd16',
    'Clint.Hollifield':'1997Married',
    'Coleen.Hollinghead':'MickyMouse56',
    'Jackie.Dimodica':'JerermyNHanna2',
    'Isabella.Dimitroff':'Anastasia',
    'Horace.Dimarco':'LovedByYou',
    'Herbert.Dils':'DiamondRIO3',
    'Hazel.Dillman':'L1ke1T',
    'Rex.Beadling':'ITdoma1n@dmin',
    'Reggie.Beacher':'WorldTurn@round',
    'Raul.Beaber':'Lovemybug2003',
    'Pete.Baysmore':'Hard24get',
    'August.Mcginnis':'W$%23eu&*!rhs0'
}
lm_dict = { 'NotTooHard':'5B9D1AFCC9784729ADD5B1A41F2CB2C0','GoBeavErs1997':'94068F2F1CD1EAF27F76AAABE8E8789D','W$%23eu&*!rhs0':'4CE5B0C344FDD1038930410E6B652F2C'}

f = open("customer.ntds","w")
f2 = open("oclHashcat.pot","w")

for last in f_last:
    add_admin = False
    if count_first < len(first_list):
        firstName = first_list[count_first].rstrip().title()
        count_first = count_first + 1
    else:
        count_first = 0
        firstName = first_list[count_first].rstrip().title()
    lastName = last.rstrip().title()
    userName = firstName + "." + lastName
    password = f_passwords.readline().rstrip()
    if domain_admins.has_key(password):
        print "Warn: duplicated password for administrator: " + password
    rid = str(random.randint(10000,500000))
    domain = domains[random.randint(0,len(domains)-1)]
    if domain_admins.has_key(userName):
        password=domain_admins[userName]
        domain=domains[1]
        f_das.write(domain + "\\" + userName + "\n")
        if userName in ["Agnes.Aarons","Alex.Revis","Burton.Vonner","Pete.Baysmore"]:
            add_admin = True
    nt_hash = binascii.hexlify(hashlib.new('md4', password.encode('utf-16le')).digest())
    lm_hash = "aad3b435b51404eeaad3b435b51404ee" # this is the LM hash of a blank password
    if lm_dict.has_key(password):
        lm_hash = lm_dict[password]
    f.write(domain + "\\" + userName + ":" + rid + ":" + lm_hash.lower() + ":" + nt_hash + ":::\n")
    if  (password != "W$%23eu&*!rhs0") and (userName != "Bobbie.Mcgrane") and (userName != "Rosalinda.Zusman") and (lm_dict.has_key(password) or random.randrange(1,100)<78):
        f2.write(nt_hash + ":" + password + "\n")
    if  password == "W$%23eu&*!rhs0":
        left_pass="W$%23eu".upper()
        right_pass="&*!rhs0".upper()
        left_hash=lm_dict[password][0:16].lower()
        right_hash=lm_dict[password][16:32].lower()
        f2.write(left_hash + ":" + left_pass + "\n")
        f2.write(right_hash + ":" + right_pass + "\n")
    if add_admin:
        f.write(domain + "\\admin" + userName + ":" + rid + ":" + lm_hash.lower() + ":" + nt_hash + ":::\n")



f.close()
f2.close()
f_first.close()
f_last.close()
f_passwords.close()