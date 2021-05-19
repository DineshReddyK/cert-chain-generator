#!/usr/bin/python

""""
Generates the certificate chain and optioanlly revokes any certficates.
Input File Format:

Cert chain      | Revoked Certs
rca1->ica1->ee1 | ee1
rca2->ica2->ee2 | ica2,ee2


"""
__author__ = 'Dinesh Reddy K'


import os
import sys
import glob
import shutil
import subprocess
from random import randint

if len(sys.argv) < 2:
    print "Input file required.."
    print """Input File Format:
            ---------------------------------
           | Cert chain      | Revoked Certs |
           | rca1->ica1->ee1 | ee1           |
           | rca2->ica2->ee2 | ica2,ee2      |
            ---------------------------------"""
    sys.exit(1)


LEN = 2048
treefile = sys.argv[1]

def create_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def execute_command(command):
    print "#"*80
    print command
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    print output
    print err
    print "#"*80

def initCRL():
    create_dir("./certs/db")
    os.chdir("./certs")

def copyCNF(directory):
    with open("/etc/pki/tls/openssl.cnf", 'r') as ifile, open("./db/openssl-%s.cnf"%directory, 'w') as ofile:
        for line in ifile:
            if line.startswith("dir"):
                ofile.write("dir    =   ./db/%s/\n"%directory)
            else:
                ofile.write(line)

def setupDB(parent):
    path = "./db/" + parent
    if os.path.exists(path):
        return

    create_dir(path)
    copyCNF(parent)
    open(path + '/index.txt', 'w').close()
    fp = open(path + '/crlnumber', 'w')
    fp.write("00")
    fp.close()
    
def generateRoot(root):
    if os.path.exists(root + ".pem"):
        return
    print "Generating root CA - ", root
    command = "openssl req -new -nodes -x509 -extensions v3_ca -out %s.pem -keyout %s.key -subj /CN=DinRoot -newkey rsa:%s"%(root, root, LEN)
    execute_command(command)

def generateICAs(parent, childs):
    if not childs:
        return

    child = childs[0]
    if os.path.exists(child + ".pem"):
        return

    print "Generating intermediate CA - %s, Sign by - %s"%(child, parent)
    command1 = "openssl req -new -nodes -out %s.req -keyout %s.key -subj /CN=DinIca-%s -newkey rsa:%s"%(child, child, child, LEN)
    command2 = "openssl x509 -req -extensions v3_ca -in %s.req -CAkey %s.key -CA %s.pem -set_serial %s -out %s.pem"%(child, parent, parent, randint(1111,9999), child)
    execute_command(command1)
    execute_command(command2)
    generateICAs(child, childs[1:])

def genereateEE(ca, ee):
    if os.path.exists(ee + ".pem"):
        return

    print "Generating EE - ", ee
    command1 = "openssl req -new -out %s.req -keyout %s.key -nodes -newkey rsa:%s -subj /CN=%s/emailAddress=dinesh.k@nokia.com"%(ee, ee, LEN, ee)
    command2 = "openssl x509 -req -extensions usr_cert -in %s.req -CAkey %s.key -CA %s.pem -set_serial %s -sha512 -out %s.pem"%(ee, ca, ca, randint(1111,9999), ee)
    execute_command(command1)
    execute_command(command2)

def revokeCert(parent, cert):
    print "Revoking Cert - ", cert
    
    setupDB(parent)
    sslcnf = "./db/openssl-%s.cnf"%parent

    command1 = "openssl ca -config %s -revoke %s.pem -keyfile %s.key -cert %s.pem"%(sslcnf, cert, parent, parent)
    execute_command(command1)

def generateCrl(issuer):
    print "Generating crl for - ", issuer

    setupDB(issuer)
    sslcnf = "./db/openssl-%s.cnf"%issuer
    
    command2 = "openssl ca -config %s -gencrl -keyfile %s.key -cert %s.pem -out crl_%s.pem"%(sslcnf, issuer, issuer, issuer)
    execute_command(command2)

with open(treefile, 'r') as f:
    initCRL()
    next(f) #ignore header
    for line in f:
        chain, revoke = line.split('|')
        chain = [c.strip() for c in chain.split("->")]
        revoke = [cert.strip() for cert in revoke.split(',')]
        root, ee, icas = chain[0], chain[-1], chain[1:-1]


        generateRoot(root)
        if icas:
            generateICAs(root, icas)
            genereateEE(icas[-1], ee)
        else:
            genereateEE(root, ee)

        for cert in revoke:
            if not cert: 
                continue
            index = chain.index(cert)
            if index: parent = chain[index-1]
            else: parent = cert
            revokeCert(parent, cert)

        for issuer in chain[:-1]:
            generateCrl(issuer)

for f in glob.glob("*.req"):
    os.remove(f)

