import re
import sys
import sqlite3
import threading

tls = threading.local()


def create_db():
    con = get_con()
    c = con.cursor()

    c.execute("""create table vendors (prefix char(6) UNIQUE,vendor varchar(255))""")

def setup_con(con,row_factory):
    con.row_factory = sqlite3.Row
    if row_factory is not None:
        con.row_factory = row_factory
    con.text_factory = str
def connect_db():
    con = sqlite3.connect('clients.db',detect_types=sqlite3.PARSE_DECLTYPES)
    return con

def get_con(row_factory=None):
    global tls
    try:
        setup_con(tls.con,row_factory)
        return tls.con
    except:
        tls.con = connect_db()
        setup_con(tls.con,row_factory)
        return tls.con
def init_db():
    con = get_con()
    c = con.cursor()

    try:
        c.execute("SELECT * from vendors LIMIT 1")
    except:
        create_db()


p = re.compile("^([\dA-F]{6})\s(.*)$")
vendors = {}
with open("mac-prefixes","r") as f:
    for line in f:
        m = p.match(line)
        if not m:
           print "error"
           sys.exit()
        prefix =  m.group(1)
        vendor = m.group(2)
        vlow = vendor.lower()
        if 'samsung' in vlow:
            vendor = "Samsung"
        elif 'apple' in vlow:
            vendor = "Apple"
        elif 'asustek' in vlow:
            vendor = "Asus"
        elif 'sony' in vlow:
            vendor = "Sony"
        elif 'lenovo' in vlow:
            vendor = "Lenovo"
        elif vendor == "zte":
            vendor = "ZTE"
        elif 'tp-link' in vlow:
            vendor="TP-Link"
        elif 'azurewave' in vlow:
            vendor="AzureWave"
        elif 'Hon Hai Precision' in vendor:
            vendor="HonHaiPrecision"
        elif 'motorola' in vlow:
            vendor="Motorola"
        elif 'intel' in vlow:
            vendor="Intel"
        elif vendor=="LG Electronics":
            vendor="LG"
        elif vendor=="LG Innotek":
            vendor="LG"



#        print prefix,"-",vendor
        if vendor not in vendors:
            vendors[vendor] = set()
        vendors[vendor] |= {prefix}
init_db()
con = get_con()
with con:
    cursor = con.cursor()
    cursor.execute("DELETE FROM vendors")
    for vendor in sorted(vendors.keys()):
        prefixes = vendors[vendor]
#        print vendor,":",vendors[vendor]
        for prefix in prefixes:
            cursor.execute("INSERT OR IGNORE INTO vendors (prefix,vendor) VALUES(?,?)",(prefix,vendor))


        
