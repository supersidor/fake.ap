#! /usr/bin/python
 
import os
import gps
import time
import threading
 
class GpsPoller(threading.Thread):
  def __init__(self):
    threading.Thread.__init__(self)
    self.gpsd = gps.gps(mode=gps.WATCH_ENABLE) #starting the stream of info
    self.current_value = None
    self.running = True #setting the thread running to true
    self.daemon = True
    self.last = None
  def run(self):
    while self.running:
      self.gpsd.next() #this will continue to loop and grab EACH set of gpsd info to clear the buffer

  def stop(self):
    self.running = False
    self.join() # wait for the thread to finish what it's doing

  def get(self):
    if self.gpsd.fix:
#      print self.gpsd.fix.mode
      if self.gpsd.fix.mode==gps.MODE_NO_FIX:
        if self.last:
          return (self.last[0],self.last[1],False)
      else:
          fix = self.gpsd.fix
          self.last  = (fix.latitude,fix.longitude)
          return (self.last[0],self.last[1],True)
    return None
def initGps():
  gpsp = GpsPoller() # create the thread
  gpsp.start()
  return gpsp

"""if __name__ == '__main__':


  gpsp = GpsPoller() # create the thread
  try:
    gpsp.start() # start it up
    while True:
      #It may take a second or two to get good data
      #print gpsd.fix.latitude,', ',gpsd.fix.longitude,'  Time: ',gpsd.utc
 
      os.system('clear')
 
      print
      print ' GPS reading'
      print '----------------------------------------'
      print 'latitude    ' , gpsd.fix.latitude
      print 'longitude   ' , gpsd.fix.longitude
      print 'time utc    ' , gpsd.utc,' + ', gpsd.fix.time
      print 'altitude (m)' , gpsd.fix.altitude
      print 'eps         ' , gpsd.fix.eps
      print 'epx         ' , gpsd.fix.epx
      print 'epv         ' , gpsd.fix.epv
      print 'ept         ' , gpsd.fix.ept
      print 'speed (m/s) ' , gpsd.fix.speed
      print 'climb       ' , gpsd.fix.climb
      print 'track       ' , gpsd.fix.track
      print 'mode        ' , gpsd.fix.mode
      print
      print 'sats        ' , gpsd.satellites
 
      time.sleep(5) #set to whatever
 
  except (KeyboardInterrupt, SystemExit): #when you press ctrl+c
    print "\nKilling Thread..."
    gpsp.running = False
    gpsp.join() # wait for the thread to finish what it's doing
  print "Done.\nExiting."
"""
