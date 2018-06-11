#!/usr/bin/python

import time
import math
import threading

class hiloPWM(threading.Thread):
	def __init__(self,velocidad):
		threading.Thread.__init__(self)
		self.running = True
		self.velocidad = velocidad

	def run(self):
		try:
			while True:
				f = open('/home/pi/Desktop/adios.txt', 'w')
				f.write('{0:0.0f}\n'.format(self.velocidad))
				f.close()
				time.sleep(7)
		except (KeyboardInterrupt):
				print "Adios"
 
def makeHilo(velocidad): 
	#vel = velocidad
	threadPWM = hiloPWM(velocidad)
	try:
		threadPWM.setDaemon(True)
		threadPWM.start()
	except (KeyboardInterrupt):
		print "Matamos el hilo"
		hiloPWM.running = False
		hiloPWMjoin()

'''if __name__=="__main__":
   #main()
	velocidad = 5
	makeHilo(velocidad)
	raw_input("Pulsa enter para salir")'''
