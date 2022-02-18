# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_WhoisRegistrantPhone
# Purpose:      Get the Registrant Number.
#
# Author:      Daniel Martínez Cuevas <danimartinezcuevas@gmail.com>
#
# Created:     18/02/2022
# Copyright:   (c) Daniel Martínez Cuevas 2022
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import subprocess
import re

class sfp_WhoisRegistrantPhone(SpiderFootPlugin):

    meta = {
        'name': "Whois Registrant Phone",
        'summary': "Get the Registrant Number",
        'flags': [""],
        'useCases': [""],
        'categories': ["Passive DNS"] 
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["PHONE_NUMBER"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            data = None

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")
            
            Telefono = ""
            AhoraLargo = 0
            Largo = 0

            data = subprocess.run("whois "+eventData, shell=True, text=True, capture_output=True)
            salida = data.stdout
            listado = re.split('[\n:]',salida)
            for i in range(len(listado)):
                cadena = listado[i]
                REGPhone = re.search("Registrant Phone",cadena)
                    
                if REGPhone != None:
                    TelefonoREG = listado[i+1]
                    TelefonoREG = re.split("[\n+.]",TelefonoREG)
                    for y in TelefonoREG:
                        if y != " ":
                            AhoraLargo = len(y)
                            if AhoraLargo > Largo:
                                Largo = AhoraLargo
                                Telefono = y

            if not Telefono:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return
        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return

        evt = SpiderFootEvent("PHONE_NUMBER", Telefono, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_WhoisRegistrantPhone class
