#!/usr/bin/env python
#
# pulsedata.py - scans a log file produced by hd_root for exceptions thrown by
#                the DEVIOWorkerThread::Parsef250Bank reporting bad pulse data
#                from the frontend fadc250 module, and print out a parsed 
#                listing of the contents of the defective block.
#
# author: richard.t.jones at uconn.edu
# version: march 17, 2020

import fileinput
import re
import sys

def eprint(msg=""):
   global eprint_repeat
   global eprint_msg
   try:
      if len(eprint_msg) > 0 and eprint_msg != msg:
         print eprint_msg
         if eprint_repeat > 0:
            print "*** last message was repeated", eprint_repeat+1, "times ***"
         eprint_repeat = 0
         eprint_msg = msg
      elif len(eprint_msg) > 0:
         eprint_repeat += 1
      else:
         eprint_repeat = 0
         eprint_msg = msg
   except:
      eprint_repeat = 0
      eprint_msg = msg

def parse_block(block):
   p = 0
   while p < len(block):
      if   (block[p] & 0xf8000000) == 0x80000000: # block header
         slot = (block[p] >> 22) & 0x1f
         moduleId = (block[p] >> 18) & 0x7
         blockNo = (block[p] >> 8) & 0x3ff
         eventcount = block[p] & 0xff
         eprint(("  block header: module {0} in slot {1}, block {2} with" +
                 " {3} events").format(moduleId, slot, blockNo, eventcount))
      elif (block[p] & 0xf8000000) == 0x88000000: # block trailer
         slot = (block[p] >> 22) & 0x1f
         blockwords = block[p] & 0x3fffff
         eprint("  block trailer: slot {0} with {1} words".format(slot, blockwords))
      elif (block[p] & 0xf8000000) == 0x90000000: # event header
         slot = (block[p] >> 22) & 0x1f
         trigtime = (block[p] >> 12) & 0x3ff
         eventno = block[p] & 0xfff
         eprint("    event header: slot {0}, event {1}, trigger time {2}".format(slot, eventno, trigtime))
      elif (block[p] & 0xffffffff) == 0x80000000: # event trailer
         eprint("    event trailer: slot {0}, event {1}".format(slot, eventno))
      elif (block[p] & 0xf8000000) == 0x98000000: # trigger time (1)
         TD = (block[p] >> 16) & 0xff
         TE = (block[p] >> 8) & 0xff
         TF = (block[p] & 0xff)
         p += 1
         if (block[p] & 0xff000000) != 0:
            eprint("ERROR - expected trigger time (2), found {0:08x}".format(block[p]))
            break
         TA = (block[p] >> 16) & 0xff
         TB = (block[p] >> 8) & 0xff
         TC = (block[p] & 0xff)
         trigtime = ((TA << 40) + (TB << 32) + (TC << 24) +
                     (TD << 16) + (TE << 8) + TF)
         eprint("    event trigger time: {0}".format(trigtime))
      elif (block[p] & 0xf807ff00) == 0xa0000000: # window raw data
         channel = (block[p] >> 23) & 0xf
         winwidth = block[p] & 0xfff
         eprint(("      window raw data:" +
                 "channel {0} with {1} words").format(channel, winwidth))
         for i in range(0, winwidth):
            p += 1
            if (block[p] & 0xc000c000) != 0:
               eprint("ERROR - expected window raw data, found {0:08x}".format(block[p]))
               break
            val0 = block[p] >> 16
            val1 = block[p] & 0xffff
            if (val0 & 0x1000) == 0:
               eprint("        {0}: {1:04x}".format(2*i, val0))
            if (val1 & 0x1000) == 0:
               eprint("        {0}: {1:04x}".format(2*i+1, val1))
      elif (block[p] & 0xf81ffc00) == 0xb0000000: # pulse raw data
         channel = (block[p] >> 23) & 0xf
         pulse = (block[p] >> 21) & 0x3
         tcross = block[p] & 0x1ff
         eprint(("      pulse raw data for channel" +
                 "{0}: pulse {1}, tcross {2:03x}").format(channel, pulse, tcross))
         while p < len(block) and (block[p+1] & 0xc000c000) == 0:
            p += 1
            val0 = block[p] >> 16
            val1 = block[p] & 0xffff
            if (val0 & 0x1000) == 0:
               eprint("        {0}: {1:04x}".format(2*i, val0))
            if (val1 & 0x1000) == 0:
               eprint("        {0}: {1:04x}".format(2*i+1, val1))
      elif (block[p] & 0xf8000000) == 0xb8000000: # pulse integral
         channel = (block[p] >> 23) & 0xf
         pulse = (block[p] >> 21) & 0x3
         qf = (block[p] >> 19) & 0x3
         integral = block[p] & 0x7ffff
         eprint(("      pulse integral for channel {0} pulse {1}: " +
                 "{2} with qf {3:02x}").format(channel, pulse, integral, qf))
      elif (block[p] & 0xf8078000) == 0xc0000000: # pulse time
         channel = (block[p] >> 23) & 0xf
         pulse = (block[p] >> 21) & 0x3
         qf = (block[p] >> 19) & 0x3
         time = block[p] & 0x7fff
         eprint(("      pulse time for channel {0} pulse {1}:" +
                 " {2} with qf {3:02x}").format(channel, pulse, time, qf))
      elif (block[p] & 0xf8000000) == 0xd0000000: # pulse peak
         channel = (block[p] >> 23) & 0xf
         pulse = (block[p] >> 21) & 0x3
         pedestal = (block[p] >> 12) & 0x1ff
         peak = block[p] & 0xfff
         eprint(("      pulse peak for channel {0} pulse {1}: " +
                 "{2} with pedestal {3}").format(channel, pulse, peak, pedestal))
      elif (block[p] & 0xf8000000) == 0xc8000000: # pulse parameters
         event = (block[p] >> 19) & 0xff
         channel = (block[p] >> 15) & 0xf
         pedestal = block[p] & 0x7fff
         eprint(("      pulse parameters for channel {0} event {1}:" +
                 " pedestal {2} with qf {3:01x}").format(channel, event,
                 pedestal & 0x3fff, pedestal >> 14))
         while p + 1 < len(block) and (block[p + 1] & 0xc0000000) == 0x40000000:
            p += 1
            integral = (block[p] >> 12) & 0x3ffff
            qf = (block[p] >> 9) & 0x7
            samples = (block[p] & 0x1ff)
            eprint(("         pulse integral {0}, {1} samples above threshold," +
                    " qf {2:01x}").format(integral, samples, qf))
            p += 1
            if (block[p] & 0xc0000000) == 0:
               time = (block[p] >> 15) & 0x7fff
               peak = (block[p] >> 3) & 0x3fff
               qf = block[p] & 0x7
               eprint("         pulse time {0}, peak {1}, qf {2:01x} ({3:08x})".format(time, peak, qf, block[p]))
            else:
               eprint(("ERROR - unexpected word {:08x} in place of pulse" +
                       " time word").format(block[p]))
      elif (block[p] & 0xf8000000) == 0xf8000000: # filler word
         slot = (block[p] >> 22) & 0x1f
         eprint("      filler word for slot {0}".format(slot))
      else:
         eprint("ERROR - unexpected word {:08x}".format(block[p]))
      p += 1
   eprint()
   return 0

dumping_binary = 0
for line in fileinput.input():
   line = line.rstrip()
   if "Bad f250 Pulse Data " in line:
      print "Bad f250 Pulse Data:"
      dumping_binary = 1
      continue
   if dumping_binary == 1:
      m = re.match(r"Dumping binary: istart=(0x[0-9a-f]+) " +
                   r"iend=(0x[0-9a-f]+) MaxWords=([0-9]+)",
                   line)
      if m:
         try:
            istart = int(m.group(1), 0)
            iend = int(m.group(2), 0)
            maxwords = int(m.group(3), 0)
            block = []
            dumping_binary = 2
         except:
            print "bad decode of ", m.group(1)
            print "from", line
      else:
         print "Parse error -- missing 'Dumping binary' line in log!"
         print line
         print "cannot continue, aborting"
         sys.exit(1)
   elif dumping_binary == 2:
      m = re.match(r" *([0-9]+) +(0x[0-9a-f]+)\** +(0x[0-9a-f]+)\** +" +
                   r"(0x[0-9a-f]+)\** +(0x[0-9a-f]+)\** +(0x[0-9a-f]+)\** +" +
                   r"(0x[0-9a-f]+)\** +(0x[0-9a-f]+)\** +(0x[0-9a-f]+)\**",
                   line)
      if m:
         for n in range(0, 8):
            block.append(int(m.group(n + 2), 0))
      elif "JANA ERROR>>Now let's REALLY print something!!!" in line:
         block = []
         dumping_binary == 1
      elif "JANA ERROR" in line:
         parse_block(block)
         dumping_binary = 0
