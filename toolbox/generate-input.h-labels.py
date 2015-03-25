#!/usr/bin/env python
#
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# pylint: disable=bad-indentation,bad-continuation

import os
import re
import sys

input_prop_list = list()
ev_list = list()
syn_list = list()
key_list = list()
rel_list = list()
abs_list = list()
sw_list = list()
msc_list = list()
led_list = list()
rep_list = list()
snd_list = list()
mt_tool_list = list()
ff_status_list = list()
ff_list = list()

r = re.compile(r'#define\s+(\S+)\s+((?:0x)?\d+)')

f = open(os.environ['ANDROID_BUILD_TOP'] + '/bionic/libc/kernel/uapi/linux/input.h', 'r')
for line in f.read().splitlines():
  m = r.match(line)
  if m:
    name = m.group(1)
    if name.startswith("INPUT_PROP_"):
      input_prop_list.append(name)
    elif name.startswith("EV_"):
      ev_list.append(name)
    elif name.startswith("SYN_"):
      syn_list.append(name)
    elif name.startswith("KEY_") or name.startswith("BTN_"):
      key_list.append(name)
    elif name.startswith("REL_"):
      rel_list.append(name)
    elif name.startswith("ABS_"):
      abs_list.append(name)
    elif name.startswith("SW_"):
      sw_list.append(name)
    elif name.startswith("MSC_"):
      msc_list.append(name)
    elif name.startswith("LED_"):
      led_list.append(name)
    elif name.startswith("REP_"):
      rep_list.append(name)
    elif name.startswith("SND_"):
      snd_list.append(name)
    elif name.startswith("MT_TOOL_"):
      mt_tool_list.append(name)
    elif name.startswith("FF_STATUS_"):
      ff_status_list.append(name)
    elif name.startswith("FF_"):
      ff_list.append(name)

f.close()

def Dump(list_name, list):
  print 'static struct label %s_labels[] = {' % (list_name)
  for element in list:
    print '    LABEL(%s),' % (element)
  print '    LABEL_END,'
  print '};'

Dump("input_prop", input_prop_list)
Dump("ev", ev_list)
Dump("syn", syn_list)
Dump("key", key_list)
Dump("rel", rel_list)
Dump("abs", abs_list)
Dump("sw", sw_list)
Dump("msc", msc_list)
Dump("led", led_list)
Dump("rep", rep_list)
Dump("snd", snd_list)
Dump("mt_tool", mt_tool_list)
Dump("ff_status", ff_status_list)
Dump("ff", ff_list)

sys.exit(0)
