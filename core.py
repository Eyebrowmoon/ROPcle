import sys
from binary import *
from libdict import *
from disassemble import *

coreGadgets = ['RE', 'CR', 'BR']

filtered = \
['B', 'BR', 'BRA', 'BRR', 
'C', 'CAA', 'CAR', 'CR', 
'HT', 'IR', 'RE']

possible_instr_len = [2, 3, 4, 6]

def compute_pi(pattern):
  ret = [0]

  for i in range(1, len(pattern)):
    j = ret[i - 1]

    while j > 0 and pattern[j] != pattern[i]:
      j = ret[j - 1]
    
    ret.append(j + 1 if pattern[j] == pattern[i] else j)

  return ret

def search(code, pattern):
  pi, ret, j = compute_pi(pattern), [], 0
  pattern_len, code_len = len(pattern), len(code)

  for i in range(code_len):
    while j > 0 and code[i] != pattern[j]:
      j = pi[j - 1]
    
    if code[i] == pattern[j]:
      j += 1

    if j == pattern_len:
      ret.append(i - j + 1)
      j = 0

  return ret

def match(a, b):
  if len(a) != len(b):
    return False

  length = len(a)
  for i in range(length):
    if a[i] != b[i]:
      return False

  return True

def findLibraries(code):
  dic = LibraryDict().getDict()

  for key in dic.keys():
    addr_arr = search(code, dic[key])

    if len(addr_arr) < 1:
      print ("%s not found" % key)
    else:
      print ("%s: 0x%x" % (key, addr_arr[0]))

def findCoreGadgets(code):
  codelen = len(code) - 6
  gadgets = []

  for idx in range(codelen):
    inst = checkinst(code, idx)
        
    if inst is None:
      continue
    if inst.type in coreGadgets:
      gadgets.append((inst.tostring(), idx))

  return gadgets

def alreadyExist(newGadget, gadgetList):
  gadget_str = newGadget[0]

  for gadget in gadgetList:
    if gadget_str == gadget[0]:
      return True

  return False

def compareInstrs(instr1, instr2):
  instr_arr1 = instr1.split(';')
  instr_arr2 = instr2.split(';')

  len1, len2 = len(instr_arr1), len(instr_arr2)
  length = min([len1, len2])

  for i in range(length):
    if instr_arr1[i] > instr_arr2[i]:
      return 1
    elif instr_arr1[i] < instr_arr2[i]:
      return -1

  if len1 > len2:
    return 1
  elif len1 < len2:
    return -1
  else:
    return 0

def compareGadgets(gadget1, gadget2):
  instr1, addr1 = gadget1
  instr2, addr2 = gadget2

  cinstr = compareInstrs(instr1, instr2)
  if cinstr != 0:
    return cinstr
  else:
    return 1 if addr1 > addr2 else 0

def cmp_to_key(mycmp):
  class K:
    def __init__(self, obj, *args):
      self.obj = obj
    def __lt__(self, other):
      return mycmp(self.obj, other.obj) < 0
    def __gt__(self, other):
      return mycmp(self.obj, other.obj) > 0
    def __eq__(self, other):
      return mycmp(self.obj, other.obj) == 0
    def __le__(self, other):
      return mycmp(self.obj, other.obj) <= 0
    def __ge__(self, other):
      return mycmp(self.obj, other.obj) >= 0
    def __ne__(self, other):
      return mycmp(self.obj, other.obj) != 0
  return K

def findGadgets(code, depth, dup):
  newGadgets = findCoreGadgets(code)
  completeGadgets = []

  for curDepth in range(depth):
    gadgets = newGadgets
    newGadgets = []

    for gadget in gadgets:
      s, addr = gadget

      for instr_len in possible_instr_len:
        start = addr - instr_len
        inst = checkinst(code, start)
        
        if inst is None:
          continue
        if inst.length() != instr_len:
          continue
        if inst.type in filtered:
          continue

        instr_str = inst.tostring()

        newGadgets.append((instr_str + "; " + s, start))

      if dup or not alreadyExist(gadget, completeGadgets):
        completeGadgets.append(gadget)

  key = cmp_to_key(compareGadgets)
  return sorted(completeGadgets, key=key) 
