import sys
from binary import *
from core import *
import argparse

def printGadget(gadget, important = False):
  instr, addr = gadget

  if important:
    print ('[*] 0x%x: %s' % (addr, instr))
  else:
    print ('0x%x: %s' % (addr, instr))

def main():
  parser = argparse.ArgumentParser()

  parser.add_argument('--binary', type=str, required=True,
                      help='Specify binary name')
  parser.add_argument('--depth', type=int, default=5,
                       help='Max length of gadget')
  parser.add_argument('--dup', action='store_true',
                       help='Print all duplicated gadgets')
  parser.add_argument('--minor', action='store_true',
                       help='Print minor gadgets')

  args = parser.parse_args(sys.argv[1:])

  filename = args.binary
  depth = args.depth
  dup = args.dup
  minor = args.minor

  binary = CLEMENCY(filename)

  code = binary.getCode()

  print ("--- Library addresses ---")
  findLibraries(code)
  print ("")

  print ("--- ROP Gadgets ---")
  gadgets = findGadgets(code, depth, dup)
  importantGadgets = []

  for gadget in gadgets:
    gadget_instr, addr = gadget

    if gadget_instr.find('RE') > 0 and \
       gadget_instr.find('LDT R28, [R28 + 0x0, 3]') > 0:
      importantGadgets.append(gadget)
    elif gadget_instr.find('RE') > 0:
      if minor:
        printGadget(gadget)
    else:
      importantGadgets.append(gadget)

  for gadget in importantGadgets:
    printGadget(gadget, important=True)

if __name__ == "__main__":
  main()
