import sys

def eprint(msg):
  sys.stderr.write(msg + '\n')

def main():
  script, command, fname = sys.argv
  eprint("Messages here will go to the parent testers logs")
  eprint("Hello world")
  print("This goes to stdout as expected")
  # non-zero return code signals error
  return -1


if __name__ == "__main__":
  sys.exit(main())
