import sys

def main():
  script, response, info = sys.argv
  # the info responses are concated by newlines
  infos = [s.strip() for s in info.splitlines()]
  sys.stderr.write(infos[-1])
  print("Hi I am the parser, extracted checksum: '%s'" % infos[-1])
  # non-zero return code signals error
  return 0


if __name__ == "__main__":
  sys.exit(main())
