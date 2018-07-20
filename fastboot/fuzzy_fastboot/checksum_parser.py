import sys

  sys.stderr.write(msg + '\n')

def main():
  script, response, info = sys.argv
  print sys.argv
  sys.stderr.write(b'abc123')
  print("I'm in the parser!")

  # non-zero return code signals error
  return 0


if __name__ == "__main__":
  sys.exit(main())
