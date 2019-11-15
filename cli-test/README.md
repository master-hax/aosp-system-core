# cli-test

## What?

`cli-test` makes integration testing of command-line tools easier.

## Goals

* Readable syntax. Common cases should be concise, and pretty much anyone
  should be able to read tests even if they've never seen this tool before.

* Minimal issues with quoting. The toybox tests -- being shell scripts --
  quickly become a nightmare of quoting. Using a non ad hoc format (such as
  JSON) would have introduced similar but different quoting issues. A custom
  format, while annoying, side-steps this.

* Sensible defaults. We expect your exit status to be 0 unless you say
  otherwise. We expect nothing on stderr unless you say otherwise. And so on.

* Convention over configuration. Related to sensible defaults, we don't let you
  configure things that aren't absolutely necessary. So you can't keep your test
  data anywhere except in the `files/` subdirectory of the directory containing
  your test, for example.

## Non Goals

* Portability. Just being able to run on Linux (host and device) is sufficient
  for our needs. macOS is probably easy enough if we ever need it, but Windows
  probably doesn't make sense.

## Syntax

## Example

## Bugs

## Future Directions

* It's often useful to be able to *match* against stdout/stderr/a file rather
  than give exact expected output. We might want to add explicit support for
  this. In the meantime, it's possible to use an `after:` with `grep -q` if
  you redirect in your `command:`.

* In addition to using a `before:` (which will fail a test), it can be useful
  to be able to specify tests that would cause us to *skip* a test. An example
  would be "am I running as root?".
