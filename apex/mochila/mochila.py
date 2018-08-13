#!/usr/bin/env python
#
# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
mochila is a command line tool for creating an APEX file, a new package format
for system components.

Its name is derived from the Pony Express mochila
(https://en.wikipedia.org/wiki/Pony_Express_mochila), which was used as a mail
bag by the Pony Express.

Typical usage: mochila --manifest manifest.json input_dir output.apex


Missing features:
- protect the filesystem image with dm-verity
- uid/gid mapping of the files in the filesystem image
- labeling the files in the filesystem image
- versioning
- dump of an apex file (without actually mounting)
- signing (not clear whether it should be done by mochila)
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback

def ParseArgs(argv):
  parser = argparse.ArgumentParser(description='Create an APEX file')
  parser.add_argument('-f', '--force', action='store_true',
                      help='force overwriting output')
  parser.add_argument('-v', '--verbose', action='store_true',
                      help='verbose execution')
  parser.add_argument('--manifest', required=True,
                      help='path to the APEX manifest file')
  parser.add_argument('input_dir', metavar='INPUT_DIR',
                      help='the directory having files to be packaged')
  parser.add_argument('output', metavar='OUTPUT',
                      help='name of the APEX file')
  return parser.parse_args(argv)


def RunCommand(cmd, verbose=None, env=None):
  env_copy = None
  if env is not None:
    env_copy = os.environ.copy()
    env_copy.update(env)
  if verbose:
    print("Running: " + " ".join(cmd))
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       env=env_copy)
  output, _ = p.communicate()

  if verbose:
    print(output.rstrip())

  assert p.returncode is 0, "Failed to execute: " + " ".join(cmd)

  return (output, p.returncode)


def GetDirSize(dir_name):
  size = 0
  for dirpath, dirnames, filenames in os.walk(dir_name):
    for f in filenames:
      size += os.path.getsize(os.path.join(dirpath, f))
  return size


def PrepareAndroidManifest(packagename):
  template = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
  package="{packagename}">
</manifest>
"""
  return template.format(packagename=packagename)

def ValidateArgs(args):
  if not os.path.exists(args.manifest):
    print("Manifest file '" + args.manifest + "' does not exist")
    return False

  if not os.path.isfile(args.manifest):
    print("Manifest file '" + args.manifest + "' is not a file")
    return False

  if not os.path.exists(args.input_dir):
    print("Input directory '" + args.input_dir + "' does not exist")
    return False

  if not os.path.isdir(args.input_dir):
    print("Input directory '" + args.input_dir + "' is not a directory")
    return False

  if not args.force and os.path.exists(args.output):
    print(args.output + ' already exists. Use --force to overwrite.')
    return False

  return True

def CreateApex(args, work_dir):
  if not ValidateArgs(args):
    return False

  try:
    with open(args.manifest) as f:
      manifest = json.load(f)
  except ValueError:
    print("'" + args.manifest + "' is not a valid manifest file")
    return False
  except IOError:
    print("Cannot read manifest file: '" + args.manifest + "'")
    return False

  if 'name' not in manifest or manifest['name'] is None:
    print("Invalid manifest: 'name' not exist")
    return False
  package_name = manifest['name']

  # Step 1: create an empty ext4 image that is sufficiently big
  # Sufficiently big = twice the size of the input directory
  size_in_mb = GetDirSize(args.input_dir) * 2 / (1024*1024)

  content_dir = os.path.join(work_dir, 'content')
  os.mkdir(content_dir)
  img_file =  os.path.join(content_dir, 'image.img')

  cmd = ['mke2fs']
  cmd.extend(['-O', '^has_journal']) # because image is read-only
  cmd.extend(['-b', '4096']) # block size
  cmd.extend(['-m', '0']) # reserved block percentage
  cmd.extend(['-t', 'ext4'])
  cmd.append(img_file)
  cmd.append(str(size_in_mb) + 'M')
  RunCommand(cmd, args.verbose)

  # Step 2: Add files to the image file
  cmd = ['e2fsdroid']
  cmd.append('-e') # input is not android_sparse_file
  cmd.extend(['-f', args.input_dir])
  cmd.append(img_file)
  RunCommand(cmd, args.verbose)

  # APEX manifest is also included in the image. The manifest is included
  # twice: once inside the image and once outside the image (but still
  # within the zip container).
  manifests_dir = os.path.join(work_dir, 'manifests')
  os.mkdir(manifests_dir)
  manifest_file = os.path.join(manifests_dir, 'manifest.json')
  if args.verbose:
    print('Copying ' + args.manifest + ' to ' + manifest_file)
  shutil.copyfile(args.manifest, manifest_file)

  cmd = ['e2fsdroid']
  cmd.append('-e') # input is not android_sparse_file
  cmd.extend(['-f', manifests_dir])
  cmd.append(img_file)
  RunCommand(cmd, args.verbose)

  # Step 3: Resize the image file to save space
  cmd = ['resize2fs']
  cmd.append('-M') # shrink as small as possible
  cmd.append(img_file)
  RunCommand(cmd, args.verbose)

  # Step 4: package the image file and APEX manifest as an APK.
  # The AndroidManifest file is automatically generated.
  android_manifest_file = os.path.join(work_dir, 'AndroidManifest.xml')
  if args.verbose:
    print('Creating AndroidManifest ' + android_manifest_file)
  with open(android_manifest_file, 'w+') as f:
    f.write(PrepareAndroidManifest(package_name))

  # copy manifest to the content dir so that it is also accessible
  # without mounting the image
  shutil.copyfile(args.manifest, os.path.join(content_dir, 'manifest.json'))

  unaligned_apex_file = os.path.join(work_dir, 'unaligned.apex')
  cmd = ['aapt2']
  cmd.append('link')
  cmd.extend(['--manifest', android_manifest_file])
  cmd.extend(['-o', unaligned_apex_file])
  RunCommand(cmd, args.verbose)

  cwd = os.getcwd()
  os.chdir(content_dir)
  cmd = ['zip']
  cmd.append('-qrX')
  cmd.append('-0') # don't compress
  cmd.append(unaligned_apex_file)
  cmd.append('.')
  RunCommand(cmd, args.verbose)
  os.chdir(cwd)

  # Step 5: Align the files at page boundary for efficient access
  cmd = ['zipalign']
  cmd.append('-f')
  cmd.append('4096') # 4k alignment
  cmd.append(unaligned_apex_file)
  cmd.append(args.output)
  RunCommand(cmd, args.verbose)

  if (args.verbose):
    print('Created ' + args.output)

  return True


class TempDirectory(object):
  def __enter__(self):
    self.name = tempfile.mkdtemp()
    return self.name

  def __exit__(self, exc_type, exc_value, traceback):
    shutil.rmtree(self.name)


def main(argv):
  args = ParseArgs(argv)
  with TempDirectory() as work_dir:
    success = CreateApex(args, work_dir)

  if not success:
    sys.exit(1)


if __name__ == '__main__':
  main(sys.argv[1:])
