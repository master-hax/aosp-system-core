/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <private/sparse/sparse_utils.h>

void usage()
{
  fprintf(stderr, "Usage: simg2simg <input sparse file> <output sparse basename> <max_size>\n");
}

int main(int argc, char *argv[])
{
	if (argc != 4) {
		usage();
		return -1;
	}

	return simg2simg(argv[1], argv[2], atoll(argv[3]));
}
