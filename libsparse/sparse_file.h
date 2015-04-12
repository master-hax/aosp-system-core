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

#ifndef _LIBSPARSE_SPARSE_FILE_H_
#define _LIBSPARSE_SPARSE_FILE_H_

#include <sparse/sparse.h>

struct sparse_file_layer {
	int order;
	struct backed_block_list *block_list;
	struct sparse_file_layer *next;
};

struct sparse_file {
	unsigned int block_size;
	int64_t len;
	bool verbose;
	struct sparse_file_layer *layer;		/* current layer */
	struct sparse_file_layer *default_layer;	/* default layer for backward compatible */
	struct sparse_file_layer *layer_list;
	struct output_file *out;
};

struct sparse_file_layer *sparse_file_layer_lookup(struct sparse_file *s, int order);

#endif /* _LIBSPARSE_SPARSE_FILE_H_ */
