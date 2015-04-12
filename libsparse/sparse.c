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

#include <assert.h>
#include <stdlib.h>

#include <sparse/sparse.h>

#include "defs.h"
#include "sparse_file.h"

#include "output_file.h"
#include "backed_block.h"
#include "sparse_defs.h"
#include "sparse_format.h"

struct sparse_file_layer *sparse_file_layer_lookup(struct sparse_file *s, int order)
{
	struct sparse_file_layer *prev, *next;
	struct backed_block_list *list;
	struct sparse_file_layer *layer = NULL;

	/* mostly likely in current layer */
	if (s->layer && s->layer->order == order)
		return s->layer;

	/* search for the ordered list */
	for (prev = NULL, next = s->layer_list;
	     next != NULL && next->order <= order;
	     prev = next, next = next->next) {
		if (prev && prev->order == order) {
			layer = prev;
			break;
		}
		if (next && next->order == order) {
			layer = next;
			break;
		}
	}

	/* found an existing one */
	if (layer) {
		s->layer = layer;
		return layer;
	}

	/* lookup failed, create a new one between prev and next */
	layer = calloc(1, sizeof(*layer));
	if (layer == NULL)
		return NULL;

	layer->block_list = backed_block_list_new(s->block_size);
	if (layer->block_list == NULL) {
		free(layer);
		return NULL;
	}

	layer->order = order;
	layer->next = next;
	if (prev == NULL)
		s->layer_list = layer;
	else
		prev->next = layer;
	s->layer = layer;
	return layer;
}

struct sparse_file *sparse_file_new(unsigned int block_size, int64_t len)
{
	struct sparse_file *s = calloc(sizeof(struct sparse_file), 1);
	if (!s) {
		return NULL;
	}

	s->block_size = block_size;
	s->len = len;

	/* default layer order being 0 */
	s->layer = sparse_file_layer_lookup(s, 0);
	return s;
}

void sparse_file_destroy(struct sparse_file *s)
{
	struct sparse_file_layer *layer, *next;

	for (layer = s->layer_list; layer; layer = next) {
		next = layer->next;
		backed_block_list_destroy(layer->block_list);
		free(layer);
	}
	free(s);
}

int sparse_file_add_data(struct sparse_file *s,
		void *data, unsigned int len, unsigned int block)
{
	return backed_block_add_data(s->layer->block_list, data, len, block);
}

int sparse_file_add_fill(struct sparse_file *s,
		uint32_t fill_val, unsigned int len, unsigned int block)
{
	return backed_block_add_fill(s->layer->block_list, fill_val, len, block);
}

int sparse_file_add_file(struct sparse_file *s,
		const char *filename, int64_t file_offset, unsigned int len,
		unsigned int block)
{
	return backed_block_add_file(s->layer->block_list, filename, file_offset,
			len, block);
}

int sparse_file_add_fd(struct sparse_file *s,
		int fd, int64_t file_offset, unsigned int len, unsigned int block)
{
	return backed_block_add_fd(s->layer->block_list, fd, file_offset,
			len, block);
}

int sparse_file_add_data_ordered(struct sparse_file *s, int order,
		void *data, unsigned int len, unsigned int block)
{
	struct sparse_file_layer *layer = sparse_file_layer_lookup(s, order);
	if (layer == NULL)
		return -ENOMEM;
	return backed_block_add_data(layer->block_list, data, len, block);
}

int sparse_file_add_fill_ordered(struct sparse_file *s, int order,
		uint32_t fill_val, unsigned int len, unsigned int block)
{
	struct sparse_file_layer *layer = sparse_file_layer_lookup(s, order);
	if (layer == NULL)
		return -ENOMEM;
	return backed_block_add_fill(layer->block_list, fill_val, len, block);
}

int sparse_file_add_file_ordered(struct sparse_file *s, int order,
		const char *filename, int64_t file_offset, unsigned int len,
		unsigned int block)
{
	struct sparse_file_layer *layer = sparse_file_layer_lookup(s, order);
	if (layer == NULL)
		return -ENOMEM;
	return backed_block_add_file(layer->block_list, filename, file_offset,
			len, block);
}

int sparse_file_add_fd_ordered(struct sparse_file *s, int order,
		int fd, int64_t file_offset, unsigned int len, unsigned int block)
{
	struct sparse_file_layer *layer = sparse_file_layer_lookup(s, order);
	if (layer == NULL)
		return -ENOMEM;
	return backed_block_add_fd(layer->block_list, fd, file_offset,
			len, block);
}

unsigned int sparse_count_chunks(struct sparse_file *s)
{
	struct backed_block *bb;
	unsigned int last_block = 0;
	unsigned int chunks = 0;
	struct sparse_file_layer *layer;

	for (layer = s->layer_list; layer; layer = layer->next) {
		for (bb = backed_block_iter_new(layer->block_list); bb;
			bb = backed_block_iter_next(bb)) {
			if (backed_block_block(bb) > last_block) {
				/* If there is a gap between chunks, add a skip chunk */
				chunks++;
			}
			chunks++;
			last_block = backed_block_block(bb) +
				DIV_ROUND_UP(backed_block_len(bb), s->block_size);
		}
		/* If there is a new layer, add a REWIND chunk */
		if (layer->next) {
			chunks++;
			last_block = 0;
		}
	}
	if (last_block < DIV_ROUND_UP(s->len, s->block_size)) {
		chunks++;
	}

	return chunks;
}

static int sparse_file_write_block(struct output_file *out,
		struct backed_block *bb)
{
	int ret = -EINVAL;

	switch (backed_block_type(bb)) {
	case BACKED_BLOCK_DATA:
		ret = write_data_chunk(out, backed_block_len(bb), backed_block_data(bb));
		break;
	case BACKED_BLOCK_FILE:
		ret = write_file_chunk(out, backed_block_len(bb),
				       backed_block_filename(bb),
				       backed_block_file_offset(bb));
		break;
	case BACKED_BLOCK_FD:
		ret = write_fd_chunk(out, backed_block_len(bb),
				     backed_block_fd(bb),
				     backed_block_file_offset(bb));
		break;
	case BACKED_BLOCK_FILL:
		ret = write_fill_chunk(out, backed_block_len(bb),
				       backed_block_fill_val(bb));
		break;
	}

	return ret;
}

static int write_all_blocks(struct sparse_file *s, struct output_file *out)
{
	struct sparse_file_layer *layer;
	struct backed_block *bb;
	unsigned int last_block = 0;
	int64_t pad;
	int ret = 0;

	for (layer = s->layer_list; layer; layer = layer->next) {
		for (bb = backed_block_iter_new(layer->block_list); bb;
			bb = backed_block_iter_next(bb)) {
			if (backed_block_block(bb) > last_block) {
				unsigned int blocks = backed_block_block(bb) - last_block;
				write_skip_chunk(out, (int64_t)blocks * s->block_size);
			}
			ret = sparse_file_write_block(out, bb);
			if (ret)
				return ret;
			last_block = backed_block_block(bb) +
				DIV_ROUND_UP(backed_block_len(bb), s->block_size);
		}
		if (layer->next) {
			write_rewind_chunk(out);
			last_block = 0;
		}
	}

	pad = s->len - (int64_t)last_block * s->block_size;
	assert(pad >= 0);
	if (pad > 0) {
		write_skip_chunk(out, pad);
	}

	return 0;
}

int sparse_file_write(struct sparse_file *s, int fd, bool gz, bool sparse,
		bool crc)
{
	int ret;
	int chunks;
	struct output_file *out;

	chunks = sparse_count_chunks(s);
	out = output_file_open_fd(fd, s->block_size, s->len, gz, sparse, chunks, crc);

	if (!out)
		return -ENOMEM;

	ret = write_all_blocks(s, out);

	output_file_close(out);

	return ret;
}

int sparse_file_callback(struct sparse_file *s, bool sparse, bool crc,
		int (*write)(void *priv, const void *data, int len), void *priv)
{
	int ret;
	int chunks;
	struct output_file *out;

	chunks = sparse_count_chunks(s);
	out = output_file_open_callback(write, priv, s->block_size, s->len, false,
			sparse, chunks, crc);

	if (!out)
		return -ENOMEM;

	ret = write_all_blocks(s, out);

	output_file_close(out);

	return ret;
}

static int out_counter_write(void *priv, const void *data __unused, int len)
{
	int64_t *count = priv;
	*count += len;
	return 0;
}

int64_t sparse_file_len(struct sparse_file *s, bool sparse, bool crc)
{
	int ret;
	int chunks = sparse_count_chunks(s);
	int64_t count = 0;
	struct output_file *out;

	out = output_file_open_callback(out_counter_write, &count,
			s->block_size, s->len, false, sparse, chunks, crc);
	if (!out) {
		return -1;
	}

	ret = write_all_blocks(s, out);

	output_file_close(out);

	if (ret < 0) {
		return -1;
	}

	return count;
}

static struct backed_block *move_chunks_up_to_len(
		struct sparse_file_layer *from,
		struct sparse_file *to, unsigned int len)
{
	int64_t count = 0;
	struct output_file *out_counter;
	struct backed_block *last_bb = NULL;
	struct backed_block *bb;
	struct backed_block *start;
	int64_t file_len = 0;
	int ret;

	/*
	 * overhead is sparse file header, initial skip chunk, split chunk, end
	 * skip chunk, and crc chunk.
	 */
	int overhead = sizeof(sparse_header_t) + 4 * sizeof(chunk_header_t) +
			sizeof(uint32_t);
	len -= overhead;

	start = backed_block_iter_new(from->block_list);
	out_counter = output_file_open_callback(out_counter_write, &count,
			to->block_size, to->len, false, true, 0, false);
	if (!out_counter) {
		return NULL;
	}

	for (bb = start; bb; bb = backed_block_iter_next(bb)) {
		count = 0;
		/* will call out_counter_write to update count */
		ret = sparse_file_write_block(out_counter, bb);
		if (ret) {
			bb = NULL;
			goto out;
		}
		if (file_len + count > len) {
			/*
			 * If the remaining available size is more than 1/8th of the
			 * requested size, split the chunk.  Results in sparse files that
			 * are at least 7/8ths of the requested size
			 */
			if (!last_bb || (len - file_len > (len / 8))) {
				backed_block_split(from->block_list, bb, len - file_len);
				last_bb = bb;
				file_len += (len - file_len);
			}
			goto move;
		}
		file_len += count;
		last_bb = bb;
	}

move:
	backed_block_list_move(from->block_list,
		to->layer->block_list, start, last_bb);

out:
	output_file_close(out_counter);

	return bb;
}

int sparse_file_resparse(struct sparse_file *in_s, unsigned int max_len,
		struct sparse_file **out_s, int out_s_count)
{
	struct backed_block *bb;
	struct sparse_file *s;
	struct sparse_file *tmp;
	struct sparse_file_layer *layer;
	int c = 0;

	tmp = sparse_file_new(in_s->block_size, in_s->len);
	if (!tmp) {
		return -ENOMEM;
	}

	for (layer = in_s->layer_list; layer; layer = layer->next) {
		do {
			s = sparse_file_new(in_s->block_size, in_s->len);

			bb = move_chunks_up_to_len(layer, s, max_len);

			if (c < out_s_count) {
				out_s[c] = s;
			} else {
				backed_block_list_move(s->layer->block_list,
						       tmp->layer->block_list,
						       NULL, NULL);
				sparse_file_destroy(s);
			}
			c++;
		} while (bb);

		/* move back to the original layer */
		backed_block_list_move(tmp->layer->block_list,
				       layer->block_list, NULL, NULL);
	}

	sparse_file_destroy(tmp);

	return c;
}

void sparse_file_verbose(struct sparse_file *s)
{
	s->verbose = true;
}
