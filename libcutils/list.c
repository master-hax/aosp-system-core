/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <cutils/list.h>

void list_init(struct listnode *node)
{
    node->next = node;
    node->prev = node;
}

int node_in_list(struct listnode *head, struct listnode *item)
{
    struct listnode *temp = head;

    if ( !head || !item)
        return 0;

    do {
        if (temp == item)
            return 1;
        temp = temp->next;
    }
    while (temp != head);

    return 0;
}

void list_add_tail(struct listnode *head, struct listnode *item)
{
    item->next = head;
    item->prev = head->prev;
    head->prev->next = item;
    head->prev = item;
}

void list_remove(struct listnode *item)
{
    item->next->prev = item->prev;
    item->prev->next = item->next;
}
