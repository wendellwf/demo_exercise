//
// Created by wendell on 2024/9/14.
//

#ifndef HASHTABLE_H
#define HASHTABLE_H
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string>

// hashtable node, should be embedded into the payload
struct HNode {
    HNode* next = NULL;
    uint64_t hcode = 0;
};

// a simple fixed-sized hashtable
struct HTab {
    HNode** tab = NULL;
    size_t mask = 0;
    size_t size = 0;
};

// the real hashtable interface.
// it uses 2 hashtables fro progressive resizing.
struct HMap {
    HTab ht1;
    HTab ht2;
    size_t resizing_pos = 0;
};

HNode* hm_lookup(HMap* hmap, HNode* key, bool(*eq)(HNode*, HNode*));
void hm_insert(HMap* hmap, HNode* node);
HNode* hm_pop(HMap* hmap, HNode* key, bool (*eq)(HNode*, HNode*));
size_t hm_size(HMap* hmap);
void hm_destroy(HMap* hmap);


#endif //HASHTABLE_H
