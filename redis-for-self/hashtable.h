//
// Created by wendell on 2024/9/14.
//

#ifndef HASHTABLE_H
#define HASHTABLE_H
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

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

// n must be a pow of 2
static void h_init(HTab* htab, size_t n) {
    assert(n > 0 && (n-1) & n == 0);
    htab->tab = (HNode**)calloc(sizeof(HNode*), n);
    htab->mask = n - 1;
    htab->size = 0;
}

// hashtable insertion
static void h_insert(HTab* htab, HNode* node) {
    size_t pos = node->hcode & htab->mask;
    HNode* next = htab->tab[pos];
    node->next = next;
    htab->tab[pos] = node;
    htab->size++;
}

// hashtable look up subroutine.
// Pay attention to the return val. It returns the address of
// the parent pointer that owns the target ndoe,
// witch can be used to delete the target ndoe.
static HNode** h_lookup(HTab* htab, HNode*key, bool (*cmp)(HNode*, HNode*)) {
    if (!htab->tab) {
        return NULL;
    }
    size_t pos = key->hcode & htab->mask;
    HNode** from = &htab->tab[pos];
    while(*from) {
        if (cmp(*from, key)) {
            return from;
        }
        from = &((*from)->next);
    }
    return NULL;
}

// remove a node from the chain
static HNode* h_detach(HTab* htab, HNode** from) {
    HNode *node = *from;
    *from = (*from)->next;
    htab->size--;
    return node;
}



#endif //HASHTABLE_H
