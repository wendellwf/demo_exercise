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

// n must be a pow of 2
static void h_init(HTab* htab, size_t n) {
    assert(n > 0 && ((n-1) & n) == 0);
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

// the real hashtable interface.
// it uses 2 hashtables fro progressive resizing.
struct HMap {
    HTab ht1;
    HTab ht2;
    size_t resizing_pos = 0;
};


const size_t k_resizing_work = 128;
static void hm_help_resizing(HMap* hmap) {
    if (hmap->ht2.tab == NULL) {
        return;
    }
    size_t nwork = 0;
    while(nwork < k_resizing_work && hmap->ht2.size > 0) {
        HNode** from = &hmap->ht2.tab[hmap->resizing_pos];
        if (!*from) {
            hmap->resizing_pos++;
            continue;
        }
        h_insert(&hmap->ht1, h_detach(&hmap->ht2, from));
        nwork++;
    }

    if (hmap->ht2.size == 0) {
        // done
        free(hmap->ht2.tab);
        hmap->ht2 = HTab{};
    }
}

HNode* hm_lookup(HMap* hmap, HNode* key, bool (*cmp)(HNode*, HNode*)) {
    hm_help_resizing(hmap);
    HNode** from = h_lookup(&hmap->ht1, key, cmp);
    if (!from) {
        from = h_lookup(&hmap->ht2, key, cmp);
    }
    return from ? *from : NULL;
}

static void hm_start_resizing(HMap* hmap) {
    assert(hmap->ht2.tab == NULL);
    h_init(&hmap->ht1, (hmap->ht1.mask + 1) * 2);
    hmap->resizing_pos = 0;
}

const size_t k_max_load_factor = 8;
void hm_insert(HMap* hmap, HNode* node) {
    if (!hmap->ht1.tab) {
        h_init(&hmap->ht1, 4);
    }
    h_insert(&hmap->ht1, node);
    if (!hmap->ht2.tab) {
        // check whether we need to resize
        size_t load_factor = hmap->ht1.size / (hmap->ht1.mask + 1);
        if (load_factor >= k_max_load_factor) {
            hm_start_resizing(hmap);
        }
    }
    hm_help_resizing(hmap);
}

HNode* hm_pop(HMap* hmap, HNode* key, bool (*cmp)(HNode*, HNode*)) {
    hm_help_resizing(hmap);
    HNode** from = h_lookup(&hmap->ht1, key, cmp);
    if (from) {
        return h_detach(&hmap->ht1, from);
    }
    from = h_lookup(&hmap->ht2, key, cmp);
    if (from) {
        return h_detach(&hmap->ht2, from);
    }
    return NULL;
}

size_t hm_size(HMap* hmap) {
    return hmap->ht1.size + hmap->ht2.size;
}

void hm_destory(HMap* hmap) {
    free(hmap->ht1.tab);
    free(hmap->ht2.tab);
    *hmap = HMap{};
}


#endif //HASHTABLE_H
