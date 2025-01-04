#ifndef HASHTABLE_DEFINITION // single file library cannot use pragma once
#define HASHTABLE_DEFINITION // https://en.wikipedia.org/wiki/Header-only
                             // https://github.com/nothings/single_file_libs
/*
 License: "Unlicense" (public domain) see bottom of the file for details.
 This is brain dead 4 hours implementation of #153 of absolutely non-universal,
 simple, growing, lineral rehash, key and value retaining hashtable with open
 read/write access to table entries.
 What it is NOT:
    It is not performance champion by any means.
    It does not use cyptograhically strong hash function.
    It is not designed for usage convience.
 Goals:
    As simple as possible.
    As reliable as possible.
 Limitations:
    key, val cannot exceed 2GB-1 bytes in size (can use int64_t instead of int32_t to make it bigger).
    Number of entries in a table cannot exceed (2GB - sizeof(hashtable_t)) / sizeof(hashtable_entry_t).
    Even replacing int32_t by int64_t does NOT make array of entries index 64 bit on the platforms
    where "int" is 32-bit (most of 64 bits platforms at the time of coding).
    It will be capable of indexing 2G entries (with some luck in indexof) but not 2^63 entries
    unless some additional indexing effort is added.
 Usage example:
    #define HASHTABLE_IMPLEMENTATION
    #include "hashtable.h"
    hashtable_t* ht = hashtable_create(16);
    if (ht == null) {
        perror("hashtable_create() failed"); // error is in "errno"
    } else {
        hashtable_kv_t key = {};
        hashtable_kv_t val = {};
        key.data = "Hello World!";
        key.bytes = (int32_t)strlen((char*)key.data);
        val.data = "Good bye cruel Universe...";
        val.bytes = (int32_t)strlen((char*)val.data);
        int r = hashtable_put(ht, &key, &val);
        // Adding key value pair to hashtable makes ht owned copy of kv data.
        // Adding can grow hashtable and pointers to entries will migrate to new
        // addressed. Called must NOT hold pointers to entry over "hashtable_add" call.
        if (r != 0) {
            perror("hashtable_put() failed"); // error is in "r" and also in errno
        } else {
            hashtable_entry_t* e = hashtable_get(ht, key.data, key.bytes);
            assert(e != null);
            assert(e->key.bytes == key.bytes && memcmp(e->key.data, key.data, key.bytes) == 0);
            assert(e->val.bytes == val.bytes && memcmp(e->val.data, val.data, val.bytes) == 0);
            // The content of e->val can be read and written at this point.
            // It will be very bad idea to touch e->key or e->hash here. Treat "key" as being read-only.
            // Caller should not hold the pointer to the entry over hashtable_add/remove/dispose calls.
            // See note above and below.
            hashtable_remove(ht, key.data, key.bytes);
            // Removal frees the hashtable owned copy of key value pair data.
            e = hashtable_get(ht, key.data, key.bytes);
            assert(e == null);
            hashtable_dispose(ht); // Frees all the memory used by hashtable.
        }
    }
  Inspiration: (nostalgic, obsolete, esoteric and buggy... but still in use)
    https://www.gnu.org/software/libc/manual/html_node/Hash-Search-Function.html
    https://github.com/ARM-software/u-boot/blob/master/lib/hashtable.c
    with the comment in the source code:
      [Aho, Sethi, Ullman] Compilers: Principles, Techniques and Tools, ***1986***
      [Knuth]              The Art of Computer Programming, part 3 (6.4)
  Questions and comments: Leo.Kuznetsov@gmail.com
*/

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hashtable_kv_s {
    void* data;
    int32_t bytes;
} hashtable_kv_t;

typedef struct hashtable_entry_s {
    hashtable_kv_t key;
    hashtable_kv_t val;
    uint32_t hash;
} hashtable_entry_t;

typedef struct hashtable_t {
    int32_t capacity;
    int32_t n;
    hashtable_entry_t* entries; // array[capacity]
} hashtable_t;

enum {
    HASHTABLE_INT32_MAX = (int32_t)-1U/2 == (int32_t)(-1U/2) ? (int32_t)-1U : (int32_t)(-1U/2), // INT_MAX
    HASHTABLE_MAX_CAPACITY = (HASHTABLE_INT32_MAX - sizeof(hashtable_t)) / sizeof(hashtable_entry_t)
};

hashtable_t* hashtable_create(int capacity); // capacity [16..HASHTABLE_MAX_CAPACITY]
hashtable_entry_t* hashtable_get(hashtable_t* ht, const void* key, int32_t bytes);
int  hashtable_put(hashtable_t* ht, const hashtable_kv_t* key, const hashtable_kv_t* val);
void hashtable_remove(hashtable_t* ht, const void* key, int32_t bytes);
void hashtable_dispose(hashtable_t* ht);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // HASHTABLE_DEFINITION

#ifdef HASHTABLE_IMPLEMENTATION

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define byte uint8_t
#define null ((void*)0)
#define memequ(a, b, n) (memcmp((a), (b), (n)) == 0)
#define hashtable_mem_alloc malloc
#define hashtable_mem_free free

static const byte HASHTABLE_REMOVED_KEY; // unique address designating removed key for linear rehash

static inline void hashtable_mem_free_not_removed(void* data) {
    // since &HASHTABLE_REMOVED_KEY is unique no harm comparing any other address with it
    if (data != &HASHTABLE_REMOVED_KEY) { hashtable_mem_free(data); }
}

static inline void hashtable_kv_free(hashtable_kv_t* kv) {
    if (kv != null) { // unnecessary := null and := 0 assignments will be removed by optimizations
        hashtable_mem_free_not_removed(kv->data); kv->data = null; kv->bytes = 0;
    }
}

static uint32_t hashtable_hash(const byte* key, int bytes);
static int hashtable_kv_dup(hashtable_kv_t* d, const hashtable_kv_t* s);
static int hashtable_grow(hashtable_t* ht);
static int hashtable_indexof(hashtable_t* ht, const hashtable_entry_t* e) { return (int)(e - ht->entries); }

hashtable_t* hashtable_create(int capacity) { // capacity [16..HASHTABLE_MAX_CAPACITY]
    int r = 0;
    hashtable_t* ht = null;
    assert(16 <= capacity && capacity < HASHTABLE_MAX_CAPACITY);
    if (16 <= capacity && capacity < HASHTABLE_MAX_CAPACITY) {
        ht = (hashtable_t*)hashtable_mem_alloc(sizeof(hashtable_t));
        if (ht == null) {
            r = errno;
        } else {
            memset(ht, 0, sizeof(hashtable_t));
            int32_t bytes = capacity * sizeof(hashtable_entry_t);
            ht->entries = (hashtable_entry_t*)hashtable_mem_alloc(bytes);
            if (ht->entries == null) {
                r = errno; // save to protect against hashtable_mem_free() setting "errno"
                hashtable_mem_free(ht);
                ht = null;
            } else {
                ht->capacity = capacity;
                memset(ht->entries, 0, bytes);
            }
        }
    } else {
        r = EINVAL;
    }
    if (r != 0) { errno = r; }
    return ht;
}

void hashtable_free_entries(hashtable_t* ht) {
    for (int i = 0; i < ht->capacity; i++) {
        hashtable_kv_free(&ht->entries[i].key);
        hashtable_kv_free(&ht->entries[i].val);
    }
}

void hashtable_dispose(hashtable_t* ht) {
    hashtable_free_entries(ht);
    hashtable_mem_free(ht->entries);
    hashtable_mem_free(ht);
}

static hashtable_entry_t* hashtable_find(hashtable_t* ht, uint32_t hash, const void* key, int32_t bytes) {
    // Last time I've checked idiv r32:r32 was pretty expensive on most ARM, Intel and AMD
    // processors, thus loop below uses increment and compare instead of extra "%" operation.
    // http://uops.info/table.html
    int ix = (int)(hash % ht->capacity); // arrays are indexed by "int" in C
    const int a = ix; // `again` full circle index value after visiting all entries
    do {
        hashtable_entry_t* e = &ht->entries[ix];
        if (e->key.data == null) { break; }
        if (hash == e->hash && e->key.bytes == bytes && memequ(e->key.data, key, bytes)) { return e; }
        ix++;
        if (ix == ht->capacity) { ix = 0; }
    } while (ix != a);
    return null;
}

hashtable_entry_t* hashtable_get(hashtable_t* ht, const void* key, int32_t bytes) {
    return hashtable_find(ht, hashtable_hash(key, bytes), key, bytes);
}

int hashtable_put(hashtable_t* ht, const hashtable_kv_t* key, const hashtable_kv_t* val) {
    int r = 0;
    assert(key->data != null && 1 <= key->bytes && key->bytes < HASHTABLE_INT32_MAX);
    if (key->data != null && 1 <= key->bytes && key->bytes < HASHTABLE_INT32_MAX) {
        uint32_t hash = hashtable_hash(key->data, key->bytes);
        hashtable_entry_t* e = hashtable_find(ht, hash, key->data, key->bytes);
        if (e != null) {
            r = hashtable_kv_dup(&e->val, val);
        } else {
            int ix = (int)(hash % ht->capacity);
            const int a = ix;
            while (r == 0) {
                e = &ht->entries[ix];
                bool removed = e->key.data == &HASHTABLE_REMOVED_KEY;
                if (e->key.data == null || removed) {
                    r = hashtable_kv_dup(&e->key, key);
                    if (r == 0) {
                        r = hashtable_kv_dup(&e->val, val);
                        if (r != 0) { // restore key to retained value
                            hashtable_kv_free(&e->val);
                            e->key.data = removed ? (void*)&HASHTABLE_REMOVED_KEY : null;
                        }
                    }
                    if (r == 0) {
                        e->hash = hash;
                        ht->n++;
                        if (ht->n > ht->capacity * 3 / 4) { r = hashtable_grow(ht); }
                    }
                    break;
                }
                ix++;
                if (ix == ht->capacity) { ix = 0; }
                // the only way for ix == a is the table previous failure to grow was ignored
                if (ix == a) { r = ENOMEM; break; } // hit initial value of 'h' again...
            }
        }
    } else {
        r = EINVAL;
    }
    return r;
}

void hashtable_remove(hashtable_t* ht, const void* key, int32_t bytes) {
    hashtable_entry_t* e = hashtable_get(ht, key, bytes);
    if (e != null) {
        assert(e->key.data != (void*)&HASHTABLE_REMOVED_KEY);
        hashtable_kv_free(&e->key);
        hashtable_kv_free(&e->val);
        int next = hashtable_indexof(ht, e) + 1;
        if (next == ht->capacity) { next = 0; }
        e->key.data = ht->entries[next].key.data == null ? null : (void*)&HASHTABLE_REMOVED_KEY;
        ht->n--;
    }
}

static int hashtable_grow(hashtable_t* ht) {
    int r = 0;
    if (ht->capacity < HASHTABLE_MAX_CAPACITY * 2 / 3) {
        int capacity = ht->capacity * 3 / 2;
        int32_t bytes = capacity * sizeof(hashtable_entry_t);
        hashtable_entry_t* entries = (hashtable_entry_t*)hashtable_mem_alloc(bytes);
        if (entries == null) {
            r = errno;
        } else {
            memset(entries, 0, bytes);
            for (int i = 0; i < ht->capacity; i++) {
                hashtable_entry_t* e = &ht->entries[i];
                if (e->key.data != null && e->key.data != &HASHTABLE_REMOVED_KEY) {
                    int ix = (int)(e->hash % capacity);
                    for (;;) {
                        if (entries[ix].key.data == null) { entries[ix] = *e; break; }
                        ix++;
                        if (ix == capacity) { ix = 0; }
                    }
                }
            }
            hashtable_mem_free(ht->entries);
            ht->entries = entries;
            ht->capacity = capacity;
        }
    } else {
        r = E2BIG;
    }
    if (r != 0) { errno = r; }
    return r;
}

static int hashtable_kv_dup(hashtable_kv_t* d, const hashtable_kv_t* s) {
    int r = 0; // similar to strdup() but for a (data,bytes) pair
    if (d->bytes == s->bytes) {
        memcpy(d->data, s->data, s->bytes);
    } else {
        void* dup = hashtable_mem_alloc(s->bytes);
        if (dup == null) {
            r = errno;
        } else {
            hashtable_mem_free_not_removed(d->data);
            d->data = dup;
            d->bytes = s->bytes;
            memcpy(d->data, s->data, s->bytes);
        }
    }
    return r;
}

static uint32_t hashtable_hash(const byte* data, int bytes) { // http://www.azillionmonkeys.com/qed/hash.html
    #define get16bits(a) (*((const uint16_t*)(a)))
    uint32_t hash = bytes;
    uint32_t tmp;
    if (bytes <= 0 || data == null) { return 0; }
    int32_t reminder = bytes & 3;
    bytes >>= 2;
    while (bytes > 0) {
        hash  +=  get16bits(data);
        tmp    = (get16bits(data + 2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2 * sizeof(uint16_t);
        hash  += hash >> 11;
        bytes--;
    }
    switch (reminder) { /* Handle end cases */
        case 3: hash += get16bits(data);
            hash ^= hash << 16;
            hash ^= ((int8_t)data[sizeof(uint16_t)]) << 18;
            hash += hash >> 11;
            break;
        case 2: hash += get16bits(data);
            hash ^= hash << 11;
            hash += hash >> 17;
            break;
        case 1: hash += (int8_t)data[0];
            hash ^= hash << 10;
            hash += hash >> 1;
            break;
        case 0: break;
    }
    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;
    return hash;
}

/*
This is free and unencumbered software released into the public domain.
Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.
In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
For more information, please refer to <http://unlicense.org/>
*/
#endif