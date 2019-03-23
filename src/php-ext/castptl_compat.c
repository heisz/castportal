/*
 * Compatibility methods to interface the toolkit library to the Zend core.
 *
 * Copyright (C) 2016-2019 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "php_castptl.h"
#include "mem.h"

/* The standard memory wrappers need to utilize the PHP functions instead */

void *_WXMalloc(size_t size, int line, char *file) {
    return emalloc(size);
}

void *_WXCalloc(size_t size, int line, char *file) {
    return ecalloc(1, size);
}

void *_WXRealloc(void *original, size_t size, int line, char *file) {
    return erealloc(original, size);
}

void _WXFree(void *original, int line, char *file) {
    efree(original);
}
