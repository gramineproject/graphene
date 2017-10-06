/*
 *  util.h
 *
 *  Copyright (C) 2017-, Chia-Che Tsai, Bhushan Jain and Donald Porter
 *
 */

#include <linux/module.h>
#include <linux/version.h>

int norm_path (const char * path, char * buf, int size);

static inline void
init_filename(struct filename *name)
{
	name->uptr   = NULL;
	name->aname  = NULL;
	name->refcnt = 1;
}
