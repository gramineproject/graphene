
#ifndef SHIM_FS_PSEUDO_H_
#define SHIM_FS_PSEUDO_H_

#include "list.h"
#include "shim_fs.h"

enum pseudo_type {
    PSEUDO_DIR = 1,
    PSEUDO_LINK = 2,
    PSEUDO_STR = 3,
};

DEFINE_LIST(pseudo2_ent);
DEFINE_LISTP(pseudo2_ent);
struct pseudo2_ent {
    struct pseudo2_ent* parent;

    const char* name;
    enum pseudo_type type;

    LIST_TYPE(pseudo2_ent) siblings;

    struct {
        LISTP_TYPE(pseudo2_ent) children;
    } dir;

    struct {
        int (*follow_link)(struct shim_dentry* dent, struct shim_qstr* link);
    } link;

    struct {
        int (*get_content)(struct shim_dentry* dent, char** str, size_t* len);
    } str;
};

struct pseudo2_ent* pseudo_add_root_dir(const char* name);

struct pseudo2_ent* pseudo_add_dir(struct pseudo2_ent* parent_ent, const char* name);

struct pseudo2_ent* pseudo_add_link(struct pseudo2_ent* parent_ent, const char* name,
                                    int (*follow_link)(struct shim_dentry*, struct shim_qstr*));

struct pseudo2_ent* pseudo_add_str(struct pseudo2_ent* parent_ent, const char* name,
                                   int (*get_content)(struct shim_dentry*, char**, size_t*));

extern struct shim_fs pseudo_builtin_fs;

int init_procfs(void);

#endif /* SHIM_FS_PSEUDO_H_ */
