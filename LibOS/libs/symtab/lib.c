#include <includes.h>
#include <symtab/symtab.h>

/* Address of application .text section */
void *text_section = 0UL;

/* DkStreamMap and friends require the addr, offset, and len to be
 * aligned. If the area we wish to map in a file is not exactly on
 * page boundaries, we must map a region larger than what we intend.
 * The offset helps us keep track of where within this page our data
 * actually lies: data = .addr + .offset
 */
struct dkmap {
    void *addr;
    size_t len;
    size_t offset;
};

struct symtab_cache {
    bool exists;
    struct dkmap ehdr;
    struct dkmap strtab;
    struct dkmap symtab;
    size_t sym_n;
};

static struct symtab_cache symbol_info = {.exists = false};

void symtab_unmap(void) {
    if (symbol_info.exists) {
        if (symbol_info.symtab.addr)
            DkStreamUnmap((PAL_PTR)symbol_info.symtab.addr, symbol_info.symtab.len);
        if (symbol_info.strtab.addr)
            DkStreamUnmap((PAL_PTR)symbol_info.strtab.addr, symbol_info.strtab.len);
        if (symbol_info.ehdr.addr)
            DkStreamUnmap((PAL_PTR)symbol_info.ehdr.addr, symbol_info.ehdr.len);
        memset(&symbol_info, 0, sizeof(symbol_info));
        symbol_info.exists = false;
    }
}

static inline bool
is_file(const PAL_HANDLE h) {
    return HANDLE_HDR(h)->type == pal_type_file;
}

static bool symtab_init(void) {
    const PAL_FLG prot = PAL_PROT_READ;

    PAL_HANDLE handle = NULL;

    const ElfW(Shdr) *sh = NULL;
    const ElfW(Ehdr) *ehdr = NULL;

    struct dkmap shdr_map = { 0 };
    const ElfW(Shdr) *shdr_tbl = NULL;

    struct dkmap shstr_map = { 0 };
    const char *shstr_sec = NULL;

    /* Open the executable */

    const char *uri = pal_control.executable;
    if (!(handle = DkStreamOpen(uri, PAL_ACCESS_RDONLY, 0, 0, 0)))
        return false;
    if (!is_file(handle))
        goto fail;

    /* Map in ELF and section headers */

    size_t len, offset;
    void *map;

    offset = 0;
    len = alignup(sizeof(ElfW(Ehdr)));
    if (!(map = DkStreamMap(handle, NULL, prot, aligndown(offset), len)))
        goto fail;

    symbol_info.ehdr.addr = map;
    symbol_info.ehdr.len = len;
    symbol_info.ehdr.offset = offset - aligndown(offset);

    ehdr = symbol_info.ehdr.addr + symbol_info.ehdr.offset;

    offset = ehdr->e_shoff;
    len = alignup((size_t)ehdr->e_shentsize * (size_t)ehdr->e_shnum);
    if (!(map = DkStreamMap(handle, NULL, prot, aligndown(offset), len)))
        goto fail;

    shdr_map.addr = map;
    shdr_map.len = len;
    shdr_map.offset = offset - aligndown(offset);

    shdr_tbl = shdr_map.addr + shdr_map.offset;

    /* Map in the section header string table */

    const size_t shstrndx = ehdr->e_shstrndx;
    const ElfW(Shdr) *shstr_shdr = &shdr_tbl[shstrndx];

    offset = shstr_shdr->sh_offset;
    len = alignup(shstr_shdr->sh_size);

    if (!(map = DkStreamMap(handle, NULL, prot, aligndown(offset), len)))
        goto fail;

    shstr_map.addr = map;
    shstr_map.len = len;
    shstr_map.offset = offset - aligndown(offset);

    shstr_sec = shstr_map.addr + shstr_map.offset;

    /* Map in the symbol table and associated symbol string table */

    const ElfW(Shdr)* symtab_shdr = NULL, *strtab_shdr = NULL;
    const size_t nshdr = ehdr->e_shnum;
    for (sh = shdr_tbl; sh < &shdr_tbl[nshdr]; sh++) {
        if (sh->sh_type == SHT_SYMTAB) {
            if (!symtab_shdr)
                symtab_shdr = sh;
        } else if (sh->sh_type == SHT_STRTAB && (sh - shdr_tbl) != shstrndx) {
            if (!strtab_shdr)
                strtab_shdr = sh;
        } else if (sh->sh_type == SHT_PROGBITS) {
            if (!text_section)
                if (sh->sh_name > 0 && 0 == strcmp(".text", &shstr_sec[sh->sh_name]))
                    text_section = (void*)sh->sh_addr;
        }
    }
    if (!symtab_shdr || !strtab_shdr)
        goto fail;

    offset = symtab_shdr->sh_offset;
    len = alignup(symtab_shdr->sh_size);
    if (!(map = DkStreamMap(handle, NULL, prot, aligndown(offset), len)))
        goto fail;

    symbol_info.symtab.addr = map;
    symbol_info.symtab.len = len;
    symbol_info.symtab.offset = offset - aligndown(offset);
    symbol_info.sym_n = symtab_shdr->sh_size / symtab_shdr->sh_entsize;

    offset = strtab_shdr->sh_offset;
    len = alignup(strtab_shdr->sh_size);
    if (!(map = DkStreamMap(handle, NULL, prot, aligndown(offset), len)))
        goto fail;

    symbol_info.strtab.addr = map;
    symbol_info.strtab.len = len;
    symbol_info.strtab.offset = offset - aligndown(offset);

    symbol_info.exists = true;
    goto done;

fail:
    symtab_unmap();
    symbol_info.exists = false;
    /* fall through */

done:
    if (shstr_map.addr)
        DkStreamUnmap((PAL_PTR)shstr_map.addr, shstr_map.len);
    if (shdr_map.addr)
        DkStreamUnmap((PAL_PTR)shdr_map.addr, shdr_map.len);
    DkObjectClose(handle);
    return symbol_info.exists;
}

static bool __symtab_lookup_symbol(const char* name, struct syminfo* info) {
    const ElfW(Sym) *sym, *tbl = symbol_info.symtab.addr + symbol_info.symtab.offset;
    const char *symstr = NULL, *strtab = symbol_info.strtab.addr + symbol_info.strtab.offset;
    for (sym = tbl; sym < &tbl[symbol_info.sym_n]; sym++, symstr = NULL) {
        if (sym->st_name > 0)
            symstr = &strtab[sym->st_name];
        if (symstr && 0 == strcmp(name, symstr)) {
            info->name = symstr;
            info->addr = (void*)sym->st_value;
            info->len  = sym->st_size;
            return true;
        }
    }
    return false;
}

bool symtab_lookup_symbol(const char* name, struct syminfo* info) {
    return name && info && symbol_info.exists && __symtab_lookup_symbol(name, info);
}

void __fini(void) {
    symtab_unmap();
}

void __init(void) {
    if (!symtab_init())
        pal_printf("libsymtab: error initializing\n");
}
