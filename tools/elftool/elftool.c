#include <stdio.h>
#include <stdlib.h>
#include <bfd.h>
#include <strings.h>
#include <linux/elf.h>

#define nonfatal(s) {perror(s); return -1;}
#define fatal(s) {perror(s); exit(-1);}
#define bfd_nonfatal(s) {bfd_perror(s); return -1;}
#define bfd_fatal(s) {bfd_perror(s); exit(-1);}

#define EI_NIDENT   16      /* Size of e_ident[] */

typedef struct elf_internal_ehdr {
  unsigned char     e_ident[EI_NIDENT]; /* ELF "magic number" */
  bfd_vma       e_entry;    /* Entry point virtual address */
  bfd_size_type     e_phoff;    /* Program header table file offset */
  bfd_size_type     e_shoff;    /* Section header table file offset */
  unsigned long     e_version;  /* Identifies object file version */
  unsigned long     e_flags;    /* Processor-specific flags */
  unsigned short    e_type;     /* Identifies object file type */
  unsigned short    e_machine;  /* Specifies required architecture */
  unsigned int      e_ehsize;   /* ELF header size in bytes */
  unsigned int      e_phentsize;    /* Program header table entry size */
  unsigned int      e_phnum;    /* Program header table entry count */
  unsigned int      e_shentsize;    /* Section header table entry size */
  unsigned int      e_shnum;    /* Section header table entry count */
  unsigned int      e_shstrndx; /* Section header string table index */
} Elf_Internal_Ehdr;


struct elf_internal_phdr {
  unsigned long p_type;         /* Identifies program segment type */
  unsigned long p_flags;        /* Segment flags */
  bfd_vma   p_offset;       /* Segment file offset */
  bfd_vma   p_vaddr;        /* Segment virtual address */
  bfd_vma   p_paddr;        /* Segment physical address */
  bfd_vma   p_filesz;       /* Segment size in file */
  bfd_vma   p_memsz;        /* Segment size in memory */
  bfd_vma   p_align;        /* Segment alignment, file & memory */
};

typedef struct elf_internal_phdr Elf_Internal_Phdr;

/* Section header */

typedef struct elf_internal_shdr {
  unsigned int  sh_name;        /* Section name, index in string tbl */
  unsigned int  sh_type;        /* Type of section */
  bfd_vma   sh_flags;       /* Miscellaneous section attributes */
  bfd_vma   sh_addr;        /* Section virtual addr at execution */
  file_ptr  sh_offset;      /* Section file offset */
  bfd_size_type sh_size;        /* Size of section in bytes */
  unsigned int  sh_link;        /* Index of another section */
  unsigned int  sh_info;        /* Additional section information */
  bfd_vma   sh_addralign;       /* Section alignment */
  bfd_size_type sh_entsize;     /* Entry size if section holds table */

  /* The internal rep also has some cached info associated with it. */
  asection *    bfd_section;        /* Associated BFD section.  */
  unsigned char *contents;      /* Section contents.  */
} Elf_Internal_Shdr;

struct elf_obj_tdata
{
  Elf_Internal_Ehdr elf_header[1];  /* Actual data, but ref like ptr */
  Elf_Internal_Shdr **elf_sect_ptr;
  Elf_Internal_Phdr *phdr;
  Elf_Internal_Shdr symtab_hdr;
  Elf_Internal_Shdr shstrtab_hdr;
  Elf_Internal_Shdr strtab_hdr;
  Elf_Internal_Shdr dynsymtab_hdr;
  Elf_Internal_Shdr dynstrtab_hdr;
  Elf_Internal_Shdr dynversym_hdr;
  Elf_Internal_Shdr dynverref_hdr;
  Elf_Internal_Shdr dynverdef_hdr;
 };

#define elf_tdata(bfd)      ((bfd)->tdata.elf_obj_data)
#define elf_elfheader(bfd)	(elf_tdata(bfd)->elf_header)

struct ksym {
    long addr;
    char *name;
};

struct elf_manager {
    long counts;
    long index;
    struct ksym *psym;
};

static int elf_init = 1;

static long get_load_off(bfd *ibfd) {
    struct elf_obj_tdata* tdata;
    struct elf_internal_phdr* p;

    printf("%p\n", tdata->phdr);

    tdata = elf_tdata(ibfd);
    p = tdata->phdr;
    if (p != NULL) {
        unsigned int i, c;
        c = elf_elfheader(ibfd)->e_phnum;
        for (i = 0; i < c; i++, p++) {
            if ((p->p_type == PT_LOAD)&&(p->p_flags & PF_X)) {
                return p->p_vaddr;
            }
        }
    }
    return -1;
}

static int sym_cmp(const void *p1, const void *p2)
{
    return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

static int walk_symbol(asymbol **symbol_table,
                       long number_of_symbols,
                       struct elf_manager *p_mana) {
    long i;
    int ret = 0;
    long index = p_mana->index;
    symbol_info symbolinfo;

    for (i = 0; i < number_of_symbols; i++) {
        struct ksym *psym = &(p_mana->psym[index]);

        if (symbol_table[i]->section == NULL)
            continue;

        if (strncmp(".text", symbol_table[i]->section->name) == 0) {
            bfd_symbol_info(symbol_table[i], &symbolinfo);
//            printf("Symbol \"%s\", type:%c  value 0x%x\n", symbolinfo.name, symbolinfo.type, symbolinfo.value);
            psym->name = strdup(symbolinfo.name);
            psym->addr = symbolinfo.value;
            index ++;
        }
    }
    p_mana->index = index;
    return ret;
}

static int dump_local_symbol(bfd *ibfd, struct elf_manager *p_mana) {
    int ret = 0;
    long storage_needed;
    asymbol **symbol_table;
    long number_of_symbols;

    storage_needed = bfd_get_symtab_upper_bound(ibfd);
    if (storage_needed < 0)
        bfd_nonfatal("bfd_get_symtab_upper_bound");

    if (storage_needed > 0) {
        symbol_table = (asymbol **)(long)malloc(storage_needed);
        if (symbol_table == NULL) {
            fprintf(stderr, "malloc for local_symbol failed.\n");
            return -12;
        }

        number_of_symbols = bfd_canonicalize_symtab(ibfd, symbol_table);
        if (number_of_symbols < 0) {
            fprintf(stderr, "bfd_canonicalize_symtab failed.\n");
            free(symbol_table);
            return -1;
        }

        ret = walk_symbol(symbol_table, number_of_symbols, p_mana);
        if (ret < 0) {
            ret = -1;
        }
        free(symbol_table);
    }
    return ret;
}

static int dump_dynamic_symbol(bfd *ibfd, struct elf_manager *p_mana) {
    int ret = 0;
    long storage_needed;
    asymbol **symbol_table;
    long number_of_symbols;

    storage_needed = bfd_get_dynamic_symtab_upper_bound(ibfd);
    if (storage_needed < 0)
        bfd_nonfatal("bfd_get_dynamic_symtab_upper_bound");

    if (storage_needed > 0) {
        symbol_table = (asymbol **)(long)malloc(storage_needed);
        if (symbol_table == NULL) {
            fprintf(stderr, "malloc for local_symbol failed.\n");
            return -12;
        }

        number_of_symbols = bfd_canonicalize_dynamic_symtab(ibfd, symbol_table);
        if (number_of_symbols < 0) {
            fprintf(stderr, "bfd_canonicalize_dynamic_symtab failed.\n");
            free(symbol_table);
            return -1;
        }

        ret = walk_symbol(symbol_table, number_of_symbols, p_mana);
        if (ret < 0) {
            ret = -1;
        }
        free(symbol_table);
    }
    return ret;
}

static long symbol_count(bfd *ibfd) {
    return bfd_get_symtab_upper_bound(ibfd) + bfd_get_dynamic_symtab_upper_bound(ibfd);
}

struct ksym *sym_search(struct elf_manager *p_mana, long key) {
    long start = 0, end = p_mana->index;
    long result;
    struct ksym *syms = p_mana->psym;

    while (start < end) {
        int mid = start + (end - start) / 2;

        result = key - syms[mid].addr;
        if (result < 0)
            end = mid;
        else if (result > 0)
            start = mid + 1;
        else
            return &syms[mid];
    }

    if (start >= 1 && syms[start - 1].addr < key && key < syms[start].addr)
        /* valid ksym */
        return &syms[start - 1];

    /* out of range. return _stext */
    return &syms[0];
}

void de_symbol(struct elf_manager *p_mana) {
    int i;

    for (i = 0; i < p_mana->index; i ++) {
        free(p_mana->psym[i].name);
    }
    free(p_mana->psym);
    free(p_mana);
}

static void show(struct elf_manager *p_mana) {
    int i;
    struct ksym* rsym;

    for (i = 0; i < 10; i ++) {
        rsym = p_mana->psym;

        printf("%s, %lx\n", rsym[i].name, rsym[i].addr);
    }
}

int main(int argc, char *argv[])
{
    bfd *ibfd;
    char *filename;
    char **matching;
    struct elf_manager *p_mana;
    char *end;
    long addr;
    struct ksym* rsym;

    if (argc<3) exit(-1);
    filename = argv[1];
    addr = strtol(argv[2], &end, 16);

    if (elf_init) {
        bfd_init();
        elf_init = 0;
    }

    p_mana = (struct elf_manager *)malloc(sizeof(struct elf_manager));
    if (p_mana == NULL) {
        return -1;
    }

    ibfd = bfd_openr(filename, NULL);
    if (ibfd == NULL) {
        bfd_nonfatal("openr");
    }

    printf("name: %s\n", ibfd->xvec->name);
    if (bfd_check_format_matches(ibfd, bfd_object, &matching)) {

        p_mana->counts = symbol_count(ibfd);
        p_mana->index = 0;
        p_mana->psym = (struct ksym*)malloc(sizeof(struct ksym) * p_mana->counts);
        if (p_mana->psym == NULL) {
            goto end_syms;
        }

        dump_local_symbol(ibfd, p_mana);
        dump_dynamic_symbol(ibfd, p_mana);
    } else {
        bfd_fatal("format_matches");
        goto end_syms;
    }

    printf("offset: 0x%lx\n", get_load_off(ibfd));

    qsort(p_mana->psym, p_mana->index, sizeof(struct ksym), sym_cmp);
    bfd_close(ibfd);

//    show(p_mana);

    rsym = sym_search(p_mana, addr);
    printf("symbol: %s, offset: %ld\n", rsym->name, addr - rsym->addr);
    de_symbol(p_mana);
    return 0;

end_syms:
    free(p_mana);
    bfd_close(ibfd);
    return -1;
}
