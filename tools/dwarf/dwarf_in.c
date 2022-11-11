#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "dwarf.h"
#include "libdwarf.h"
#include "libdwarf_private.h"


struct srcfilesdata {
    char ** srcfiles;
    Dwarf_Signed srcfilescount;
    int srcfilesres;
};

static void read_cu_list(Dwarf_Debug dbg);
static void print_die_data(Dwarf_Debug dbg, Dwarf_Die print_me,
                           int level, struct srcfilesdata *sf);
static void get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die,
                                 int is_info, int in_level, struct srcfilesdata *sf);
static void reset_src_files(Dwarf_Debug dbg, struct srcfilesdata *sf);

static int cu_version_stamp = 0;
static int cu_offset_size = 0;

static unsigned char_to_uns4bit(unsigned char c) {
    unsigned v;
    if ( c >= '0' && c <= '9') {
        v =  c - '0';
    }
    else if ( c >= 'a' && c <= 'f') {
        v =  c - 'a' + 10;
    }
    else if ( c >= 'A' && c <= 'F') {
        v =  c - 'A' + 10;
    } else {
        printf("Garbage hex char in %c 0x%x\n", c, c);
        exit(EXIT_FAILURE);
    }
    return v;
}

static void xfrm_to_sig8(const char *cuhash_in, Dwarf_Sig8 *hash_out) {
    char localhash[16];
    unsigned hashin_len = strlen(cuhash_in);
    unsigned fixed_size = sizeof(localhash);
    unsigned init_byte = 0;
    unsigned i;

    memset(localhash, 0, fixed_size);
    if (hashin_len > fixed_size) {
        printf("FAIL: argument hash too long, len %u val:\"%s\"\n",
               hashin_len, cuhash_in);
        exit(EXIT_FAILURE);
    }
    if (hashin_len  < fixed_size) {
        unsigned add_zeros = fixed_size - hashin_len;
        for (; add_zeros > 0; add_zeros --) {
            localhash[init_byte] = '0';
            init_byte ++;
        }
    }
    for (i = 0; i < hashin_len; ++i, ++init_byte) {
        localhash[init_byte] = cuhash_in[i];
    }

    /*  So now local hash as a full 16 bytes of hex characters with
        any needed leading zeros.
        transform it to 8 byte hex signature */

    for (i = 0; i < sizeof(Dwarf_Sig8) ; ++i) {
        unsigned char hichar = localhash[2 * i];
        unsigned char lochar = localhash[2 * i + 1];
        hash_out->signature[i] = (char_to_uns4bit(hichar) << 4)  | char_to_uns4bit(lochar);
    }
    printf("Hex key = 0x");
    for (i = 0; i < sizeof(Dwarf_Sig8); ++ i) {
        unsigned char c = hash_out->signature[i];
        printf("%02x",c);
    }
    printf("\n");
}

static void format_sig8_string(Dwarf_Sig8* data, char* str_buf, unsigned buf_size) {
    unsigned i = 0;
    char *cp = str_buf;
    if (buf_size <  19) {
        printf("FAIL: internal coding error in test.\n");
        exit(EXIT_FAILURE);
    }
    strcpy(cp, "0x");
    cp += 2;
    buf_size -= 2;
    for (; i < sizeof(data->signature); ++ i, cp += 2, buf_size--) {
        snprintf(cp, buf_size, "%02x", (unsigned char)(data->signature[i]));
    }
    return;
}

static void print_debug_fission_header(struct Dwarf_Debug_Fission_Per_CU_s *fsd) {
    const char * fissionsec = ".debug_cu_index";
    unsigned i = 0;
    char str_buf[30];

    if (!fsd || !fsd->pcu_type) {
        /* No fission data. */
        return;
    }
    printf("\n");
    if (!strcmp(fsd->pcu_type, "tu")) {
        fissionsec = ".debug_tu_index";
    }
    printf("  %-19s = %s\n","Fission section", fissionsec);
    printf("  %-19s = 0x%" DW_PR_XZEROS DW_PR_DUx "\n",
        "Fission index ",
        fsd->pcu_index);
    format_sig8_string(&fsd->pcu_hash,str_buf, sizeof(str_buf));
    printf("  %-19s = %s\n","Fission hash", str_buf);
    /* 0 is always unused. Skip it. */
    printf("  %-19s = %s\n","Fission entries","offset     "
        "size        DW_SECTn");
    for (i = 1; i < DW_FISSION_SECT_COUNT; ++ i)  {
        const char *nstring = 0;
        Dwarf_Unsigned off = 0;
        Dwarf_Unsigned size = fsd->pcu_size[i];
        int res = 0;
        if (size == 0) {
            continue;
        }
        res = dwarf_get_SECT_name(i, &nstring);
        if (res != DW_DLV_OK) {
            nstring = "Unknown SECT";
        }
        off = fsd->pcu_offset[i];
        printf("  %-19s = 0x%" DW_PR_XZEROS DW_PR_DUx
            " 0x%" DW_PR_XZEROS DW_PR_DUx " %2u\n",
            nstring,
            off,
            size,i);
    }
}

/*  If there is no 'error' passed into a dwarf function
    and there is an error, and an error-handler like this
    is passed.  This example simply returns so we
    test how well that action works.   */
static void simple_error_handler(Dwarf_Error error, Dwarf_Ptr errarg) {
    Dwarf_Unsigned earg = (Dwarf_Unsigned)(uintptr_t)errarg;
    printf("\nlibdwarf error detected: 0x%" DW_PR_DUx " %s\n",
        dwarf_errno(error),dwarf_errmsg(error));
    printf("libdwarf errarg. %" DW_PR_DUu "\n", earg);
    return;
}

int main(int argc, char **argv) {
    Dwarf_Debug dbg = 0;
    int i = 0;
    int res = DW_DLV_ERROR;
    Dwarf_Error error;
    Dwarf_Error *errp  = 0;

    #define MACHO_PATH_LEN 2000
    char macho_real_path[MACHO_PATH_LEN];

    macho_real_path[0] = '\0';
    res = dwarf_init_path(argv[1],
            macho_real_path,
            MACHO_PATH_LEN,
            DW_GROUPNUMBER_ANY,simple_error_handler,(Dwarf_Ptr)1,&dbg, errp);
    if (res != DW_DLV_OK) {
        if (res == DW_DLV_ERROR) {
            dwarf_dealloc_error(dbg, error);
            error = 0;
        }
        printf("Giving up, cannot do DWARF processing %s\n", argv[1] ? argv[1] : "");
        exit(EXIT_FAILURE);
    }

    read_cu_list(dbg);

    res = dwarf_finish(dbg);
    if (res != DW_DLV_OK) {
        printf("dwarf_finish failed!\n");
    }
    return 0;
}

static void read_cu_list(Dwarf_Debug dbg) {
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Unsigned abbrev_offset = 0;
    Dwarf_Half     address_size = 0;
    Dwarf_Half     version_stamp = 0;
    Dwarf_Half     offset_size = 0;
    Dwarf_Half     extension_size = 0;
    Dwarf_Sig8     signature;
    Dwarf_Unsigned typeoffset = 0;
    Dwarf_Unsigned next_cu_header = 0;
    Dwarf_Half     header_cu_type = DW_UT_compile;
    Dwarf_Bool     is_info = true;
    Dwarf_Error error;
    int cu_number = 0;
    Dwarf_Error *errp  = 0;

    for (;; ++ cu_number) {
        Dwarf_Die no_die = 0;
        Dwarf_Die cu_die = 0;
        int res = DW_DLV_ERROR;
        struct srcfilesdata sf;
        sf.srcfilesres = DW_DLV_ERROR;
        sf.srcfiles = 0;
        sf.srcfilescount = 0;

        memset(&signature,0, sizeof(signature));
        res = dwarf_next_cu_header_d(dbg,is_info,&cu_header_length,
            &version_stamp, &abbrev_offset,
            &address_size, &offset_size,
            &extension_size, &signature,
            &typeoffset, &next_cu_header,
            &header_cu_type, errp);
        if (res == DW_DLV_ERROR) {
            char *em = errp ? dwarf_errmsg(error) : "An error next cu her";
            printf("Error in dwarf_next_cu_header: %s\n", em);
            exit(EXIT_FAILURE);
        }
        if (res == DW_DLV_NO_ENTRY) {
            /* Done. */
            printf("function read_cu_list  read to end.");
            return;
        }

        cu_version_stamp = version_stamp;
        cu_offset_size   = offset_size;
        /* The CU will have a single sibling, a cu_die. */
        res = dwarf_siblingof_b(dbg, no_die, is_info, &cu_die, errp);
        if (res == DW_DLV_ERROR) {
            char *em = errp ? dwarf_errmsg(error) : "An error";
            printf("Error in dwarf_siblingof_b on CU die: %s\n", em);
            exit(EXIT_FAILURE);
        }
        if (res == DW_DLV_NO_ENTRY) {
            /* Impossible case. */
            printf("no entry! in dwarf_siblingof on CU die \n");
            exit(EXIT_FAILURE);
        }
        get_die_and_siblings(dbg, cu_die, is_info, 0, &sf);
        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
        reset_src_files(dbg, &sf);
    }
}

static void get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die,
    int is_info,int in_level, struct srcfilesdata *sf) {
    int res = DW_DLV_ERROR;
    Dwarf_Die cur_die=in_die;
    Dwarf_Die child = 0;
    Dwarf_Error error = 0;
    Dwarf_Error *errp = 0;

    print_die_data(dbg, in_die, in_level, sf);

    for (;;) {
        Dwarf_Die sib_die = 0;
        res = dwarf_child(cur_die ,&child, errp);
        if (res == DW_DLV_ERROR) {
            printf("Error in dwarf_child , level %d \n", in_level);
            exit(EXIT_FAILURE);
        }
        if (res == DW_DLV_OK) {
            get_die_and_siblings(dbg, child, is_info, in_level + 1, sf);
            /* No longer need 'child' die. */
            dwarf_dealloc(dbg, child, DW_DLA_DIE);
            child = 0;
        }
        /* res == DW_DLV_NO_ENTRY or DW_DLV_OK */
        res = dwarf_siblingof_b(dbg, cur_die, is_info, &sib_die, errp);
        if (res == DW_DLV_ERROR) {
            char *em = errp ? dwarf_errmsg(error) : "Error siblingof_b";
            printf("Error in dwarf_siblingof_b , level %d :%s \n", in_level, em);
            exit(EXIT_FAILURE);
        }
        if (res == DW_DLV_NO_ENTRY) {
            /* Done at this level. */
            break;
        }
        /* res == DW_DLV_OK */
        if (cur_die != in_die) {
            dwarf_dealloc(dbg, cur_die, DW_DLA_DIE);
            cur_die = 0;
        }
        cur_die = sib_die;
        print_die_data(dbg, cur_die, in_level, sf);
    }
    return;
}

static void get_addr(Dwarf_Attribute attr, Dwarf_Addr *val)
{
    Dwarf_Error error = 0;
    int res;
    Dwarf_Addr uval = 0;
    Dwarf_Error *errp  = 0;

    res = dwarf_formaddr(attr, &uval, errp);
    if (res == DW_DLV_OK) {
        *val = uval;
        return;
    }
    return;
}

static void get_number(Dwarf_Attribute attr, Dwarf_Unsigned *val) {
    Dwarf_Error error = 0;
    int res;
    Dwarf_Signed sval = 0;
    Dwarf_Unsigned uval = 0;
    Dwarf_Error *errp  = 0;

    res = dwarf_formudata(attr, &uval, errp);
    if (res == DW_DLV_OK) {
        *val = uval;
        return;
    }

    res = dwarf_formsdata(attr, &sval, errp);
    if (res == DW_DLV_OK) {
        *val = sval;
        return;
    }
    return;
}

static void print_subprog(Dwarf_Debug dbg, Dwarf_Die die,
    int level, struct srcfilesdata *sf, const char *name) {
    int res;
    Dwarf_Error error = 0;
    Dwarf_Attribute *attrbuf = 0;
    Dwarf_Addr lowpc = 0;
    Dwarf_Addr highpc = 0;
    Dwarf_Signed attrcount = 0;
    Dwarf_Signed i;
    Dwarf_Unsigned filenum = 0;
    Dwarf_Unsigned linenum = 0;
    char *filename = 0;
    Dwarf_Error *errp = 0;

    res = dwarf_attrlist(die, &attrbuf, &attrcount, errp);
    if (res != DW_DLV_OK) {
        if (res == DW_DLV_ERROR) {
            dwarf_dealloc_error(dbg, error);
            error = 0;
            exit(EXIT_FAILURE);
        }
        return;
    }
    for (i = 0; i < attrcount ; ++i) {
        Dwarf_Half aform;
        res = dwarf_whatattr(attrbuf[i], &aform, errp);
        if (res == DW_DLV_OK) {
            if (aform == DW_AT_decl_file) {
                Dwarf_Signed filenum_s = 0;

                get_number(attrbuf[i], &filenum);
                filenum_s = filenum;
                /*  Would be good to evaluate filenum_s
                    sanity here, ensuring filenum_s-1 is sensible. */
                if ((filenum > 0) &&
                    (sf->srcfilescount > (filenum_s - 1))) {
                    filename = sf->srcfiles[filenum_s - 1];
                }
            }
            if (aform == DW_AT_decl_line) {
                get_number(attrbuf[i], &linenum);
            }
            if (aform == DW_AT_low_pc) {
                get_addr(attrbuf[i], &lowpc);
            }
            if (aform == DW_AT_high_pc) {
                /*  This will FAIL with DWARF4 highpc form
                    of 'class constant'.  */
                get_addr(attrbuf[i], &highpc);
            }
        }
        if (res == DW_DLV_ERROR) {
            dwarf_dealloc_error(dbg, error);
            error = 0;
        }
        dwarf_dealloc(dbg, attrbuf[i], DW_DLA_ATTR);
    }
    dwarf_dealloc(dbg,attrbuf,DW_DLA_LIST);
}

static void print_comp_dir(Dwarf_Debug dbg,Dwarf_Die die, int level, struct srcfilesdata *sf) {
    int res;
    Dwarf_Error error = 0;
    Dwarf_Attribute *attrbuf = 0;
    Dwarf_Signed attrcount = 0;
    Dwarf_Signed i;
    Dwarf_Error *errp = 0;

    res = dwarf_attrlist(die, &attrbuf, &attrcount, errp);
    if (res != DW_DLV_OK) {
        return;
    }

    sf->srcfilesres = dwarf_srcfiles(die, &sf->srcfiles, &sf->srcfilescount, &error);
    for (i = 0; i < attrcount; ++ i) {
        Dwarf_Half aform;
        res = dwarf_whatattr(attrbuf[i], &aform, errp);
        if (res == DW_DLV_OK) {
            if (aform == DW_AT_comp_dir) {
                char *name = 0;
                res = dwarf_formstring(attrbuf[i], &name, errp);
                if (res == DW_DLV_OK) {
                    printf("<%3d> compilation directory : \"%s\"\n", level, name);
                }
            }
            if (aform == DW_AT_stmt_list) {
                /* Offset of stmt list for this CU in .debug_line */
            }
        }
        dwarf_dealloc(dbg, attrbuf[i], DW_DLA_ATTR);
    }
    dwarf_dealloc(dbg, attrbuf, DW_DLA_LIST);
}

static void reset_src_files(Dwarf_Debug dbg, struct srcfilesdata *sf) {
    Dwarf_Signed sri;
    if (sf->srcfiles) {
        for (sri = 0; sri < sf->srcfilescount; ++ sri) {
            dwarf_dealloc(dbg, sf->srcfiles[sri], DW_DLA_STRING);
        }
        dwarf_dealloc(dbg, sf->srcfiles, DW_DLA_LIST);
    }
    sf->srcfilesres = DW_DLV_ERROR;
    sf->srcfiles = 0;
    sf->srcfilescount = 0;
}

static void print_single_string(Dwarf_Debug dbg, Dwarf_Die die, Dwarf_Half attrnum) {
    int res = 0;
    Dwarf_Error error = 0;
    char * stringval = 0;

    res = dwarf_die_text(die, attrnum, &stringval, &error);
    if (res == DW_DLV_OK) {
        printf("string val: %s, %d\n", stringval, attrnum);
        dwarf_dealloc(dbg, stringval, DW_DLA_STRING);
    }
    return;
}

static void print_name_strings_attr(Dwarf_Debug dbg, Dwarf_Die die, Dwarf_Attribute attr) {
    int res = 0;
    Dwarf_Half attrnum = 0;
    Dwarf_Half finalform = 0;
    enum Dwarf_Form_Class cl = DW_FORM_CLASS_UNKNOWN;
    Dwarf_Error error = 0;

    res = dwarf_whatattr(attr, &attrnum, &error);
    if (res != DW_DLV_OK) {
        printf("Unable to get attr number");
        exit(EXIT_FAILURE);
    }

    res = dwarf_whatform(attr, &finalform, &error);
    if (res != DW_DLV_OK) {
        printf("Unable to get attr form");
        exit(EXIT_FAILURE);
    }

    cl = dwarf_get_form_class(cu_version_stamp, attrnum, cu_offset_size, finalform);

    if (cl != DW_FORM_CLASS_STRING) {
        return;
    }
    print_single_string(dbg, die, attrnum);
}

static void print_name_strings(Dwarf_Debug dbg, Dwarf_Die die) {
    Dwarf_Error error =0;
    Dwarf_Attribute *atlist = 0;
    Dwarf_Signed atcount = 0;
    Dwarf_Signed i = 0;
    int res = 0;

    res = dwarf_attrlist(die, &atlist, &atcount, &error);
    if (res != DW_DLV_OK) {
        return;
    }
    for (i = 0; i < atcount; ++ i) {
        Dwarf_Attribute attr = atlist[i];
        /*  Use an empty attr to get a placeholder on
            the attr list for this IRDie. */
        print_name_strings_attr(dbg, die, attr);
    }
    dwarf_dealloc(dbg,atlist, DW_DLA_LIST);
}

static void print_die_data_i(Dwarf_Debug dbg, Dwarf_Die print_me,
    int level, struct srcfilesdata *sf) {
    char *name = 0;
    Dwarf_Error error = 0;
    Dwarf_Half tag = 0;
    const char *tagname = 0;
    int res = 0;
    Dwarf_Error *errp = 0;
    Dwarf_Attribute attr = 0;
    Dwarf_Half formnum = 0;
    const char *formname = 0;

    res = dwarf_diename(print_me, &name, errp);
    if (res == DW_DLV_ERROR) {
        printf("Error in dwarf_diename , level %d \n", level);
        exit(EXIT_FAILURE);
    }
    if (res == DW_DLV_NO_ENTRY) {
        name = "<no DW_AT_name attr>";
    }
    res = dwarf_tag(print_me, &tag, errp);
    if (res != DW_DLV_OK) {
        printf("Error in dwarf_tag , level %d \n", level);
        exit(EXIT_FAILURE);
    }
    res = dwarf_get_TAG_name(tag, &tagname);
    if (res != DW_DLV_OK) {
        printf("Error in dwarf_get_TAG_name , level %d \n", level);
        exit(EXIT_FAILURE);
    }
    print_name_strings(dbg, print_me);
    res = dwarf_attr(print_me, DW_AT_name, &attr, errp);
    if (res != DW_DLV_OK) {
        /* do nothing */
    } else {
        res = dwarf_whatform(attr, &formnum, errp);
        if (res != DW_DLV_OK) {
            printf("Error in dwarf_whatform , level %d \n",level);
            exit(EXIT_FAILURE);
        }
        formname = "form-name-unavailable";
        res = dwarf_get_FORM_name(formnum, &formname);
        if (res != DW_DLV_OK) {
            formname = "UNKNoWn FORM!";
        }
        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
    }

    printf("<%d> tag: %d %s  name: \"%s\"",level, tag, tagname, name);
    if (formname) {
        printf(" FORM 0x%x \"%s\"", formnum, formname);
    }
    printf("\n");
    /*  This dwarf_dealloc was always wrong but
        before March 14, 2020 the documentation said
        the dwarf_dealloc was necessary.
        dwarf_dealloc(dbg,name,DW_DLA_STRING); */

}

static void print_die_data(Dwarf_Debug dbg, Dwarf_Die print_me, int level,
    struct srcfilesdata *sf) {
    print_die_data_i(dbg, print_me, level, sf);
}
