#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include "cJSON.h"

// refer to https://blog.csdn.net/qq_34272143/article/details/82884408

#include "dwarf.h"
#include "libdwarf.h"
#include "libdwarf_private.h"

typedef int (*cb_out_func)(char*);
struct dwarf_handler {
    Dwarf_Debug dbg;
    cb_out_func cb;
    cb_out_func check;
};

struct src_files_data {
    char ** src_files;
    Dwarf_Signed src_files_count;
    int src_files_res;
    int cu_version_stamp;
    int cu_offset_size;
};

typedef int (*walk_die_and_siblings)(struct dwarf_handler*, Dwarf_Die, int, int, struct src_files_data *);

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

static void reset_src_files(Dwarf_Debug dbg, struct src_files_data *sf) {
    Dwarf_Signed sri;
    if (sf->src_files) {
        for (sri = 0; sri < sf->src_files_count; ++ sri) {
            dwarf_dealloc(dbg, sf->src_files[sri], DW_DLA_STRING);
        }
        dwarf_dealloc(dbg, sf->src_files, DW_DLA_LIST);
    }
    sf->src_files_res = DW_DLV_ERROR;
    sf->src_files = 0;
    sf->src_files_count = 0;
}

static int attr_addr(Dwarf_Attribute attr, Dwarf_Addr *val, Dwarf_Error *errp) {
    int res;
    Dwarf_Addr lval = 0;

    res = dwarf_formaddr(attr, &lval, errp);
    if (res == DW_DLV_OK) {
        *val = lval;
    }
    return res;
}

static int attr_flag(Dwarf_Attribute attr, Dwarf_Bool *val, Dwarf_Error *errp) {
    int res;
    Dwarf_Bool lval = false;

    res = dwarf_formflag(attr, &lval, errp);
    if (res == DW_DLV_OK) {
        *val = lval;
    }
    return res;
}

static int attr_u64(Dwarf_Attribute attr, Dwarf_Unsigned *val, Dwarf_Error *errp) {
    int res;
    Dwarf_Unsigned lval = 0;

    res = dwarf_formudata(attr, &lval, errp);
    if (res == DW_DLV_OK) {
        *val = lval;
    }
    return res;
}

static int attr_s64(Dwarf_Attribute attr, Dwarf_Signed *val, Dwarf_Error *errp) {
    int res;
    Dwarf_Signed lval = 0;

    res = dwarf_formsdata(attr, &lval, errp);
    if (res == DW_DLV_OK) {
        *val = lval;
    }
    return res;
}

static int attr_ref(Dwarf_Attribute attr, Dwarf_Off *off,
                     Dwarf_Bool *is_info, Dwarf_Error *errp) {
    int res;
    Dwarf_Off loff = 0;
    Dwarf_Bool info = false;

    res = dwarf_formref(attr, &loff, &info, errp);
    if (res == DW_DLV_OK) {
        *off = loff;
        *is_info = info;
    }
    return res;
}

static int attr_str(Dwarf_Attribute attr, char **val, Dwarf_Error *errp) {
    int res;
    char* lval = 0;

    res = dwarf_formstring(attr, &lval, errp);
    if (res == DW_DLV_OK) {
        *val = lval;
    }
    return res;
}

static enum Dwarf_Form_Class die_attr_class(Dwarf_Attribute attr, Dwarf_Half attr_num,
                                     struct src_files_data *sf, Dwarf_Error *error) {
    int res;
    enum Dwarf_Form_Class cl = DW_FORM_CLASS_UNKNOWN;
    Dwarf_Half final_form = 0;

    res = dwarf_whatform(attr, &final_form, error);
    if (res != DW_DLV_OK) {
        fprintf(stderr, "Unable to get attr form\n");
    } else {
        cl = dwarf_get_form_class(sf->cu_version_stamp, attr_num,
                                  sf->cu_offset_size, final_form);
    }
    return cl;
}

static void print_attr(Dwarf_Attribute attr, enum Dwarf_Form_Class cl,
        Dwarf_Error *error) {
    Dwarf_Addr addr = NULL;
    Dwarf_Bool flag = false;
    Dwarf_Unsigned val = 0;
    char *s = "";
    Dwarf_Off loff = 0;
    Dwarf_Bool info = false;

    switch (cl) {
        case DW_FORM_CLASS_ADDRESS:
            attr_addr(attr, &addr, error);
            printf("%p", addr);
            break;
        case DW_FORM_CLASS_CONSTANT:
            attr_u64(attr, &val, error);
            printf("0x%lx", val);
            break;
        case DW_FORM_CLASS_FLAG:
            attr_flag(attr, &flag, error);
            printf("%d", flag);
            break;
        case DW_FORM_CLASS_STRING:
            attr_str(attr, &s, error);
            printf("%s", s);
            break;
        case DW_FORM_CLASS_REFERENCE:
            attr_ref(attr, &loff, &info, error);
            printf("0x%lx,%d", loff, info);
            break;
        default:
            printf("<%d>", cl);
            break;
    }
}

int print_die_attr(Dwarf_Debug dbg, Dwarf_Die die,
                   struct src_files_data *sf, Dwarf_Error *errp) {
    Dwarf_Signed atcount;
    Dwarf_Attribute *atlist;
    Dwarf_Signed i = 0;
    Dwarf_Off goff = 0;
    Dwarf_Off loff = 0;
    enum Dwarf_Form_Class cl;
    int res;

    res = dwarf_die_offsets(die, &goff, &loff, errp);
    if (res == DW_DLV_OK) {
        printf("!!! die offset: 0x%lx\n", loff);
    }

    res = dwarf_attrlist(die, &atlist, &atcount, errp);
    if (res != DW_DLV_OK) {
        return res;
    }

    for (i = 0; i < atcount; ++ i) {
        Dwarf_Half attr_num = 0;
        const char *attr_name = 0;
        /*  use atlist[i], likely calling
            libdwarf functions and likely
            returning DW_DLV_ERROR if
            what you call gets DW_DLV_ERROR */
        res = dwarf_whatattr(atlist[i], &attr_num, errp);
        if (res != DW_DLV_OK) {
            /* Something really bad happened. */
            return res;
        }
        dwarf_get_AT_name(attr_num, &attr_name);
        cl = die_attr_class(atlist[i], attr_num, sf, errp);
        printf("Attribute[%ld], value %u name %s, cl: %d, value:",
               (long int)i, attr_num, attr_name, cl);
        print_attr(atlist[i], cl, errp);
        printf("\n");
        dwarf_dealloc_attribute(atlist[i]);
        atlist[i] = 0;
    }
    dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
    return DW_DLV_OK;
}

static void print_die_data_i(Dwarf_Debug dbg, Dwarf_Die print_me,
    int level, struct src_files_data *sf) {
    char *name = 0;
    Dwarf_Error error = 0;
    Dwarf_Half tag =  0;
    const char *tag_name = 0;
    int res = 0;
    Dwarf_Error *errp = 0;
    Dwarf_Attribute attr = 0;
    Dwarf_Half form_num = 0;
    const char *form_name = 0;
    Dwarf_Half addr_num = 0;
    const char *addr_name = 0;
    int abbrev;

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
    res = dwarf_get_TAG_name(tag, &tag_name);
    if (res != DW_DLV_OK) {
        printf("Error in dwarf_get_TAG_name , level %d \n", level);
        exit(EXIT_FAILURE);
    }

    print_die_attr(dbg, print_me, sf, errp);
    res = dwarf_attr(print_me, DW_AT_name, &attr, errp);
    if (res != DW_DLV_OK) {
        /* do nothing */
    } else {
        res = dwarf_whatform(attr, &form_num, errp);
        if (res != DW_DLV_OK) {
            printf("Error in dwarf_whatform , level %d \n",level);
            exit(EXIT_FAILURE);
        }
        form_name = "form-name-unavailable";
        res = dwarf_get_FORM_name(form_num, &form_name);
        if (res != DW_DLV_OK) {
            form_name = "UNKNoWn FORM!";
        }

        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
    }

    abbrev = dwarf_die_abbrev_code(print_me);
    printf("<%d><%x> tag: %d %s  name: \"%s\"", level, abbrev, tag, tag_name, name);
    if (form_name) {
        printf(" FORM 0x%x \"%s\"", form_num, form_name);
    }
    printf("\n");
}

static void print_die_data(Dwarf_Debug dbg, Dwarf_Die print_me, int level,
    struct src_files_data *sf) {
    print_die_data_i(dbg, print_me, level, sf);
}

static void _get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die,
    int is_info, int in_level, struct src_files_data *sf) {
    int res = DW_DLV_ERROR;
    Dwarf_Die cur_die = in_die;
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
            _get_die_and_siblings(dbg, child, is_info, in_level + 1, sf);
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
}

static int get_die_and_siblings(struct dwarf_handler *h, Dwarf_Die in_die,
                                 int is_info, int in_level, struct src_files_data *sf) {
    _get_die_and_siblings(h->dbg, in_die, is_info, in_level, sf);
    return 0;
}

static void attr_to_json(cJSON* parent, Dwarf_Attribute attr, enum Dwarf_Form_Class cl,
        const char *name, Dwarf_Error *error) {
    int res;
    Dwarf_Addr addr = NULL;
    Dwarf_Bool flag = false;
    Dwarf_Signed sval = 0;
    Dwarf_Unsigned val = 0;
    char *s = "";
    Dwarf_Off loff = 0;
    Dwarf_Bool info = false;

    switch (cl) {
        case DW_FORM_CLASS_ADDRESS:
            attr_addr(attr, &addr, error);
            cJSON_AddNumberToObject(parent, name, addr);
            break;
        case DW_FORM_CLASS_CONSTANT:
            res = attr_s64(attr, &sval, error);
            if (res == DW_DLV_OK) {
                cJSON_AddNumberToObject(parent, name, sval);
                break;
            }
            res = attr_u64(attr, &val, error);
            if (res == DW_DLV_OK) {
                cJSON_AddNumberToObject(parent, name, val);
                break;
            }
            break;
        case DW_FORM_CLASS_FLAG:
            attr_flag(attr, &flag, error);
            cJSON_AddBoolToObject(parent, name, flag);
            break;
        case DW_FORM_CLASS_STRING:
            attr_str(attr, &s, error);
            cJSON_AddStringToObject(parent, name, s);
            break;
        case DW_FORM_CLASS_REFERENCE:
            attr_ref(attr, &loff, &info, error);
            cJSON_AddNumberToObject(parent, name, loff);
            break;
        default:
            break;
    }
}

int json_die_attr(cJSON* parent, Dwarf_Debug dbg, Dwarf_Die die,
                  struct src_files_data *sf, Dwarf_Error *errp) {
    Dwarf_Signed atcount;
    Dwarf_Attribute *atlist;
    Dwarf_Signed i = 0;
    Dwarf_Off goff = 0;
    Dwarf_Off loff = 0;
    enum Dwarf_Form_Class cl;
    int res;

    res = dwarf_die_offsets(die, &goff, &loff, errp);
    if (res == DW_DLV_OK) {
        cJSON_AddNumberToObject(parent, "offset", loff);
    }

    res = dwarf_attrlist(die, &atlist, &atcount, errp);
    if (res != DW_DLV_OK) {
        return res;
    }

    for (i = 0; i < atcount; ++ i) {
        Dwarf_Half attr_num = 0;
        const char *attr_name = 0;
        /*  use atlist[i], likely calling
            libdwarf functions and likely
            returning DW_DLV_ERROR if
            what you call gets DW_DLV_ERROR */
        res = dwarf_whatattr(atlist[i], &attr_num, errp);
        if (res != DW_DLV_OK) {
            /* Something really bad happened. */
            return res;
        }
        dwarf_get_AT_name(attr_num, &attr_name);
        cl = die_attr_class(atlist[i], attr_num, sf, errp);
        attr_to_json(parent, atlist[i], cl, attr_name, errp);
        dwarf_dealloc_attribute(atlist[i]);
        atlist[i] = 0;
    }
    dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
    return DW_DLV_OK;
}

static void json_die_data(cJSON* parent, Dwarf_Debug dbg, Dwarf_Die print_me,
                          int level, struct src_files_data *sf) {
    char *name = 0;
    Dwarf_Error error = 0;
    Dwarf_Half tag =  0;
    const char *tag_name = 0;
    int res = 0;
    Dwarf_Error *errp = 0;
    Dwarf_Attribute attr = 0;
    Dwarf_Half form_num = 0;
    const char *form_name = 0;
    Dwarf_Half addr_num = 0;
    const char *addr_name = 0;
    int abbrev;

    res = dwarf_diename(print_me, &name, errp);
    if (res == DW_DLV_ERROR) {
        fprintf(stderr, "Error in dwarf_diename , level %d \n", level);
        exit(EXIT_FAILURE);
    }

    if (res == DW_DLV_NO_ENTRY) {
        name = "<no DW_AT_name attr>";
    }
    res = dwarf_tag(print_me, &tag, errp);
    if (res != DW_DLV_OK) {
        fprintf(stderr, "Error in dwarf_tag , level %d \n", level);
        exit(EXIT_FAILURE);
    }
    res = dwarf_get_TAG_name(tag, &tag_name);
    if (res != DW_DLV_OK) {
        printf("Error in dwarf_get_TAG_name , level %d \n", level);
        exit(EXIT_FAILURE);
    }

    json_die_attr(parent, dbg, print_me, sf, errp);
    res = dwarf_attr(print_me, DW_AT_name, &attr, errp);
    if (res != DW_DLV_OK) {
        /* do nothing */
    } else {
        res = dwarf_whatform(attr, &form_num, errp);
        if (res != DW_DLV_OK) {
            printf("Error in dwarf_whatform , level %d \n",level);
            exit(EXIT_FAILURE);
        }
        form_name = "form-name-unavailable";
        res = dwarf_get_FORM_name(form_num, &form_name);
        if (res != DW_DLV_OK) {
            form_name = "UNKNoWn FORM!";
        }
        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
    }

    abbrev = dwarf_die_abbrev_code(print_me);
    cJSON_AddNumberToObject(parent, "level", level);
    cJSON_AddNumberToObject(parent, "abbrev", abbrev);
    cJSON_AddStringToObject(parent, "tag_name", tag_name);
    if (form_name) {
        cJSON_AddStringToObject(parent, "form_name", form_name);
    }
}

static void json_die_and_siblings(cJSON* arr, Dwarf_Debug dbg, Dwarf_Die in_die,
    int is_info, int in_level, struct src_files_data *sf) {
    int res = DW_DLV_ERROR;
    Dwarf_Die cur_die = in_die;
    Dwarf_Die child = 0;
    Dwarf_Error error = 0;
    Dwarf_Error *errp = 0;

    cJSON* obj = cJSON_CreateObject();
    cJSON_AddItemToArray(arr, obj);
    json_die_data(obj, dbg, in_die, in_level, sf);

    for (;;) {
        Dwarf_Die sib_die = 0;

        res = dwarf_child(cur_die ,&child, errp);
        if (res == DW_DLV_ERROR) {
            printf("Error in dwarf_child , level %d \n", in_level);
            exit(EXIT_FAILURE);
        }
        if (res == DW_DLV_OK) {
            cJSON* j_childs = cJSON_AddArrayToObject(obj, "child");
            json_die_and_siblings(j_childs, dbg, child, is_info, in_level + 1, sf);
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
        obj = cJSON_CreateObject();
        cJSON_AddItemToArray(arr, obj);
        json_die_data(obj, dbg, cur_die, in_level, sf);
    }
}

static int compile_unit_to_json(struct dwarf_handler *h, Dwarf_Die in_die,
    int is_info, int in_level, struct src_files_data *sf) {
    char *out;
    int res;

    cJSON* root = cJSON_CreateObject();
    cJSON* arr = cJSON_AddArrayToObject(root, "child");

    json_die_and_siblings(arr, h->dbg, in_die, is_info, in_level, sf);
    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    res = h->cb(out);
    free(out);
    return res;
}

static int check_compile_unit_json(struct dwarf_handler *h, Dwarf_Die in_die,
                                 int is_info, int in_level, struct src_files_data *sf) {
    char *name = 0;
    int res = 0;
    Dwarf_Error *errp = 0;

    res = dwarf_diename(in_die, &name, errp);
    if (res == DW_DLV_ERROR) {
        fprintf(stderr, "Error in dwarf_diename , level %d \n", in_level);
        exit(EXIT_FAILURE);
    }
    if (h->check(name) == 0) {
        char *out;
        cJSON* root = cJSON_CreateObject();
        cJSON* arr = cJSON_AddArrayToObject(root, "child");

        json_die_and_siblings(arr, h->dbg, in_die, is_info, in_level, sf);
        out = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);

        h->cb(out);
        free(out);
    }
    return 0;
}

static int walk_compile_unit(struct dwarf_handler *h, Dwarf_Die in_die,
    int is_info, int in_level, struct src_files_data *sf) {
    char *name = 0;
    int res = 0;
    Dwarf_Error *errp = 0;

    res = dwarf_diename(in_die, &name, errp);
    if (res == DW_DLV_ERROR) {
        fprintf(stderr, "Error in dwarf_diename , level %d \n", in_level);
        exit(EXIT_FAILURE);
    }
    h->cb(name);
    return 0;
}

static int read_cu_list(struct dwarf_handler *h, walk_die_and_siblings cb_walk) {
    Dwarf_Debug dbg = h->dbg;
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
        struct src_files_data sf;
        sf.src_files_res = DW_DLV_ERROR;
        sf.src_files = 0;
        sf.src_files_count = 0;

        memset(&signature, 0, sizeof(signature));
        res = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length,
            &version_stamp, &abbrev_offset,
            &address_size, &offset_size,
            &extension_size, &signature,
            &typeoffset, &next_cu_header,
            &header_cu_type, errp);
        if (res == DW_DLV_ERROR) {
            char *em = errp ? dwarf_errmsg(error) : "An error next cu her";
            fprintf(stderr, "Error in dwarf_next_cu_header: %s\n", em);
            return -ENOEXEC;
        }
        if (res == DW_DLV_NO_ENTRY) {
            /* Done. */
            return 0;
        }

        sf.cu_version_stamp = version_stamp;
        sf.cu_offset_size   = offset_size;;

        /* The CU will have a single sibling, a cu_die. */
        res = dwarf_siblingof_b(dbg, no_die, is_info, &cu_die, errp);
        if (res == DW_DLV_ERROR) {
            char *em = errp ? dwarf_errmsg(error) : "An error";
            fprintf(stderr, "Error in dwarf_siblingof_b on CU die: %s\n", em);
            dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
            return -ENOEXEC;
        }
        if (res == DW_DLV_NO_ENTRY) {
            /* Impossible case. */
            fprintf(stderr, "no entry! in dwarf_siblingof on CU die \n");
            return -ENOENT;
        }
        res = cb_walk(h, cu_die, is_info, 0, &sf);
        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
        reset_src_files(dbg, &sf);

        if (res != 0) {
            return res;
        }
    }
}

void* dwarf_load(char* path) {
    struct dwarf_handler *phandler;
    int i = 0;
    int res = DW_DLV_ERROR;
    Dwarf_Error error;
    Dwarf_Error *errp  = 0;

    #define MACHO_PATH_LEN 2000
    char macho_real_path[MACHO_PATH_LEN];

    phandler = malloc(sizeof(struct dwarf_handler));
    if (phandler == NULL) {
        errno = -ENOMEM;
        return NULL;
    }

    macho_real_path[0] = '\0';
    res = dwarf_init_path(path, macho_real_path, MACHO_PATH_LEN,
            DW_GROUPNUMBER_ANY, simple_error_handler, (Dwarf_Ptr)1, &phandler->dbg, errp);
    if (res != DW_DLV_OK) {
        if (res == DW_DLV_ERROR) {
            dwarf_dealloc_error(phandler->dbg, error);
            error = 0;
        }
        printf("Giving up, cannot do DWARF processing %s\n", path ? path : "");
        errno = -ENOENT;
        free(phandler);
        phandler = NULL;
    }
    phandler->cb = NULL;
    return phandler;
}

int dwarf_show(void *handler) {
    struct dwarf_handler *h = (struct dwarf_handler *)handler;
    h->cb = NULL;
    h->check = NULL;
    return read_cu_list(h, get_die_and_siblings);
}

int dwarf_walk_compile_unit(void *handler, void* cb) {
    struct dwarf_handler *h = (struct dwarf_handler *)handler;
    h->cb = (cb_out_func)cb;
    h->check = NULL;
    return read_cu_list(h, walk_compile_unit);
}

int dwarf_walk2json(void *handler, void* cb) {
    struct dwarf_handler *h = (struct dwarf_handler *)handler;
    h->cb = (cb_out_func)cb;
    h->check = NULL;
    return read_cu_list(h, compile_unit_to_json);
}

int dwarf_filter2json(void *handler, void* cb, void* filter) {
    struct dwarf_handler *h = (struct dwarf_handler *)handler;
    h->cb = (cb_out_func)cb;
    h->check = filter;
    return read_cu_list(h, check_compile_unit_json);
}

void dwarf_close(void *handler) {
    struct dwarf_handler *h = (struct dwarf_handler *)handler;
    int res = dwarf_finish(h->dbg);

    if (res != DW_DLV_OK) {
        fprintf(stderr, "dwarf_finish failed!\n");
    }
}
