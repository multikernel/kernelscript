#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/custom.h>

/* Debug macro */
/* #define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__) */
#define DEBUG_PRINT(...)

/* Custom block for BTF handle */
#define BTF_HANDLE_TAG 0

/* Custom finalization function for BTF handle */
static void btf_handle_finalize(value v) {
    struct btf *btf = *((struct btf **) Data_custom_val(v));
    if (btf) {
        btf__free(btf);
        *((struct btf **) Data_custom_val(v)) = NULL;
    }
}

static struct custom_operations btf_handle_ops = {
    "btf_handle",
    btf_handle_finalize,
    custom_compare_default,
    custom_hash_default,
    custom_serialize_default,
    custom_deserialize_default
};

/* Convert BTF handle to OCaml value */
static inline struct btf *btf_of_value(value v) {
    return *((struct btf **) Data_custom_val(v));
}

/* Convert OCaml value to BTF handle */
static inline value value_of_btf(struct btf *btf) {
    value v = alloc_custom(&btf_handle_ops, sizeof(struct btf *), 0, 1);
    *((struct btf **) Data_custom_val(v)) = btf;
    return v;
}

/* Open BTF file */
value btf_new_from_file_stub(value path) {
    CAMLparam1(path);
    CAMLlocal1(result);
    const char *file_path = String_val(path);
    struct btf *btf;
    
    DEBUG_PRINT("btf_new_from_file_stub: Opening %s\n", file_path);
    
    /* Try to open as raw BTF first */
    btf = btf__parse_raw(file_path);
    if (!btf) {
        DEBUG_PRINT("btf__parse_raw failed, trying btf__parse_elf\n");
        /* If that fails, try as ELF */
        btf = btf__parse_elf(file_path, NULL);
    }
    
    if (!btf) {
        DEBUG_PRINT("Both parsing methods failed\n");
        CAMLreturn(Val_int(0)); /* None */
    }
    
    DEBUG_PRINT("Successfully opened BTF file\n");
    result = caml_alloc_tuple(1);
    Store_field(result, 0, value_of_btf(btf));
    CAMLreturn(result); /* Some(btf_handle) */
}

/* Get number of types */
value btf_get_nr_types_stub(value btf_handle) {
    CAMLparam1(btf_handle);
    struct btf *btf = btf_of_value(btf_handle);
    
    DEBUG_PRINT("btf_get_nr_types_stub: handle=%ld, btf=%p\n", (long)Int_val(btf_handle), btf);
    
    if (!btf) {
        DEBUG_PRINT("btf_get_nr_types_stub: BTF handle is NULL\n");
        CAMLreturn(Val_int(0));
    }
    
    int nr_types = btf__type_cnt(btf);
    DEBUG_PRINT("btf_get_nr_types_stub: nr_types=%d\n", nr_types);
    CAMLreturn(Val_int(nr_types));
}

/* Get type by ID */
value btf_type_by_id_stub(value btf_handle, value type_id) {
    CAMLparam2(btf_handle, type_id);
    CAMLlocal1(result);
    
    struct btf *btf = btf_of_value(btf_handle);
    int id = Int_val(type_id);
    
    if (!btf) {
        caml_failwith("Invalid BTF handle");
    }
    
    const struct btf_type *t = btf__type_by_id(btf, id);
    if (!t) {
        caml_failwith("Invalid type ID");
    }
    
    /* Extract type information */
    int kind = btf_kind(t);
    const char *name = btf__name_by_offset(btf, t->name_off);
    if (!name) name = "";
    
    int size = 0;
    int type_ref = 0;
    int vlen = btf_vlen(t);
    
    switch (kind) {
        case BTF_KIND_INT:
        case BTF_KIND_STRUCT:
        case BTF_KIND_UNION:
        case BTF_KIND_ENUM:
            size = t->size;
            break;
        case BTF_KIND_PTR:
        case BTF_KIND_TYPEDEF:
        case BTF_KIND_VOLATILE:
        case BTF_KIND_CONST:
        case BTF_KIND_RESTRICT:
            type_ref = t->type;
            break;
    }
    
    /* Return tuple (kind, name, size, type_id, vlen) */
    result = caml_alloc_tuple(5);
    Store_field(result, 0, Val_int(kind));
    Store_field(result, 1, caml_copy_string(name));
    Store_field(result, 2, Val_int(size));
    Store_field(result, 3, Val_int(type_ref));
    Store_field(result, 4, Val_int(vlen));
    
    CAMLreturn(result);
}

/* Get name by offset */
value btf_name_by_offset_stub(value btf_handle, value offset) {
    CAMLparam2(btf_handle, offset);
    
    struct btf *btf = btf_of_value(btf_handle);
    int off = Int_val(offset);
    
    if (!btf) {
        CAMLreturn(caml_copy_string(""));
    }
    
    const char *name = btf__name_by_offset(btf, off);
    if (!name) name = "";
    
    CAMLreturn(caml_copy_string(name));
}

/* Get struct/union members */
value btf_type_get_members_stub(value btf_handle, value type_id) {
    CAMLparam2(btf_handle, type_id);
    CAMLlocal2(result, member_tuple);
    
    struct btf *btf = btf_of_value(btf_handle);
    int id = Int_val(type_id);
    
    if (!btf) {
        caml_failwith("Invalid BTF handle");
    }
    
    const struct btf_type *t = btf__type_by_id(btf, id);
    if (!t) {
        caml_failwith("Invalid type ID");
    }
    
    int kind = btf_kind(t);
    if (kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION) {
        /* Return empty array for non-struct/union types */
        CAMLreturn(caml_alloc_tuple(0));
    }
    
    int vlen = btf_vlen(t);
    if (vlen == 0) {
        CAMLreturn(caml_alloc_tuple(0));
    }
    
    const struct btf_member *members = btf_members(t);
    result = caml_alloc_tuple(vlen);
    
    for (int i = 0; i < vlen; i++) {
        const char *member_name = btf__name_by_offset(btf, members[i].name_off);
        if (!member_name) member_name = "";
        
        member_tuple = caml_alloc_tuple(2);
        Store_field(member_tuple, 0, caml_copy_string(member_name));
        Store_field(member_tuple, 1, Val_int(members[i].type));
        
        Store_field(result, i, member_tuple);
    }
    
    CAMLreturn(result);
}

/* Resolve type to string representation */
value btf_resolve_type_stub(value btf_handle, value type_id) {
    CAMLparam2(btf_handle, type_id);
    
    struct btf *btf = btf_of_value(btf_handle);
    int id = Int_val(type_id);
    
    if (!btf) {
        CAMLreturn(caml_copy_string("unknown"));
    }
    
    const struct btf_type *t = btf__type_by_id(btf, id);
    if (!t) {
        CAMLreturn(caml_copy_string("unknown"));
    }
    
    int kind = btf_kind(t);
    
    /* Follow type chains for pointers and typedefs */
    while (kind == BTF_KIND_PTR || kind == BTF_KIND_TYPEDEF || 
           kind == BTF_KIND_VOLATILE || kind == BTF_KIND_CONST || 
           kind == BTF_KIND_RESTRICT) {
        
        if (kind == BTF_KIND_PTR) {
            /* Check if this points to a function prototype */
            const struct btf_type *target = btf__type_by_id(btf, t->type);
            if (target && btf_kind(target) == BTF_KIND_FUNC_PROTO) {
                CAMLreturn(caml_copy_string("fn_ptr"));
            }
            /* Check if this points to char (string) */
            if (target && btf_kind(target) == BTF_KIND_INT && target->size == 1) {
                CAMLreturn(caml_copy_string("str"));
            }
            /* Other pointer types */
            CAMLreturn(caml_copy_string("*u8"));
        }
        
        /* Follow the type chain */
        t = btf__type_by_id(btf, t->type);
        if (!t) break;
        kind = btf_kind(t);
    }
    
    /* Handle final type */
    switch (kind) {
        case BTF_KIND_INT:
            switch (t->size) {
                case 1: CAMLreturn(caml_copy_string("u8"));
                case 2: CAMLreturn(caml_copy_string("u16"));
                case 4: CAMLreturn(caml_copy_string("u32"));
                case 8: CAMLreturn(caml_copy_string("u64"));
                default: CAMLreturn(caml_copy_string("u32"));
            }
            break;
        case BTF_KIND_STRUCT:
        case BTF_KIND_UNION:
        case BTF_KIND_ENUM: {
            const char *name = btf__name_by_offset(btf, t->name_off);
            if (name && strlen(name) > 0) {
                CAMLreturn(caml_copy_string(name));
            }
            break;
        }
        case BTF_KIND_FUNC_PROTO:
            CAMLreturn(caml_copy_string("fn_ptr"));
            break;
    }
    
    CAMLreturn(caml_copy_string("unknown"));
}

/* Free BTF handle */
value btf_free_stub(value btf_handle) {
    CAMLparam1(btf_handle);
    
    struct btf *btf = btf_of_value(btf_handle);
    if (btf) {
        btf__free(btf);
        /* Set to NULL to prevent double-free in finalization */
        *((struct btf **) Data_custom_val(btf_handle)) = NULL;
    }
    
    CAMLreturn(Val_unit);
} 