/*
 * Copyright 2025 Multikernel Technologies, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

/* BTF integer encoding macros (if not already defined in libbpf) */
#ifndef BTF_INT_ENCODING
#define BTF_INT_ENCODING(VAL)  (((VAL) & 0x0f000000) >> 24)
#endif
#ifndef BTF_INT_OFFSET
#define BTF_INT_OFFSET(VAL)    (((VAL) & 0x00ff0000) >> 16)
#endif
#ifndef BTF_INT_BITS
#define BTF_INT_BITS(VAL)      ((VAL) & 0x000000ff)
#endif

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
    value v = caml_alloc_custom(&btf_handle_ops, sizeof(struct btf *), 0, 1);
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
    if (kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION && kind != BTF_KIND_ENUM) {
        /* Return empty array for non-struct/union/enum types */
        CAMLreturn(caml_alloc_tuple(0));
    }
    
    int vlen = btf_vlen(t);
    if (vlen == 0) {
        CAMLreturn(caml_alloc_tuple(0));
    }
    
    result = caml_alloc_tuple(vlen);
    
    if (kind == BTF_KIND_ENUM) {
        /* Handle enum types - extract enum values */
        const struct btf_enum *enums = btf_enum(t);
        for (int i = 0; i < vlen; i++) {
            const char *enum_name = btf__name_by_offset(btf, enums[i].name_off);
            if (!enum_name) enum_name = "";
            
            member_tuple = caml_alloc_tuple(2);
            Store_field(member_tuple, 0, caml_copy_string(enum_name));
            /* For enums, store the value instead of type_id */
            Store_field(member_tuple, 1, Val_int(enums[i].val));
            
            Store_field(result, i, member_tuple);
        }
    } else {
        /* Handle struct/union types - extract members */
        const struct btf_member *members = btf_members(t);
        for (int i = 0; i < vlen; i++) {
            const char *member_name = btf__name_by_offset(btf, members[i].name_off);
            if (!member_name) member_name = "";
            
            member_tuple = caml_alloc_tuple(2);
            Store_field(member_tuple, 0, caml_copy_string(member_name));
            Store_field(member_tuple, 1, Val_int(members[i].type));
            
            Store_field(result, i, member_tuple);
        }
    }
    
    CAMLreturn(result);
}

/* Helper function to resolve a single type to string */
static char* resolve_type_to_string(struct btf *btf, int type_id) {
    if (type_id == 0) return strdup("void");
    
    const struct btf_type *t = btf__type_by_id(btf, type_id);
    if (!t) return strdup("unknown");
    
    int kind = btf_kind(t);
    
    /* Follow type chains */
    while (kind == BTF_KIND_PTR || kind == BTF_KIND_TYPEDEF || 
           kind == BTF_KIND_VOLATILE || kind == BTF_KIND_CONST || 
           kind == BTF_KIND_RESTRICT) {
        
        if (kind == BTF_KIND_PTR) {
            const struct btf_type *target = btf__type_by_id(btf, t->type);
            if (target && btf_kind(target) == BTF_KIND_INT && target->size == 1) {
                return strdup("*u8");  /* Use *u8 for char* to avoid str parsing issues */
            }
            return strdup("*u8");
        }
        
        t = btf__type_by_id(btf, t->type);
        if (!t) break;
        kind = btf_kind(t);
    }
    
    switch (kind) {
        case BTF_KIND_INT: {
            /* Check encoding to determine if signed or unsigned */
            __u32 *info_ptr = (__u32 *)(t + 1);
            __u32 info = *info_ptr;
            __u32 encoding = BTF_INT_ENCODING(info);
            
            /* BTF_INT_SIGNED is defined as 0x1 in BTF specification */
            int is_signed = (encoding & 0x1) != 0;
            
            switch (t->size) {
                case 1: return strdup(is_signed ? "i8" : "u8");
                case 2: return strdup(is_signed ? "i16" : "u16");
                case 4: return strdup(is_signed ? "i32" : "u32");
                case 8: return strdup(is_signed ? "i64" : "u64");
                default: return strdup(is_signed ? "i32" : "u32");
            }
        }
        case BTF_KIND_STRUCT:
        case BTF_KIND_UNION:
        case BTF_KIND_ENUM: {
            const char *name = btf__name_by_offset(btf, t->name_off);
            if (name && strlen(name) > 0) {
                return strdup(name);
            }
            return strdup(kind == BTF_KIND_STRUCT ? "struct" : 
                         kind == BTF_KIND_UNION ? "union" : "enum");
        }
        default:
            return strdup("unknown");
    }
}

/* Helper function to format function prototype */
static char* format_function_prototype(struct btf *btf, const struct btf_type *func_proto) {
    char result[1024];
    int ret_type_id = func_proto->type;
    int param_count = btf_vlen(func_proto);
    
    /* Get return type */
    char *ret_type = resolve_type_to_string(btf, ret_type_id);
    
    /* Start building the function signature */
    snprintf(result, sizeof(result), "fn(");
    
    /* Add parameters */
    if (param_count > 0) {
        const struct btf_param *params = (const struct btf_param *)(func_proto + 1);
        
        for (int i = 0; i < param_count; i++) {
            const struct btf_param *param = &params[i];
            
            /* Get parameter name */
            const char *param_name = btf__name_by_offset(btf, param->name_off);
            if (!param_name || strlen(param_name) == 0) {
                param_name = "arg";
            }
            
            /* Get parameter type */
            char *param_type = resolve_type_to_string(btf, param->type);
            
            /* Add parameter to result */
            char param_str[256];
            snprintf(param_str, sizeof(param_str), "%s%s: %s", 
                    (i > 0 ? ", " : ""), param_name, param_type);
            strncat(result, param_str, sizeof(result) - strlen(result) - 1);
            
            free(param_type);
        }
    }
    
    /* Close parameters and add return type */
    char closing[256];
    snprintf(closing, sizeof(closing), ") -> %s", ret_type);
    strncat(result, closing, sizeof(result) - strlen(result) - 1);
    
    free(ret_type);
    return strdup(result);
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
                char *func_sig = format_function_prototype(btf, target);
                value result = caml_copy_string(func_sig);
                free(func_sig);
                CAMLreturn(result);
            }
            /* Check if this points to char (string) */
            if (target && btf_kind(target) == BTF_KIND_INT && target->size == 1) {
                CAMLreturn(caml_copy_string("*u8"));  /* Use *u8 for char* to avoid str parsing issues */
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
        case BTF_KIND_ARRAY: {
            /* Arrays have additional btf_array data after btf_type */
            const void *array_data = t + 1;
            const struct {
                __u32 type;
                __u32 index_type;
                __u32 nelems;
            } *array_info = (const void *)array_data;
            
            /* Get element type string */
            const struct btf_type *elem_type = btf__type_by_id(btf, array_info->type);
            char result_buf[64];
            
            if (elem_type) {
                int elem_kind = btf_kind(elem_type);
                const char *elem_type_str = "u8"; /* default */
                
                if (elem_kind == BTF_KIND_INT) {
                    switch (elem_type->size) {
                        case 1: elem_type_str = "u8"; break;
                        case 2: elem_type_str = "u16"; break;
                        case 4: elem_type_str = "u32"; break;
                        case 8: elem_type_str = "u64"; break;
                        default: elem_type_str = "u32"; break;
                    }
                }
                
                snprintf(result_buf, sizeof(result_buf), "%s[%u]", elem_type_str, array_info->nelems);
            } else {
                snprintf(result_buf, sizeof(result_buf), "u8[%u]", array_info->nelems);
            }
            
            CAMLreturn(caml_copy_string(result_buf));
        }
        case BTF_KIND_STRUCT:
        case BTF_KIND_UNION:
        case BTF_KIND_ENUM: {
            const char *name = btf__name_by_offset(btf, t->name_off);
            if (name && strlen(name) > 0) {
                CAMLreturn(caml_copy_string(name));
            }
            /* For anonymous structs/unions */
            CAMLreturn(caml_copy_string(kind == BTF_KIND_STRUCT ? "struct" : 
                                      kind == BTF_KIND_UNION ? "union" : "enum"));
        }
        case BTF_KIND_ENUM64: {
            const char *name = btf__name_by_offset(btf, t->name_off);
            if (name && strlen(name) > 0) {
                CAMLreturn(caml_copy_string(name));
            }
            CAMLreturn(caml_copy_string("enum64"));
        }
        case BTF_KIND_FWD: {
            const char *name = btf__name_by_offset(btf, t->name_off);
            if (name && strlen(name) > 0) {
                CAMLreturn(caml_copy_string(name));
            }
            CAMLreturn(caml_copy_string("fwd"));
        }
        case BTF_KIND_FUNC_PROTO: {
            char *func_sig = format_function_prototype(btf, t);
            value result = caml_copy_string(func_sig);
            free(func_sig);
            CAMLreturn(result);
        }
        case BTF_KIND_FUNC: {
            const char *name = btf__name_by_offset(btf, t->name_off);
            if (name && strlen(name) > 0) {
                CAMLreturn(caml_copy_string(name));
            }
            CAMLreturn(caml_copy_string("func"));
        }
        case BTF_KIND_VAR: {
            const char *name = btf__name_by_offset(btf, t->name_off);
            if (name && strlen(name) > 0) {
                CAMLreturn(caml_copy_string(name));
            }
            CAMLreturn(caml_copy_string("var"));
        }
        case BTF_KIND_DATASEC: {
            const char *name = btf__name_by_offset(btf, t->name_off);
            if (name && strlen(name) > 0) {
                CAMLreturn(caml_copy_string(name));
            }
            CAMLreturn(caml_copy_string("datasec"));
        }
        case BTF_KIND_FLOAT:
            switch (t->size) {
                case 4: CAMLreturn(caml_copy_string("f32"));
                case 8: CAMLreturn(caml_copy_string("f64"));
                default: CAMLreturn(caml_copy_string("float"));
            }
            break;
        case BTF_KIND_DECL_TAG:
        case BTF_KIND_TYPE_TAG: {
            const char *name = btf__name_by_offset(btf, t->name_off);
            if (name && strlen(name) > 0) {
                CAMLreturn(caml_copy_string(name));
            }
            CAMLreturn(caml_copy_string("tag"));
        }
    }
    
    CAMLreturn(caml_copy_string("unknown"));
}

/* Extract kernel function signatures for kprobe targets */
value btf_extract_function_signatures_stub(value btf_handle, value function_names) {
    CAMLparam2(btf_handle, function_names);
    CAMLlocal3(result_list, current, tuple);
    
    struct btf *btf = btf_of_value(btf_handle);
    if (!btf) {
        CAMLreturn(Val_emptylist);
    }
    
    result_list = Val_emptylist;
    
    /* Convert OCaml list to C array */
    int func_count = 0;
    value temp = function_names;
    while (temp != Val_emptylist) {
        func_count++;
        temp = Field(temp, 1);
    }
    
    const char **target_functions = malloc(func_count * sizeof(const char*));
    temp = function_names;
    for (int i = 0; i < func_count; i++) {
        target_functions[i] = String_val(Field(temp, 0));
        temp = Field(temp, 1);
    }
    
    int nr_types = btf__type_cnt(btf);
    
    /* Search for function prototypes */
    for (int i = 1; i < nr_types; i++) {
        const struct btf_type *t = btf__type_by_id(btf, i);
        if (!t) continue;
        
        int kind = btf_kind(t);
        
        if (kind == BTF_KIND_FUNC) {
            const char *func_name = btf__name_by_offset(btf, t->name_off);
            if (!func_name) continue;
            
            /* Check if this is one of our target functions */
            int is_target = 0;
            for (int j = 0; j < func_count; j++) {
                if (strcmp(func_name, target_functions[j]) == 0) {
                    is_target = 1;
                    break;
                }
            }
            
            if (is_target) {
                /* Get the function prototype */
                const struct btf_type *func_proto = btf__type_by_id(btf, t->type);
                if (func_proto && btf_kind(func_proto) == BTF_KIND_FUNC_PROTO) {
                    /* Extract function signature */
                    char *signature = format_function_prototype(btf, func_proto);
                    
                    /* Create tuple (function_name, signature) */
                    tuple = caml_alloc_tuple(2);
                    Store_field(tuple, 0, caml_copy_string(func_name));
                    Store_field(tuple, 1, caml_copy_string(signature));
                    
                    /* Add to result list */
                    current = caml_alloc(2, 0);
                    Store_field(current, 0, tuple);
                    Store_field(current, 1, result_list);
                    result_list = current;
                    
                    free(signature);
                }
            }
        }
    }
    
    free(target_functions);
    CAMLreturn(result_list);
}

/* Extract all kernel-defined struct names from BTF */
value btf_extract_kernel_struct_names_stub(value btf_handle) {
    CAMLparam1(btf_handle);
    CAMLlocal2(result, cons);
    
    struct btf *btf = btf_of_value(btf_handle);
    if (!btf) {
        CAMLreturn(Val_emptylist);
    }
    
    result = Val_emptylist;
    __u32 nr_types = btf__type_cnt(btf);
    
    /* Iterate through all BTF types */
    for (__u32 i = 1; i < nr_types; i++) {
        const struct btf_type *type = btf__type_by_id(btf, i);
        if (!type) continue;
        
        /* Check if it's a struct type */
        if (btf_kind(type) == BTF_KIND_STRUCT) {
            const char *type_name = btf__name_by_offset(btf, type->name_off);
            if (type_name && strlen(type_name) > 0) {
                /* Create a new cons cell */
                cons = caml_alloc(2, 0);
                Store_field(cons, 0, caml_copy_string(type_name));
                Store_field(cons, 1, result);
                result = cons;
            }
        }
    }
    
    CAMLreturn(result);
}

/* Extract kfuncs from BTF using DECL_TAG annotations */
value btf_extract_kfuncs_stub(value btf_handle) {
    CAMLparam1(btf_handle);
    CAMLlocal3(result_list, current, tuple);
    
    struct btf *btf = btf_of_value(btf_handle);
    if (!btf) {
        CAMLreturn(Val_emptylist);
    }
    
    result_list = Val_emptylist;
    int nr_types = btf__type_cnt(btf);
    
    /* First pass: find all DECL_TAG types that reference "bpf_kfunc" */
    for (int i = 1; i < nr_types; i++) {
        const struct btf_type *t = btf__type_by_id(btf, i);
        if (!t) continue;
        
        int kind = btf_kind(t);
        
        if (kind == BTF_KIND_DECL_TAG) {
            const char *tag_name = btf__name_by_offset(btf, t->name_off);
            if (tag_name && strcmp(tag_name, "bpf_kfunc") == 0) {
                /* This is a bpf_kfunc tag, get the function it references */
                int target_id = t->type;
                const struct btf_type *target_func = btf__type_by_id(btf, target_id);
                
                if (target_func && btf_kind(target_func) == BTF_KIND_FUNC) {
                    const char *func_name = btf__name_by_offset(btf, target_func->name_off);
                    if (!func_name) continue;
                    
                    /* Get the function prototype */
                    const struct btf_type *func_proto = btf__type_by_id(btf, target_func->type);
                    if (func_proto && btf_kind(func_proto) == BTF_KIND_FUNC_PROTO) {
                        /* Extract function signature */
                        char *signature = format_function_prototype(btf, func_proto);
                        
                        /* Create tuple (function_name, signature) */
                        tuple = caml_alloc_tuple(2);
                        Store_field(tuple, 0, caml_copy_string(func_name));
                        Store_field(tuple, 1, caml_copy_string(signature));
                        
                        /* Add to result list */
                        current = caml_alloc(2, 0);
                        Store_field(current, 0, tuple);
                        Store_field(current, 1, result_list);
                        result_list = current;
                        
                        free(signature);
                    }
                }
            }
        }
    }
    
    CAMLreturn(result_list);
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