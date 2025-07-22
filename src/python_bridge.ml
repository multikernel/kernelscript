(*
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
 *)

(** Python FFI Bridge
    
    This module provides a generic Python bridge for calling any Python function
    from KernelScript userspace code, without static analysis of Python files.
*)

open Printf

(** Generate generic Python module interface *)
let generate_module_interface module_name =
  sprintf {|
// Generic Python module interface for %s
static PyObject* %s_module = NULL;

// Generic function call interface
PyObject* %s_call_function(const char* func_name, PyObject* args) {
    if (!%s_module) {
        PyErr_SetString(PyExc_RuntimeError, "Module %s not initialized");
        return NULL;
    }
    
    PyObject* py_func = PyObject_GetAttrString(%s_module, func_name);
    if (!py_func || !PyCallable_Check(py_func)) {
        PyErr_Format(PyExc_AttributeError, "Function %%s not found or not callable in module %s", func_name);
        Py_XDECREF(py_func);
        return NULL;
    }
    
    PyObject* result = PyObject_CallObject(py_func, args);
    Py_DECREF(py_func);
    return result;
}|} module_name module_name module_name module_name module_name module_name module_name

(** Generate module initialization *)
let generate_module_init module_name python_file_path =
  sprintf {|
// Initialize Python module: %s from %s
int init_%s_bridge(void) {
    if (!Py_IsInitialized()) {
        Py_Initialize();
        if (!Py_IsInitialized()) {
            fprintf(stderr, "Failed to initialize Python interpreter\n");
            return -1;
        }
    }
    
    // Add current directory to Python path for relative imports
    PyRun_SimpleString("import sys; sys.path.insert(0, '.')");
    
    // Import the module
    PyObject* module_name = PyUnicode_DecodeFSDefault("%s");
    if (!module_name) {
        fprintf(stderr, "Failed to create module name string\n");
        return -1;
    }
    
    %s_module = PyImport_Import(module_name);
    Py_DECREF(module_name);
    
    if (!%s_module) {
        PyErr_Print();
        fprintf(stderr, "Failed to import Python module: %s\n");
        return -1;
    }
    
    printf("Successfully initialized Python bridge for module: %s\n");
    return 0;
}

// Cleanup Python module: %s
void cleanup_%s_bridge(void) {
    if (%s_module) {
        Py_DECREF(%s_module);
        %s_module = NULL;
    }
}|} module_name python_file_path module_name 
    (Filename.remove_extension (Filename.basename python_file_path))
    module_name module_name python_file_path module_name
    module_name module_name module_name module_name module_name

(** Generate complete Python bridge C file *)
let generate_python_bridge module_name python_file_path =
  let headers = {|#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>|} in
  
  let module_interface = generate_module_interface module_name in
  let module_init = generate_module_init module_name python_file_path in
  
  sprintf {|%s

%s

%s
|} headers module_interface module_init

(** Generate header file for Python bridge *)
let generate_python_bridge_header module_name =
  let header_guard = String.uppercase_ascii module_name ^ "_BRIDGE_H" in
  
  sprintf {|#ifndef %s
#define %s

#include <Python.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize/cleanup Python bridge for module: %s
int init_%s_bridge(void);
void cleanup_%s_bridge(void);

// Generic function call interface
PyObject* %s_call_function(const char* func_name, PyObject* args);

#ifdef __cplusplus
}
#endif

#endif // %s|} header_guard header_guard module_name module_name module_name module_name header_guard

(** Generate basic module info for imports *)
let get_module_info module_name python_file_path =
  {|
Module: |} ^ module_name ^ {|
File: |} ^ python_file_path ^ {|
Type: Generic Python Bridge (no static analysis)
|} 