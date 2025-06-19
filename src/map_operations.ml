(** Map Operation Semantics Module for KernelScript
    
    This module provides advanced map operation analysis including access patterns,
    concurrent access safety, method implementations, and global map sharing validation.
*)

open Ast
open Maps

(** Map access patterns for optimization and safety analysis *)
type access_pattern = 
  | Sequential of int        (* Sequential access with stride *)
  | Random                   (* Random access pattern *)
  | Hotspot of string list   (* Known hot keys *)
  | Batch of int            (* Batch operations with size *)
  | Streaming               (* Streaming access for ring buffers *)

(** Map operation context for analysis *)
type operation_context = {
  program_name: string;
  function_name: string;
  map_name: string;
  operation: map_operation;
  access_pattern: access_pattern;
  concurrent_readers: int;
  concurrent_writers: int;
  expected_frequency: int; (* operations per second *)
}

(** Concurrent access safety levels *)
type concurrency_safety =
  | Safe                    (* No safety issues *)
  | ReadSafe               (* Safe for concurrent reads only *)
  | WriteLocked            (* Requires write locking *)
  | Unsafe of string       (* Unsafe with reason *)

(** Map sharing validation results *)
type sharing_validation = {
  is_valid: bool;
  shared_programs: string list;
  conflicts: (string * string * string) list; (* prog1, prog2, reason *)
  recommendations: string list;
}

(** Map performance characteristics *)
type performance_profile = {
  lookup_complexity: string;       (* O(1), O(log n), etc. *)
  update_complexity: string;
  memory_overhead: int;            (* bytes per entry *)
  cache_efficiency: float;         (* 0.0 to 1.0 *)
  scale_limit: int;               (* maximum efficient entries *)
}

(** Map operation validation result *)
type operation_validation = {
  is_valid: bool;
  safety_level: concurrency_safety;
  performance: performance_profile;
  warnings: string list;
  optimizations: string list;
}

(** Map method implementation details *)
type method_implementation = {
  method_name: string;
  supported_types: ebpf_map_type list;
  parameters: (string * bpf_type) list;
  return_type: bpf_type option;
  ebpf_helper: string option;      (* eBPF helper function *)
  complexity: string;              (* Time complexity *)
  side_effects: string list;       (* Documented side effects *)
}

(** Utility functions *)

let string_of_map_operation = function
  | MapLookup -> "lookup"
  | MapUpdate -> "update"
  | MapDelete -> "delete"
  | MapInsert -> "insert"
  | MapUpsert -> "upsert"

let string_of_map_type = function
  | HashMap -> "HashMap"
  | Array -> "Array"
  | PercpuHash -> "PercpuHash"
  | PercpuArray -> "PercpuArray"
  | LruHash -> "LruHash"
  | LruPercpuHash -> "LruPercpuHash"
  | RingBuffer -> "RingBuffer"
  | PerfEvent -> "PerfEvent"
  | ProgArray -> "ProgArray"
  | CgroupArray -> "CgroupArray"
  | StackTrace -> "StackTrace"
  | DevMap -> "DevMap"
  | SockMap -> "SockMap"
  | CpuMap -> "CpuMap"
  | XskMap -> "XskMap"
  | SockHash -> "SockHash"
  | ReusePortSockArray -> "ReusePortSockArray"

(** eBPF map helper functions and their characteristics *)
module EbpfHelpers = struct
  let map_lookup_elem = {
    method_name = "lookup";
    supported_types = [HashMap; Array; PercpuHash; PercpuArray; LruHash; LruPercpuHash];
    parameters = [("key", Pointer U8)];
    return_type = Some (Pointer U8);
    ebpf_helper = Some "bpf_map_lookup_elem";
    complexity = "O(1) for hash maps, O(1) for arrays";
    side_effects = [];
  }
  
  let map_update_elem = {
    method_name = "update";
    supported_types = [HashMap; Array; PercpuHash; PercpuArray; LruHash; LruPercpuHash];
    parameters = [("key", Pointer U8); ("value", Pointer U8); ("flags", U64)];
    return_type = Some I32;
    ebpf_helper = Some "bpf_map_update_elem";
    complexity = "O(1) for hash maps, O(1) for arrays";
    side_effects = ["May evict LRU entries"; "Updates existing or creates new entry"];
  }
  
  let map_delete_elem = {
    method_name = "delete";
    supported_types = [HashMap; PercpuHash; LruHash; LruPercpuHash];
    parameters = [("key", Pointer U8)];
    return_type = Some I32;
    ebpf_helper = Some "bpf_map_delete_elem";
    complexity = "O(1) for hash maps";
    side_effects = ["Removes entry permanently"];
  }
  
  let ringbuf_output = {
    method_name = "output";
    supported_types = [RingBuffer];
    parameters = [("data", Pointer U8); ("size", U32); ("flags", U64)];
    return_type = Some I32;
    ebpf_helper = Some "bpf_ringbuf_output";
    complexity = "O(1)";
    side_effects = ["May block if ring buffer is full"];
  }
  
  let perf_event_output = {
    method_name = "output";
    supported_types = [PerfEvent];
    parameters = [("ctx", Pointer U8); ("data", Pointer U8); ("size", U32)];
    return_type = Some I32;
    ebpf_helper = Some "bpf_perf_event_output";
    complexity = "O(1)";
    side_effects = ["Sends event to userspace"];
  }
  
  let all_methods = [map_lookup_elem; map_update_elem; map_delete_elem; ringbuf_output; perf_event_output]
end

(** Performance characteristics for different map types *)
module PerformanceProfiles = struct
  let hash_map = {
    lookup_complexity = "O(1) average, O(n) worst case";
    update_complexity = "O(1) average, O(n) worst case";
    memory_overhead = 32; (* bytes per entry overhead *)
    cache_efficiency = 0.8;
    scale_limit = 1000000;
  }
  
  let array_map = {
    lookup_complexity = "O(1)";
    update_complexity = "O(1)";
    memory_overhead = 8;
    cache_efficiency = 0.95;
    scale_limit = 65536; (* Limited by index size *)
  }
  
  let lru_hash = {
    lookup_complexity = "O(1) average";
    update_complexity = "O(1) average";
    memory_overhead = 40; (* Additional overhead for LRU tracking *)
    cache_efficiency = 0.9; (* Better due to LRU eviction *)
    scale_limit = 500000;
  }
  
  let ring_buffer = {
    lookup_complexity = "N/A";
    update_complexity = "O(1)";
    memory_overhead = 16;
    cache_efficiency = 0.85;
    scale_limit = 2097152; (* 2MB typical limit *)
  }
  
  let perf_event = {
    lookup_complexity = "N/A";
    update_complexity = "O(1)";
    memory_overhead = 24;
    cache_efficiency = 0.7; (* Lower due to userspace communication *)
    scale_limit = 1000000;
  }
  
  let get_profile = function
    | HashMap | PercpuHash -> hash_map
    | Array | PercpuArray -> array_map
    | LruHash | LruPercpuHash -> lru_hash
    | RingBuffer -> ring_buffer
    | PerfEvent -> perf_event
    | _ -> hash_map (* Default fallback *)
end

(** Access pattern analysis *)

(** Analyze access pattern from expressions *)
let analyze_access_pattern map_name expressions =
  let access_count = ref 0 in
  let sequential_accesses = ref [] in
  let random_accesses = ref 0 in
  
  let rec analyze_expr expr =
    match expr.expr_desc with
    | ArrayAccess (arr_expr, idx_expr) when arr_expr.expr_desc = Identifier map_name ->
        incr access_count;
        (match idx_expr.expr_desc with
         | Literal (IntLit (idx, _)) -> 
             sequential_accesses := idx :: !sequential_accesses
         | _ -> incr random_accesses)
    | FunctionCall (name, _) when String.contains name '.' ->
        let parts = String.split_on_char '.' name in
        (match parts with
         | [mn; _] when mn = map_name -> incr access_count
         | _ -> ())
    | FunctionCall (_, args) -> List.iter analyze_expr args
    | BinaryOp (left, _, right) -> analyze_expr left; analyze_expr right
    | UnaryOp (_, e) -> analyze_expr e
    | _ -> ()
  in
  
  List.iter analyze_expr expressions;
  
  let total_accesses = !access_count in
  let seq_accesses = List.rev !sequential_accesses in
  let rand_accesses = !random_accesses in
  
  if total_accesses = 0 then Random
  else if total_accesses > 10 then Batch total_accesses
  else if rand_accesses = 0 && List.length seq_accesses > 1 then
    (* Check if sequential *)
    let rec check_stride acc = function
      | x1 :: x2 :: rest -> 
          let stride = x2 - x1 in
          if acc = None then check_stride (Some stride) (x2 :: rest)
          else if acc = Some stride then check_stride acc (x2 :: rest)
          else Random
      | _ -> match acc with Some s -> Sequential s | None -> Random
    in
    check_stride None seq_accesses
  else Random

(** Concurrent access safety analysis *)

(** Check concurrent access safety for a map operation *)
let analyze_concurrent_safety map_type operation readers writers =
  match map_type, operation with
  | (HashMap | PercpuHash | LruHash | LruPercpuHash), MapLookup ->
      if writers = 0 then Safe
      else if writers = 1 then ReadSafe
      else WriteLocked
  | (HashMap | PercpuHash | LruHash | LruPercpuHash), (MapUpdate | MapInsert | MapUpsert) ->
      if readers = 0 && writers <= 1 then Safe
      else if readers > 0 || writers > 1 then WriteLocked
      else Safe
  | (HashMap | PercpuHash | LruHash | LruPercpuHash), MapDelete ->
      if readers = 0 && writers <= 1 then Safe
      else WriteLocked
  | (Array | PercpuArray), MapLookup ->
      if writers = 0 then Safe
      else ReadSafe
  | (Array | PercpuArray), (MapUpdate | MapUpsert) ->
      if readers = 0 && writers <= 1 then Safe
      else WriteLocked
  | (Array | PercpuArray), (MapInsert | MapDelete) ->
      Unsafe "Arrays do not support insert/delete operations"
  | RingBuffer, _ ->
      if writers <= 1 then Safe
      else WriteLocked
  | PerfEvent, _ ->
      Safe (* Per-CPU event buffers *)
  | _ ->
      Unsafe "Unknown map type or operation combination"

(** Global map sharing validation *)

(** Validate global map sharing across programs *)
let validate_global_sharing _map_name map_type programs_using_map =
  let conflicts = ref [] in
  let recommendations = ref [] in
  
  (* Check for conflicting access patterns *)
  let writers = List.filter (fun (_prog_name, ops) ->
    List.exists (function MapUpdate | MapInsert | MapDelete | MapUpsert -> true | _ -> false) ops
  ) programs_using_map in
  
  let _readers = List.filter (fun (_prog_name, ops) ->
    List.exists (function MapLookup -> true | _ -> false) ops
  ) programs_using_map in
  
  (* Detect write-write conflicts *)
  (match writers with
   | [] -> () (* No writers, no conflicts *)
   | [_] -> () (* Single writer is safe *)
   | (p1, _) :: (p2, _) :: _ ->
       conflicts := (p1, p2, "Multiple programs writing to shared map") :: !conflicts;
       recommendations := "Consider using per-CPU maps or synchronization" :: !recommendations);
  
  (* Check map type suitability for sharing *)
  (match map_type with
   | PercpuHash | PercpuArray ->
       recommendations := "Per-CPU maps provide better isolation for shared access" :: !recommendations
   | HashMap | Array when List.length programs_using_map > 2 ->
       recommendations := "Consider LRU maps for better memory management with multiple programs" :: !recommendations
   | RingBuffer when List.length writers > 1 ->
       conflicts := ("multiple", "programs", "Ring buffers should have single writer") :: !conflicts
   | _ -> ());
  
  {
    is_valid = !conflicts = [];
    shared_programs = List.map fst programs_using_map;
    conflicts = !conflicts;
    recommendations = !recommendations;
  }

(** Map operation validation *)

(** Validate a specific map operation *)
let validate_operation context =
  let warnings = ref [] in
  let optimizations = ref [] in
  
  (* Analyze performance implications first to determine map type *)
  let determine_map_type name =
    let name_lower = String.lowercase_ascii name in
    
    (* Helper function for clean substring checking *)
    let contains_substring haystack needle =
      let hay_len = String.length haystack in
      let needle_len = String.length needle in
      let rec search_at pos =
        if pos + needle_len > hay_len then false
        else if String.sub haystack pos needle_len = needle then true
        else search_at (pos + 1)
      in
      if needle_len = 0 then true
      else if hay_len < needle_len then false
      else search_at 0
    in
    
    (* Pattern matching with priority order - most specific first *)
    if contains_substring name_lower "percpu_hash" then PercpuHash
    else if contains_substring name_lower "percpu_array" then PercpuArray
    else if contains_substring name_lower "lru_percpu" then LruPercpuHash
    else if contains_substring name_lower "lru_hash" then LruHash
    else if contains_substring name_lower "ring_buffer" then RingBuffer
    else if contains_substring name_lower "perf_event" then PerfEvent
    else if contains_substring name_lower "hash_map" then HashMap
    else if contains_substring name_lower "array_map" then Array
    (* Fallback to partial matches *)
    else if contains_substring name_lower "percpu" then PercpuHash
    else if contains_substring name_lower "lru" then LruHash
    else if contains_substring name_lower "hash" then HashMap
    else if contains_substring name_lower "array" then Array
    else if contains_substring name_lower "ring" || contains_substring name_lower "buffer" then RingBuffer
    else if contains_substring name_lower "perf" || contains_substring name_lower "event" then PerfEvent
    else HashMap (* Default fallback *)
  in
  let map_type = determine_map_type context.map_name in

  (* Check if operation is supported for map type *)
  let method_impl = List.find_opt (fun impl -> 
    impl.method_name = string_of_map_operation context.operation &&
    List.mem map_type impl.supported_types
  ) EbpfHelpers.all_methods in
  
  let is_valid = match method_impl with
    | Some _ -> true
    | None -> 
        (* For basic operations, assume they're supported if they make sense *)
        match map_type, context.operation with
        | (HashMap | PercpuHash | LruHash | LruPercpuHash), (MapLookup | MapUpdate | MapInsert | MapUpsert | MapDelete) -> true
        | (Array | PercpuArray), (MapLookup | MapUpdate | MapUpsert) -> true
        | (Array | PercpuArray), (MapInsert | MapDelete) -> 
            warnings := "Arrays do not support insert/delete operations" :: !warnings;
            false
        | RingBuffer, _ -> true
        | PerfEvent, _ -> true
        | _ ->
            warnings := (Printf.sprintf "Operation %s not supported for map type %s" 
                        (string_of_map_operation context.operation) (string_of_map_type map_type)) :: !warnings;
            false
  in
  
  let performance = PerformanceProfiles.get_profile map_type in
  
  (* Check frequency vs performance *)
  if context.expected_frequency > 100000 then (
    warnings := "High frequency access detected - consider caching" :: !warnings;
    if map_type = HashMap then
      optimizations := "Consider LRU hash map for better cache performance" :: !optimizations
  );
  
  (* Check access pattern optimization *)
  (match context.access_pattern with
   | Sequential stride when stride = 1 && map_type <> Array ->
       optimizations := "Sequential access detected - array map might be more efficient" :: !optimizations
   | Random when map_type = Array ->
       warnings := "Random access on array map may cause poor performance" :: !warnings
   | Batch size when size > 100 ->
       optimizations := "Batch operations detected - consider batch helper functions" :: !optimizations
   | _ -> ());
  
  (* Analyze concurrency safety *)
  let safety_level = analyze_concurrent_safety map_type context.operation 
                      context.concurrent_readers context.concurrent_writers in
  
  (match safety_level with
   | Unsafe reason -> warnings := reason :: !warnings
   | WriteLocked -> warnings := "Concurrent access requires synchronization" :: !warnings
   | _ -> ());
  
  {
    is_valid = is_valid;
    safety_level = safety_level;
    performance = performance;
    warnings = !warnings;
    optimizations = !optimizations;
  }

(** Method implementation lookup and validation *)

(** Get method implementation for a map type and operation *)
let get_method_implementation map_type operation_name =
  List.find_opt (fun impl ->
    impl.method_name = operation_name &&
    List.mem map_type impl.supported_types
  ) EbpfHelpers.all_methods

(** Validate method call against implementation *)
let validate_method_call map_type method_name args =
  match get_method_implementation map_type method_name with
  | None -> 
      Error (Printf.sprintf "Method %s not supported for map type %s" 
             method_name (string_of_map_type map_type))
  | Some impl ->
      (* Check parameter count *)
      if List.length args != List.length impl.parameters then
        Error (Printf.sprintf "Method %s expects %d arguments, got %d"
               method_name (List.length impl.parameters) (List.length args))
      else
        Ok impl

(** Optimization recommendations *)

(** Generate optimization recommendations for map usage *)
let generate_optimizations operations =
  let optimizations = ref [] in
  
  (* Analyze operation patterns *)
  let lookup_count = List.length (List.filter (function (_, MapLookup) -> true | _ -> false) operations) in
  let update_count = List.length (List.filter (function (_, MapUpdate) -> true | _ -> false) operations) in
  let total_ops = List.length operations in
  
  if lookup_count > update_count * 10 then
    optimizations := "High read-to-write ratio - consider read-optimized data structures" :: !optimizations;
  
  if total_ops > 1000 then
    optimizations := "High operation count - consider batch processing" :: !optimizations;
  
  (* Check for map type recommendations *)
  let has_deletes = List.exists (function (_, MapDelete) -> true | _ -> false) operations in
  if not has_deletes then
    optimizations := "No delete operations - array maps might be more efficient" :: !optimizations;
  
  !optimizations

(** Pretty printing and debug functions *)

let string_of_access_pattern = function
  | Sequential stride -> Printf.sprintf "Sequential(stride=%d)" stride
  | Random -> "Random"
  | Hotspot keys -> Printf.sprintf "Hotspot(%s)" (String.concat "," keys)
  | Batch size -> Printf.sprintf "Batch(size=%d)" size
  | Streaming -> "Streaming"

let string_of_concurrency_safety = function
  | Safe -> "Safe"
  | ReadSafe -> "ReadSafe"
  | WriteLocked -> "WriteLocked"
  | Unsafe reason -> Printf.sprintf "Unsafe(%s)" reason

let string_of_operation_context ctx =
  Printf.sprintf "Context{prog=%s, func=%s, map=%s, op=%s, pattern=%s, readers=%d, writers=%d}"
    ctx.program_name ctx.function_name ctx.map_name
    (string_of_map_operation ctx.operation)
    (string_of_access_pattern ctx.access_pattern)
    ctx.concurrent_readers ctx.concurrent_writers

let string_of_sharing_validation (sharing_validation : sharing_validation) =
  Printf.sprintf "Sharing{valid=%b, programs=[%s], conflicts=%d, recommendations=%d}"
    sharing_validation.is_valid
    (String.concat ";" sharing_validation.shared_programs)
    (List.length sharing_validation.conflicts)
    (List.length sharing_validation.recommendations)

let string_of_operation_validation (operation_validation : operation_validation) =
  Printf.sprintf "Validation{valid=%b, safety=%s, warnings=%d, optimizations=%d}"
    operation_validation.is_valid
    (string_of_concurrency_safety operation_validation.safety_level)
    (List.length operation_validation.warnings)
    (List.length operation_validation.optimizations)

(** Debug output functions *)

let print_operation_context ctx =
  print_endline (string_of_operation_context ctx)

let print_sharing_validation sharing_validation =
  print_endline (string_of_sharing_validation sharing_validation);
  if sharing_validation.conflicts <> [] then (
    Printf.printf "Conflicts:\n";
    List.iter (fun (p1, p2, reason) ->
      Printf.printf "  %s <-> %s: %s\n" p1 p2 reason
    ) sharing_validation.conflicts
  );
  if sharing_validation.recommendations <> [] then (
    Printf.printf "Recommendations:\n";
    List.iter (fun recommendation ->
      Printf.printf "  - %s\n" recommendation
    ) sharing_validation.recommendations
  )

let print_operation_validation operation_validation =
  print_endline (string_of_operation_validation operation_validation);
  if operation_validation.warnings <> [] then (
    Printf.printf "Warnings:\n";
    List.iter (fun warning ->
      Printf.printf "  - %s\n" warning
    ) operation_validation.warnings
  );
  if operation_validation.optimizations <> [] then (
    Printf.printf "Optimizations:\n";
    List.iter (fun opt ->
      Printf.printf "  - %s\n" opt
    ) operation_validation.optimizations
  ) 