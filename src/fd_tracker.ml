open! Core

(** A unique identity for a specific incarnation of a file descriptor. Two processes
    sharing the same inherited fd will have the same [Fd_id.t]. After close+reopen, a new
    [Fd_id.t] is created. *)
module Fd_id = struct
  module T = struct
    type t =
      { source_pid : int
      (** The pid where this fd was originally created (open/dup/etc.) *)
      ; fd_number : int (** The fd number *)
      ; generation : int
      (** Per-(source_pid, fd_number) counter. Disambiguates reuses of the same fd number
          in the same source process. *)
      }
    [@@deriving sexp_of, compare, equal]
  end

  include T
  include Comparator.Make (T)
end

(** Information about the origin of a file descriptor *)
module Fd_origin = struct
  type t =
    { syscall_index : int
    ; syscall_name : string
    ; summary : string
    }
  [@@deriving sexp_of, fields ~getters]
end

(** Map from (pid, fd_number) — used for generation counters *)
module Key = struct
  module T = struct
    type t = int * int [@@deriving sexp_of, compare]
  end

  include T
  include Comparator.Make (T)
end

type t =
  { fd_tables : Fd_id.t Int.Map.t Int.Map.t
  (** Per-process fd tables: pid → fd_number → current Fd_id. On fork, the parent's table
      is copied to the child. *)
  ; generation_counters : int Map.M(Key).t
  (** Per-(pid, fd_number) counter for generating new [Fd_id.t] values. Incremented on
      close. *)
  ; origins : Fd_origin.t Map.M(Fd_id).t
  (** Origin info for each fd incarnation. Never removed — an fd_id's origin is permanent. *)
  ; parent_pid : int Int.Map.t
  (** Map from child PID to parent PID, populated by clone/fork/vfork. *)
  }
[@@deriving sexp_of]

let empty : t =
  { fd_tables = Int.Map.empty
  ; generation_counters = Map.empty (module Key)
  ; origins = Map.empty (module Fd_id)
  ; parent_pid = Int.Map.empty
  }
;;

(** Syscalls that create new file descriptors (return value is the new fd) *)
let fd_creating_syscalls =
  String.Set.of_list
    [ "open"
    ; "openat"
    ; "socket"
    ; "accept"
    ; "accept4"
    ; "dup"
    ; "dup2"
    ; "dup3"
    ; "epoll_create"
    ; "epoll_create1"
    ; "eventfd2"
    ; "timerfd_create"
    ; "signalfd4"
    ; "inotify_init1"
    ]
;;

(** Syscalls that create fd pairs (fd numbers are in the args, not the return value) *)
let fd_pair_syscalls = String.Set.of_list [ "pipe"; "pipe2"; "socketpair" ]

(* Extract fd numbers from bracket notation like "[3, 4]" or
   "[3<pipe:[8874316]>, 4<pipe:[8874316]>]" in args_raw. Uses depth tracking to find the
   matching ']' for the outermost '[', and extract_fd_number to handle fd annotations. *)
let extract_fd_pair args_raw =
  match String.lsplit2 args_raw ~on:'[' with
  | None -> []
  | Some (_, rest) ->
    (* Find matching ']' using bracket depth *)
    let len = String.length rest in
    let rec find_close i depth =
      if i >= len
      then None
      else (
        match String.get rest i with
        | '[' -> find_close (i + 1) (depth + 1)
        | ']' when depth = 0 -> Some i
        | ']' -> find_close (i + 1) (depth - 1)
        | _ -> find_close (i + 1) depth)
    in
    (match find_close 0 0 with
     | None -> []
     | Some close_pos ->
       let inside = String.sub rest ~pos:0 ~len:close_pos in
       String.split inside ~on:','
       |> List.filter_map ~f:(fun s -> Strace_parser.extract_fd_number (String.strip s)))
;;

(** Syscalls that close file descriptors *)
let fd_closing_syscalls = String.Set.of_list [ "close" ]

(** Syscalls that create child processes (return child PID) *)
let fork_syscalls = String.Set.of_list [ "clone"; "clone3"; "fork"; "vfork" ]

let get_fd_table t ~pid = Map.find t.fd_tables pid |> Option.value ~default:Int.Map.empty

let set_fd_in_table t ~pid ~fd_number ~fd_id =
  let table = get_fd_table t ~pid in
  let table = Map.set table ~key:fd_number ~data:fd_id in
  { t with fd_tables = Map.set t.fd_tables ~key:pid ~data:table }
;;

let remove_fd_from_table t ~pid ~fd_number =
  let table = get_fd_table t ~pid in
  let table = Map.remove table fd_number in
  { t with fd_tables = Map.set t.fd_tables ~key:pid ~data:table }
;;

(** Update the FD tracker based on a parsed syscall *)
let update t (line : Strace_parser.Parsed_line.t) : t =
  let pid = Strace_parser.Parsed_line.pid line in
  let syscall_name = Strace_parser.Parsed_line.syscall_name line in
  let result = Strace_parser.Parsed_line.result line in
  let args_raw = Strace_parser.Parsed_line.args_raw line in
  let index = Strace_parser.Parsed_line.index line in
  (* Only process successful syscalls *)
  match result with
  | Strace_parser.Result.Error _ | Unfinished | Resumed _ | Signal _ | Exit _ -> t
  | Value _ ->
    if Set.mem fd_creating_syscalls syscall_name
    then (
      match Strace_parser.extract_return_int result with
      | None -> t
      | Some return_fd ->
        if return_fd < 0
        then t
        else (
          let args = Strace_parser.split_args args_raw in
          let summary =
            match syscall_name with
            | "open" | "openat" ->
              let path =
                List.find args ~f:(fun a ->
                  String.is_prefix (String.strip a) ~prefix:"\"")
                |> Option.value ~default:"<unknown>"
              in
              [%string "%{syscall_name}(%{path})"]
            | "dup" | "dup2" | "dup3" ->
              [%string "%{syscall_name}(%{args_raw}) = %{return_fd#Int}"]
            | _ -> [%string "%{syscall_name}(%{args_raw})"]
          in
          let key = pid, return_fd in
          (* If the fd slot is already occupied (e.g. dup2 implicitly closes the target),
             treat it as an implicit close: increment the generation counter. *)
          let t =
            match Map.find (get_fd_table t ~pid) return_fd with
            | None -> t
            | Some _ ->
              let current_gen =
                Map.find t.generation_counters key |> Option.value ~default:0
              in
              { t with
                generation_counters =
                  Map.set t.generation_counters ~key ~data:(current_gen + 1)
              }
          in
          let generation =
            Map.find t.generation_counters key |> Option.value ~default:0
          in
          let fd_id : Fd_id.t = { source_pid = pid; fd_number = return_fd; generation } in
          let origin = { Fd_origin.syscall_index = index; syscall_name; summary } in
          let t = set_fd_in_table t ~pid ~fd_number:return_fd ~fd_id in
          { t with origins = Map.set t.origins ~key:fd_id ~data:origin }))
    else if Set.mem fd_pair_syscalls syscall_name
    then (
      (* pipe/pipe2/socketpair: return value is 0 on success, fds are in the args *)
      match Strace_parser.extract_return_int result with
      | Some 0 ->
        let fds = extract_fd_pair args_raw in
        List.fold fds ~init:t ~f:(fun t fd_number ->
          let key = pid, fd_number in
          let t =
            match Map.find (get_fd_table t ~pid) fd_number with
            | None -> t
            | Some _ ->
              let current_gen =
                Map.find t.generation_counters key |> Option.value ~default:0
              in
              { t with
                generation_counters =
                  Map.set t.generation_counters ~key ~data:(current_gen + 1)
              }
          in
          let generation =
            Map.find t.generation_counters key |> Option.value ~default:0
          in
          let fd_id : Fd_id.t = { source_pid = pid; fd_number; generation } in
          let summary = [%string "%{syscall_name}(%{args_raw})"] in
          let origin = { Fd_origin.syscall_index = index; syscall_name; summary } in
          let t = set_fd_in_table t ~pid ~fd_number ~fd_id in
          { t with origins = Map.set t.origins ~key:fd_id ~data:origin })
      | _ -> t)
    else if Set.mem fork_syscalls syscall_name
    then (
      (* Record parent-child relationship and snapshot the parent's fd table *)
      match Strace_parser.extract_return_int result with
      | Some child_pid when child_pid > 0 ->
        let parent_table = get_fd_table t ~pid in
        (* Copy each fd from parent to child. The child inherits the same Fd_id values. *)
        let t =
          { t with
            parent_pid = Map.set t.parent_pid ~key:child_pid ~data:pid
          ; fd_tables = Map.set t.fd_tables ~key:child_pid ~data:parent_table
          }
        in
        (* Inherit the parent's generation counters so the child continues the same
           numbering. If the parent's fd 3 is at generation 6, the child's next fd 3
           (after close+reopen) will be generation 7. *)
        let t =
          Map.fold
            t.generation_counters
            ~init:t
            ~f:(fun ~key:(counter_pid, fd_number) ~data:counter t ->
              if Int.equal counter_pid pid
              then (
                let child_key = child_pid, fd_number in
                { t with
                  generation_counters =
                    Map.set t.generation_counters ~key:child_key ~data:counter
                })
              else t)
        in
        t
      | _ -> t)
    else if Set.mem fd_closing_syscalls syscall_name
    then (
      let args = Strace_parser.split_args args_raw in
      match args with
      | fd_arg :: _ ->
        (match Strace_parser.extract_fd_number fd_arg with
         | Some fd_num ->
           let key = pid, fd_num in
           let current_gen =
             Map.find t.generation_counters key |> Option.value ~default:0
           in
           let t = remove_fd_from_table t ~pid ~fd_number:fd_num in
           { t with
             generation_counters =
               Map.set t.generation_counters ~key ~data:(current_gen + 1)
           }
         | None -> t)
      | [] -> t)
    else t
;;

(** Resolve the current fd at (pid, fd_number) to its Fd_id, if any. *)
let resolve_fd t ~pid ~fd_number =
  let table = get_fd_table t ~pid in
  Map.find table fd_number
;;

(** Resolve the current fd. If the fd is not in the table and has never been tracked (no
    generation counter entry), synthesize a generation-0 Fd_id for fds that existed before
    tracing started. Returns None for fds that were previously tracked but are now closed. *)
let resolve_fd_or_default ~pid ~fd_number t =
  match resolve_fd t ~pid ~fd_number with
  | Some fd_id -> Some fd_id
  | None ->
    let key = pid, fd_number in
    if Map.mem t.generation_counters key
    then None
    else Some { Fd_id.source_pid = pid; fd_number; generation = 0 }
;;

(** Look up the origin of an fd by its Fd_id. *)
let lookup_origin t (fd_id : Fd_id.t) = Map.find t.origins fd_id

(** Look up the parent PID of a process, if known from clone/fork/vfork. *)
let parent_pid t ~pid = Map.find t.parent_pid pid

(** For backward compatibility: look up the origin of the currently open fd at (pid,
    fd_number). Returns None if the fd is not currently open. *)
let lookup t ~pid ~fd_number =
  match resolve_fd t ~pid ~fd_number with
  | None -> None
  | Some fd_id -> lookup_origin t fd_id
;;
