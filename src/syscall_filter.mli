open! Core

(** Filter expressions for syscalls.

    A filter is a list of terms:
    - [%desc], [%file], etc. include a family
    - [read], [+read] include a specific syscall
    - [-read], [!read] exclude a specific syscall

    If there are no inclusions, all syscalls pass (minus exclusions). If there are any
    inclusions, only those pass (minus exclusions). *)

type t [@@deriving sexp_of, equal]

val empty : t
val is_empty : t -> bool
val to_normalized_string : t -> string
val to_display_string : t -> string
val parse : string -> t

(** Parse a filter string, removing empty regexes and normalizing whitespace, then
    re-serialize to a canonical string. Useful for cleaning up the input on submit. *)
val normalize : string -> string

val add_exclusion : t -> syscall_name:string -> t
val add_inclusion : t -> syscall_name:string -> t
val add_pid_filter : t -> pid:int -> t
val add_pid_exclusion : t -> pid:int -> t

module Syscall_info : sig
  type t =
    { syscall_name : string
    ; pid : int
    ; fd_ids : Fd_tracker.Fd_id.t list
    ; raw_line : string
    }
end

val passes : t -> Syscall_info.t -> fd_tracker:Fd_tracker.t -> bool
