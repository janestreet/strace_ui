open! Core

(** Tracks file descriptors and their origin syscalls across processes.

    Each fd incarnation is represented by an [Fd_id.t] that uniquely identifies the
    specific open/dup/etc. that created it. When a process forks, the child's fd table is
    snapshotted from the parent, so both share the same [Fd_id.t] values for inherited
    fds. After close+reopen, a new [Fd_id.t] is created. This means generation tracking
    and cross-process inheritance are handled structurally, not via lazy parent-chain
    walking. *)

module Fd_id : sig
  type t =
    { source_pid : int
    ; fd_number : int
    ; generation : int
    }
  [@@deriving sexp_of, compare, equal]

  include Comparator.S with type t := t
end

module Fd_origin : sig
  type t =
    { syscall_index : int
    ; syscall_name : string
    ; summary : string
    }
  [@@deriving sexp_of]

  val syscall_index : t -> int
  val syscall_name : t -> string
  val summary : t -> string
end

type t [@@deriving sexp_of]

val empty : t

(** Update the tracker based on a parsed syscall. On fork/clone, the parent's fd table is
    snapshotted into the child so both share the same [Fd_id.t] values. *)
val update : t -> Strace_parser.Parsed_line.t -> t

(** Resolve the current fd at (pid, fd_number) to its [Fd_id.t], if any. Returns [None] if
    the fd is not currently open in that process. *)
val resolve_fd : t -> pid:int -> fd_number:int -> Fd_id.t option

(** Like [resolve_fd], but synthesizes a generation-0 [Fd_id.t] for fds that have never
    been tracked (existed before tracing started). Returns [None] for fds that were
    previously tracked but are now closed. *)
val resolve_fd_or_default : pid:int -> fd_number:int -> t -> Fd_id.t option

(** Look up the origin of an fd by its [Fd_id.t]. Origins are permanent — they persist
    even after the fd is closed. *)
val lookup_origin : t -> Fd_id.t -> Fd_origin.t option

(** Look up the parent PID of a process, if known from clone/fork/vfork. *)
val parent_pid : t -> pid:int -> int option

(** Look up the origin of the currently open fd at (pid, fd_number). Returns [None] if the
    fd is not currently open. Convenience function that combines [resolve_fd] and
    [lookup_origin]. *)
val lookup : t -> pid:int -> fd_number:int -> Fd_origin.t option
