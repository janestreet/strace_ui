open! Core

(** Parser for strace output lines.

    Expects strace to be run with [-ttt -f] for timestamps and PIDs. *)

module Result : sig
  type t =
    | Value of string
    | Error of
        { errno : string
        ; description : string
        }
    | Unfinished
    | Resumed of t
    | Signal of string
    | Exit of string
  [@@deriving sexp_of]
end

module Parsed_line : sig
  type t =
    { index : int
    ; pid : int
    ; timestamp : float
    ; syscall_name : string
    ; args_raw : string
    ; result : Result.t
    ; duration : float option
    ; raw_line : string
    }
  [@@deriving sexp_of]

  val index : t -> int
  val pid : t -> int
  val timestamp : t -> float
  val syscall_name : t -> string
  val args_raw : t -> string
  val result : t -> Result.t
  val duration : t -> float option
  val raw_line : t -> string
end

val parse_line : index:int -> string -> Parsed_line.t option

(** Merge an unfinished syscall with its resumed completion. Concatenates args, takes the
    result/duration from [resumed], and joins raw lines. *)
val merge_resumed : original:Parsed_line.t -> resumed:Parsed_line.t -> Parsed_line.t

(** Split the raw argument string from strace into individual arguments, handling nested
    structures and quoted strings. *)
val split_args : string -> string list

(** Try to extract a numeric file descriptor from an strace argument value. Returns [None]
    for special values like AT_FDCWD. *)
val extract_fd_number : string -> int option

(** Extract the return value as an integer, if possible. *)
val extract_return_int : Result.t -> int option
