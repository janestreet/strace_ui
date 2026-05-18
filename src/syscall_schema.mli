open! Core

(** Static schema of common Linux syscalls, used to provide type information about
    arguments and return values. *)

module Arg_type : sig
  type t =
    | File_descriptor
    | Path
    | Pointer
    | Int
    | Unsigned_int
    | Size
    | Offset
    | Flags
    | String
    | Struct
    | Sockaddr
    | Buffer
    | Pid
    | Signal
    | Mode
    | Other of string
  [@@deriving sexp_of, equal]

  val is_file_descriptor : t -> bool
end

module Arg_spec : sig
  type t =
    { name : string
    ; arg_type : Arg_type.t
    }
  [@@deriving sexp_of]

  val name : t -> string
  val arg_type : t -> Arg_type.t
end

module Return_type : sig
  type t =
    | File_descriptor
    | Int
    | Ssize
    | Pointer
    | Void
    | Pid
    | Off
  [@@deriving sexp_of, equal]

  val is_file_descriptor : t -> bool
end

module Signature : sig
  type t =
    { c_signature : string
    ; args : Arg_spec.t list
    ; return_type : Return_type.t
    }
  [@@deriving sexp_of]

  val c_signature : t -> string
  val args : t -> Arg_spec.t list
  val return_type : t -> Return_type.t
end

module Syscall_info : sig
  type t =
    { name : string
    ; signatures : Signature.t list
    ; brief : string
    ; man_section : int
    }
  [@@deriving sexp_of]

  val name : t -> string
  val signatures : t -> Signature.t list
  val brief : t -> string
  val man_section : t -> int

  (** Select the best-matching signature for the given number of arguments. Falls back to
      the first signature if no exact match. *)
  val best_signature : t -> arg_count:int -> Signature.t
end

module Family : sig
  type t =
    | All
    | Desc
    | File
    | Memory
    | Network
    | Process
    | Signal
    | Ipc
  [@@deriving sexp_of, equal, compare, enumerate]

  val to_display_string : t -> string
  val includes : t -> syscall_name:string -> bool
end

val known_syscalls : Syscall_info.t String.Map.t
val lookup : string -> Syscall_info.t option
