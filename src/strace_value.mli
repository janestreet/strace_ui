open! Core

(** Parsed representation of strace value syntax. Strace outputs structured values like
    [{sa_family=AF_INET, sin_port=htons(0)}] which we parse into a tree for display in the
    detail pane. *)

type t =
  | Atom of string
  | String of string
  | Struct of (string * t) list
  | Array of t list
  | Call of string * string
[@@deriving sexp_of]

val is_struct_or_array : t -> bool

(** Parse a strace value string into a tree. *)
val parse : string -> t

(** Generic tree fold. Walks the tree structure and calls back for each element to emit.
    The [~render_prefix_with_multi] callback handles multi-line string values (e.g.
    hexdumps) where the first line is placed inline with the prefix. *)
val fold_tree
  :  t
  -> emit:('a -> unit)
  -> render_atom:(indent:string -> string -> 'a)
  -> render_string:(string -> 'a list)
  -> render_call:(indent:string -> string -> string -> 'a)
  -> render_prefix:(indent:string -> string -> string -> 'a)
  -> render_prefix_with_value:(indent:string -> string -> string -> string -> 'a)
  -> render_prefix_with_multi:
       (emit:('a -> unit)
        -> indent:string
        -> child_indent:string
        -> string
        -> string
        -> 'a list
        -> unit)
  -> unit

(** Render as expectree-like lines. [render_string] controls how quoted strings are
    displayed (e.g. for hexdump mode). It returns a list of lines; the first line is
    placed inline and subsequent lines are indented below. *)
val to_lines : ?render_string:(string -> string list) -> t -> string list
