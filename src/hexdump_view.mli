open! Core
open Bonsai_term

(** Renders raw bytes as a colored hexdump with View.t output. *)

type theme =
  { fg : Attr.Color.t
  ; bg : Attr.Color.t
  ; dim : Attr.Color.t
  ; blue : Attr.Color.t
  ; teal : Attr.Color.t
  }

val render : ?attrs:Attr.t list -> ?bytes_per_line:int -> theme -> string -> View.t list

(** Render as plain text strings (for tests). Uses dumb terminal rendering. *)
val to_string_lines : ?bytes_per_line:int -> string -> string list
