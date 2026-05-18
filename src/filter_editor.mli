open! Core

(** State and actions for the inline filter text editor. *)

module Action : sig
  type t =
    | Start
    | Start_regex
    | Key of char
    | Backspace
    | Delete_forward
    | Move_left
    | Move_right
    | Move_to_start
    | Move_to_end
    | Kill_to_end
    | Kill_to_start
    | Kill_word_backward
    | Move_word_forward
    | Move_word_backward
    | Submit
    | Cancel
  [@@deriving sexp_of]
end

type t [@@deriving sexp_of]

val empty : t
val is_editing : t -> bool
val editing_buffer : t -> string option

module Render_params : sig
  type t =
    { key_hint_color : Bonsai_term.Attr.Color.t
    ; title_color : Bonsai_term.Attr.Color.t
    ; fg_color : Bonsai_term.Attr.Color.t
    ; accent_color : Bonsai_term.Attr.Color.t
    ; bg_color : Bonsai_term.Attr.Color.t
    ; max_chars : int
    }
end

(** Render the filter label for the box title bar. *)
val render_label
  :  t
  -> current_filter:Syscall_filter.t
  -> params:Render_params.t
  -> Bonsai_term.View.t

(** Apply an action. Returns [(new_state, submitted_filter)] where [submitted_filter] is
    [Some filter_string] if the user pressed Enter. *)
val apply_action : t -> current_filter:Syscall_filter.t -> Action.t -> t * string option
