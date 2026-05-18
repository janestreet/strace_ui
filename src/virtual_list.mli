open! Core

(** A virtualized, filtered, scrollable list component.

    Items are stored in a mutable [Vec.t] for efficient append. A separate filtered index
    vec tracks which items pass the current filter. The visible viewport is centered on
    the selected item, and only the visible range is rendered. *)

module Box : sig
  (** An immutable box wrapping a mutable value. Creating a new box on mutation defeats
      Bonsai's phys_equal cutoff. *)
  type 'a t [@@deriving sexp_of]

  val create : 'a -> 'a t
end

module Action : sig
  type t =
    | Select_up
    | Select_down
    | Select_top
    | Select_bottom
    | Jump_to_filtered_index of int
  [@@deriving sexp_of]
end

module State : sig
  type 'a t [@@deriving sexp_of]

  val create : unit -> 'a t
  val total_count : _ t -> int
  val filtered_count : _ t -> int
  val selected_index : _ t -> int
  val get_filtered : 'a t -> int -> 'a option
  val get_raw : 'a t -> int -> 'a
  val get_selected : 'a t -> 'a option

  (** Append an item. [passes_filter] indicates whether it should appear in the filtered
      view. *)
  val append : 'a t -> 'a -> passes_filter:bool -> 'a t

  (** Update an item at the given raw index (in all_items) and return a new state that
      will trigger re-render. *)
  val set_item : 'a t -> int -> 'a -> 'a t

  (** Rebuild the filtered indices using a new predicate. Preserves the selection as
      closely as possible by scanning backward from the previously selected raw index to
      find the nearest matching line. *)
  val refilter : 'a t -> passes_filter:('a -> bool) -> 'a t

  val apply_action : 'a t -> Action.t -> 'a t
end

(** Render the visible portion of the list centered on the selection. *)
val render
  :  state:'a State.t
  -> viewport_height:int
  -> viewport_width:int
  -> render_item:(is_selected:bool -> width:int -> 'a -> Bonsai_term.View.t)
  -> render_empty:(width:int -> Bonsai_term.View.t)
  -> Bonsai_term.View.t
