open! Core

(** A box that wraps a mutable value, creating a new box on each mutation to defeat
    Bonsai's phys_equal cutoff. *)
module Box = struct
  type 'a t = { mutable t : 'a } [@@deriving sexp_of]

  let create x = { t = x }
end

module Action = struct
  type t =
    | Select_up
    | Select_down
    | Select_top
    | Select_bottom
    | Jump_to_filtered_index of int
  [@@deriving sexp_of]
end

(** The state of a virtual list. ['a] is the item type. *)
module State = struct
  type 'a t =
    { all_items : 'a Vec.t Box.t
    ; filtered_indices : int Vec.t Box.t
    ; selected_index : int
    }
  [@@deriving sexp_of]

  let create () =
    { all_items = Box.create (Vec.create ())
    ; filtered_indices = Box.create (Vec.create ())
    ; selected_index = 0
    }
  ;;

  let total_count t = Vec.length t.all_items.t
  let filtered_count t = Vec.length t.filtered_indices.t
  let selected_index t = t.selected_index

  let get_filtered t i =
    if i >= 0 && i < filtered_count t
    then Some (Vec.get t.all_items.t (Vec.get t.filtered_indices.t i))
    else None
  ;;

  let get_raw t i = Vec.get t.all_items.t i
  let get_selected t = get_filtered t t.selected_index

  (** Append an item. If it passes the filter, add it to the filtered list. *)
  let append t item ~passes_filter =
    let all = t.all_items.t in
    Vec.push_back all item;
    let all_items = Box.create all in
    let filtered_indices =
      if passes_filter
      then (
        let indices = t.filtered_indices.t in
        Vec.push_back indices (Vec.length all - 1);
        Box.create indices)
      else t.filtered_indices
    in
    let fc = Vec.length filtered_indices.t in
    { all_items
    ; filtered_indices
    ; selected_index = Int.min t.selected_index (Int.max 0 (fc - 1))
    }
  ;;

  let set_item t idx item =
    Vec.set t.all_items.t idx item;
    { t with all_items = Box.create t.all_items.t }
  ;;

  (** The raw index of the currently selected item, or [None] if nothing is selected. *)
  let selected_raw_index t =
    let fi = t.filtered_indices.t in
    if t.selected_index >= 0 && t.selected_index < Vec.length fi
    then Some (Vec.get fi t.selected_index)
    else None
  ;;

  (** Rebuild filtered indices from scratch using the given predicate. Preserves the
      selection as closely as possible: scans backward from the previously selected raw
      index to find the nearest matching line. *)
  let refilter t ~passes_filter =
    let prev_raw = selected_raw_index t in
    let all = t.all_items.t in
    let indices = Vec.create () in
    for i = 0 to Vec.length all - 1 do
      let item = Vec.get all i in
      if passes_filter item then Vec.push_back indices i
    done;
    let selected_index =
      match prev_raw with
      | None -> 0
      | Some prev_raw ->
        (* Find the highest filtered index whose raw index is <= prev_raw. This is the
           line at or just before our old selection that passes the new filter. *)
        let best = ref 0 in
        let len = Vec.length indices in
        for i = 0 to len - 1 do
          if Vec.get indices i <= prev_raw then best := i
        done;
        Int.min !best (Int.max 0 (len - 1))
    in
    { t with filtered_indices = Box.create indices; selected_index }
  ;;

  let apply_action t (action : Action.t) =
    match action with
    | Select_up -> { t with selected_index = Int.max 0 (t.selected_index - 1) }
    | Select_down ->
      { t with selected_index = Int.min (filtered_count t - 1) (t.selected_index + 1) }
    | Select_top -> { t with selected_index = 0 }
    | Select_bottom -> { t with selected_index = Int.max 0 (filtered_count t - 1) }
    | Jump_to_filtered_index idx ->
      { t with selected_index = Int.max 0 (Int.min (filtered_count t - 1) idx) }
  ;;
end

(** Render the visible portion of the list, centered on the selected index.
    [render_item ~is_selected ~width item] produces one row of output. *)
let render
  ~(state : _ State.t)
  ~viewport_height
  ~viewport_width
  ~render_item
  ~render_empty
  =
  let fc = State.filtered_count state in
  if fc = 0
  then render_empty ~width:viewport_width
  else (
    let half = viewport_height / 2 in
    let scroll_offset =
      Int.max 0 (Int.min (state.selected_index - half) (fc - viewport_height))
    in
    let visible_end = Int.min fc (scroll_offset + viewport_height) in
    Bonsai_term.View.vcat
      (List.init (visible_end - scroll_offset) ~f:(fun vi ->
         let i = scroll_offset + vi in
         let item = Vec.get state.all_items.t (Vec.get state.filtered_indices.t i) in
         render_item ~is_selected:(i = state.selected_index) ~width:viewport_width item)))
;;
