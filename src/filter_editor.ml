open! Core

module Action = struct
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

module Editing_state = struct
  type t =
    { buf : string
    ; cursor : int
    }
  [@@deriving sexp_of]
end

type t = Editing_state.t option [@@deriving sexp_of]

let empty : t = None
let is_editing (t : t) = Option.is_some t

let editing_buffer (t : t) =
  Option.map t ~f:(fun { Editing_state.buf; cursor = _ } -> buf)
;;

module Render_params = struct
  type t =
    { key_hint_color : Bonsai_term.Attr.Color.t
    ; title_color : Bonsai_term.Attr.Color.t
    ; fg_color : Bonsai_term.Attr.Color.t
    ; accent_color : Bonsai_term.Attr.Color.t
    ; bg_color : Bonsai_term.Attr.Color.t
    ; max_chars : int
    }
end

let render_label (t : t) ~current_filter ~(params : Render_params.t) =
  let open Bonsai_term in
  match t with
  | Some { buf; cursor } ->
    (* The display always reserves buf_len + 1 columns: the buffer text plus one trailing
       space for the cursor to sit on when it's at the end. *)
    let total_display_len = String.length buf + 1 in
    let before_cursor = String.prefix buf cursor in
    let cursor_char =
      if cursor < String.length buf then String.of_char (String.get buf cursor) else " "
    in
    let after_cursor =
      if cursor < String.length buf then String.drop_prefix buf (cursor + 1) ^ " " else ""
    in
    (* Truncation: if the total is too long, scroll to keep cursor visible. We allocate
       space to the right first (it can only use what content exists there), then give all
       remaining columns to the left so moving the cursor to the end doesn't shrink the
       visible portion of the buffer. *)
    let prefix_len = 3 (* " f:" *) in
    let available = params.max_chars - prefix_len in
    let before_cursor, cursor_char, after_cursor =
      if total_display_len <= available
      then before_cursor, cursor_char, after_cursor
      else (
        let buf_len = String.length buf in
        (* 1 column is always the cursor char itself *)
        let cols_for_sides = available - 1 in
        (* Content after the cursor char: when the cursor is on a buffer character, there
           are (buf_len - cursor - 1) remaining text chars + 1 trailing space = (buf_len -
           cursor) columns. When the cursor is at the end, the cursor char is already the
           trailing space and there is nothing after it. *)
        let right_content_len = if cursor < buf_len then buf_len - cursor else 0 in
        (* Give each side half, but if the right has less content than its half, donate
           the surplus to the left (and vice versa). *)
        let half = cols_for_sides / 2 in
        let right_cols =
          Int.min right_content_len (Int.max half (cols_for_sides - cursor))
        in
        let left_cols = cols_for_sides - right_cols in
        (* -- before cursor -- *)
        let window_start = cursor - left_cols in
        let before =
          if window_start > 0
          then "\xe2\x80\xa6" ^ String.sub buf ~pos:(window_start + 1) ~len:(left_cols - 1)
          else String.prefix buf cursor
        in
        (* -- cursor char -- *)
        let cc =
          if cursor < buf_len then String.of_char (String.get buf cursor) else " "
        in
        (* -- after cursor -- *)
        let after =
          if cursor < buf_len && right_cols > 0
          then (
            let after_start = cursor + 1 in
            let after_text_len = buf_len - after_start in
            if after_text_len + 1 (* trailing space *) <= right_cols
            then
              (* Everything after cursor fits; append trailing space *)
              String.drop_prefix buf after_start ^ " "
            else if right_cols <= 1
            then (* Only room for one char: show ellipsis *)
              "\xe2\x80\xa6"
            else
              (* Truncate with ellipsis in last column *)
              String.sub buf ~pos:after_start ~len:(right_cols - 1) ^ "\xe2\x80\xa6")
          else ""
        in
        before, cc, after)
    in
    let text_attrs = [ Attr.fg params.fg_color; Attr.bg params.bg_color ] in
    let cursor_attrs = [ Attr.fg params.bg_color; Attr.bg params.accent_color ] in
    View.hcat
      [ View.text
          ~attrs:[ Attr.fg params.key_hint_color; Attr.bold; Attr.bg params.bg_color ]
          " f"
      ; View.text
          ~attrs:[ Attr.fg params.title_color; Attr.bold; Attr.bg params.bg_color ]
          ":"
      ; View.text ~attrs:text_attrs before_cursor
      ; View.text ~attrs:cursor_attrs cursor_char
      ; View.text ~attrs:text_attrs after_cursor
      ]
  | None ->
    let filter_str = Syscall_filter.to_display_string current_filter in
    let filter_str =
      if String.length filter_str > params.max_chars - 3
      then String.prefix filter_str (params.max_chars - 4) ^ "\xe2\x80\xa6"
      else filter_str
    in
    View.hcat
      [ View.text
          ~attrs:[ Attr.fg params.key_hint_color; Attr.bold; Attr.bg params.bg_color ]
          " f"
      ; View.text
          ~attrs:[ Attr.fg params.title_color; Attr.bold; Attr.bg params.bg_color ]
          [%string ":%{filter_str} "]
      ]
;;

(* Find the position of the previous word boundary (emacs Alt-b / Ctrl-w semantics): skip
   spaces backward, then skip non-spaces backward. *)
let word_boundary_backward buf ~cursor =
  if cursor = 0
  then 0
  else (
    let pos = ref (cursor - 1) in
    while !pos > 0 && Char.equal (String.get buf !pos) ' ' do
      pos := !pos - 1
    done;
    while !pos > 0 && not (Char.equal (String.get buf (!pos - 1)) ' ') do
      pos := !pos - 1
    done;
    !pos)
;;

(* Find the position of the next word boundary (emacs Alt-f semantics): skip non-spaces
   forward, then skip spaces forward. *)
let word_boundary_forward buf ~cursor =
  let len = String.length buf in
  if cursor >= len
  then len
  else (
    let pos = ref cursor in
    while !pos < len && not (Char.equal (String.get buf !pos) ' ') do
      pos := !pos + 1
    done;
    while !pos < len && Char.equal (String.get buf !pos) ' ' do
      pos := !pos + 1
    done;
    !pos)
;;

let with_editing_state (t : t) ~f =
  match t with
  | Some state ->
    let state = f state in
    Some state, None
  | None -> t, None
;;

let apply_action (t : t) ~current_filter (action : Action.t) =
  match action with
  | Start ->
    let initial = Syscall_filter.to_normalized_string current_filter in
    let initial =
      if (not (String.is_empty initial)) && not (String.is_suffix initial ~suffix:" ")
      then initial ^ " "
      else initial
    in
    Some { Editing_state.buf = initial; cursor = String.length initial }, None
  | Start_regex ->
    let initial = Syscall_filter.to_normalized_string current_filter in
    let initial = if String.is_empty initial then "/" else initial ^ " /" in
    Some { Editing_state.buf = initial; cursor = String.length initial }, None
  | Key c ->
    with_editing_state t ~f:(fun { buf; cursor } ->
      let buf =
        String.prefix buf cursor ^ String.of_char c ^ String.drop_prefix buf cursor
      in
      { buf; cursor = cursor + 1 })
  | Backspace ->
    with_editing_state t ~f:(fun { buf; cursor } ->
      if cursor > 0
      then (
        let buf = String.prefix buf (cursor - 1) ^ String.drop_prefix buf cursor in
        { buf; cursor = cursor - 1 })
      else { buf; cursor })
  | Delete_forward ->
    with_editing_state t ~f:(fun { buf; cursor } ->
      if cursor < String.length buf
      then (
        let buf = String.prefix buf cursor ^ String.drop_prefix buf (cursor + 1) in
        { buf; cursor })
      else { buf; cursor })
  | Move_left ->
    with_editing_state t ~f:(fun { buf; cursor } ->
      { buf; cursor = Int.max 0 (cursor - 1) })
  | Move_right ->
    with_editing_state t ~f:(fun { buf; cursor } ->
      { buf; cursor = Int.min (String.length buf) (cursor + 1) })
  | Move_to_start ->
    with_editing_state t ~f:(fun { buf; cursor = _ } -> { buf; cursor = 0 })
  | Move_to_end ->
    with_editing_state t ~f:(fun { buf; cursor = _ } ->
      { buf; cursor = String.length buf })
  | Kill_to_end ->
    with_editing_state t ~f:(fun { buf; cursor } ->
      { buf = String.prefix buf cursor; cursor })
  | Kill_to_start ->
    with_editing_state t ~f:(fun { buf; cursor } ->
      { buf = String.drop_prefix buf cursor; cursor = 0 })
  | Kill_word_backward ->
    with_editing_state t ~f:(fun { buf; cursor } ->
      let new_cursor = word_boundary_backward buf ~cursor in
      let buf = String.prefix buf new_cursor ^ String.drop_prefix buf cursor in
      { buf; cursor = new_cursor })
  | Move_word_forward ->
    with_editing_state t ~f:(fun { buf; cursor } ->
      { buf; cursor = word_boundary_forward buf ~cursor })
  | Move_word_backward ->
    with_editing_state t ~f:(fun { buf; cursor } ->
      { buf; cursor = word_boundary_backward buf ~cursor })
  | Submit ->
    (match t with
     | Some { buf; cursor = _ } -> None, Some (Syscall_filter.normalize buf)
     | None -> t, None)
  | Cancel -> None, None
;;
