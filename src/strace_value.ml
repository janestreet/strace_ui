open! Core

(** Parsed representation of strace value syntax. Strace outputs structured values like
    [{sa_family=AF_INET, sin_port=htons(0)}] which we parse into a tree. *)

type t =
  | Atom of string
  | String of string (** A quoted string value *)
  | Struct of (string * t) list (** [{key=value, ...}] *)
  | Array of t list (** [[elem, ...]] *)
  | Call of string * string (** [func(arg)] like [htons(0)] *)
[@@deriving sexp_of]

let is_struct_or_array = function
  | Struct _ | Array _ -> true
  | _ -> false
;;

(** Parse a strace value string into a tree. *)
let rec parse s =
  let s = String.strip s in
  if String.is_empty s
  then Atom ""
  else if String.is_prefix s ~prefix:"\""
  then (
    (* Quoted string *)
    let content =
      s
      |> String.chop_prefix_if_exists ~prefix:"\""
      |> String.chop_suffix_if_exists ~suffix:"\""
    in
    String content)
  else if String.is_prefix s ~prefix:"{"
  then (
    (* Struct: {key=value, key=value, ...} *)
    let inner =
      s
      |> String.chop_prefix_if_exists ~prefix:"{"
      |> String.chop_suffix_if_exists ~suffix:"}"
      |> String.strip
    in
    let fields = split_top_level inner ~on:',' in
    let parsed_fields =
      List.filter_map fields ~f:(fun field ->
        let field = String.strip field in
        if String.is_empty field
        then None
        else (
          match String.lsplit2 field ~on:'=' with
          | Some (key, value) -> Some (String.strip key, parse (String.strip value))
          | None -> Some (field, Atom "")))
    in
    Struct parsed_fields)
  else if String.is_prefix s ~prefix:"["
  then (
    (* Array: [elem, elem, ...] *)
    let inner =
      s
      |> String.chop_prefix_if_exists ~prefix:"["
      |> String.chop_suffix_if_exists ~suffix:"]"
      |> String.strip
    in
    if String.is_empty inner
    then Array []
    else (
      let elems = split_top_level inner ~on:',' in
      Array (List.map elems ~f:(fun e -> parse (String.strip e)))))
  else (
    (* Check for function call: name(args) *)
    match String.lsplit2 s ~on:'(' with
    | Some (name, rest)
      when (not (String.is_empty (String.strip name)))
           && String.is_suffix (String.strip rest) ~suffix:")" ->
      let arg =
        rest |> String.strip |> String.chop_suffix_if_exists ~suffix:")" |> String.strip
      in
      Call (String.strip name, arg)
    | _ -> Atom s)

and split_top_level s ~on = Display_utils.split_top_level s ~on

(** Generic tree fold. Walks the tree and calls back for each line to emit.
    - [~render_atom ~indent s]: render an atom
    - [~render_string ~indent s]: render a quoted string, returning a list of lines
    - [~render_call ~indent name arg]: render a function call
    - [~render_prefix ~indent prefix label]: render a tree prefix (├─/╰─) with a label
    - [~render_prefix_with_value ~indent prefix label value]: render prefix + " = " +
      value
    - [~render_prefix_with_multi ~indent ~child_indent prefix lines]: render prefix +
      multi-line *)
let fold_tree
  (t : t)
  ~emit
  ~render_atom
  ~render_string
  ~render_call
  ~render_prefix
  ~render_prefix_with_value
  ~render_prefix_with_multi
  =
  let rec walk ~indent t =
    match t with
    | Atom s -> emit (render_atom ~indent s)
    | String s ->
      let views = render_string s in
      List.iter views ~f:emit
    | Call (name, arg) -> emit (render_call ~indent name arg)
    | Struct fields ->
      List.iteri fields ~f:(fun i (key, value) ->
        let is_last = i = List.length fields - 1 in
        let prefix = if is_last then "╰─" else "├─" in
        let child_prefix = if is_last then "  " else "│ " in
        if is_struct_or_array value
        then (
          emit (render_prefix ~indent prefix key);
          walk ~indent:(indent ^ child_prefix) value)
        else (
          match value with
          | Atom "" -> emit (render_prefix ~indent prefix key)
          | Atom v -> emit (render_prefix_with_value ~indent prefix key v)
          | String s ->
            let views = render_string s in
            render_prefix_with_multi
              ~emit
              ~indent
              ~child_indent:(indent ^ child_prefix)
              prefix
              key
              views
          | Call (name, arg) ->
            emit (render_prefix_with_value ~indent prefix key [%string "%{name}(%{arg})"])
          | Struct _ | Array _ -> ()))
    | Array elems ->
      List.iteri elems ~f:(fun i elem ->
        let is_last = i = List.length elems - 1 in
        let prefix = if is_last then "╰─" else "├─" in
        let child_prefix = if is_last then "  " else "│ " in
        if is_struct_or_array elem
        then (
          emit (render_prefix ~indent prefix [%string "[%{i#Int}]"]);
          walk ~indent:(indent ^ child_prefix) elem)
        else (
          match elem with
          | Atom s -> emit (render_prefix ~indent prefix s)
          | String s ->
            let views = render_string s in
            render_prefix_with_multi
              ~emit
              ~indent
              ~child_indent:(indent ^ child_prefix)
              prefix
              ""
              views
          | Call (name, arg) ->
            emit (render_prefix ~indent prefix [%string "%{name}(%{arg})"])
          | Struct _ | Array _ -> ()))
  in
  walk ~indent:"" t
;;

(** Render a parsed value as an expectree-like string. [render_string] controls how quoted
    strings are displayed. *)
let to_lines ?(render_string = fun s -> [ "\"" ^ s ^ "\"" ]) t =
  let lines = ref [] in
  fold_tree
    t
    ~emit:(fun s -> lines := s :: !lines)
    ~render_atom:(fun ~indent s -> indent ^ s)
    ~render_string:(fun s -> render_string s)
    ~render_call:(fun ~indent name arg -> indent ^ [%string "%{name}(%{arg})"])
    ~render_prefix:(fun ~indent prefix label -> indent ^ [%string "%{prefix}%{label}"])
    ~render_prefix_with_value:(fun ~indent prefix key value ->
      indent ^ [%string "%{prefix}%{key} = %{value}"])
    ~render_prefix_with_multi:(fun ~emit ~indent ~child_indent prefix key views ->
      match views with
      | [] -> ()
      | [ single ] ->
        let label =
          if String.is_empty key
          then [%string "%{prefix}%{single}"]
          else [%string "%{prefix}%{key} = %{single}"]
        in
        emit (indent ^ label)
      | first :: rest when String.is_empty key ->
        emit (indent ^ [%string "%{prefix}%{first}"]);
        List.iter rest ~f:(fun l -> emit (child_indent ^ l))
      | _ ->
        emit (indent ^ [%string "%{prefix}%{key} ="]);
        List.iter views ~f:(fun l -> emit (child_indent ^ l)));
  List.rev !lines
;;
