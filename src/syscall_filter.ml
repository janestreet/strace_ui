open! Core

(** A single filter term *)
module Term = struct
  type t =
    | Include_family of Syscall_schema.Family.t
    | Include_syscall of string
    | Exclude_syscall of string
    | Filter_pid of int
    | Exclude_pid of int
    | Filter_fd of
        { fd_number : int
        ; generation : int option
        }
    | Filter_related_pid of int
    | Regex of Re2.t
  [@@deriving sexp_of, equal]
end

(** A filter expression is a list of terms applied in order *)
type t = Term.t list [@@deriving sexp_of, equal]

let empty : t = []
let is_empty (t : t) = List.is_empty t

let to_normalized_string (t : t) =
  String.concat
    ~sep:" "
    (List.map t ~f:(fun term ->
       match term with
       | Include_family f -> Syscall_schema.Family.to_display_string f
       | Include_syscall name -> name
       | Exclude_syscall name -> [%string "-%{name}"]
       | Filter_pid pid -> [%string "pid:%{pid#Int}"]
       | Exclude_pid pid -> [%string "!pid:%{pid#Int}"]
       | Filter_fd { fd_number; generation = None } -> [%string "fd:%{fd_number#Int}"]
       | Filter_fd { fd_number; generation = Some g } ->
         [%string "fd:%{fd_number#Int}.%{g#Int}"]
       | Filter_related_pid pid -> [%string "rel:%{pid#Int}"]
       | Regex re ->
         let escaped =
           String.concat_map (Re2.pattern re) ~f:(fun c ->
             if Char.equal c '/' then "\\/" else String.of_char c)
         in
         [%string "/%{escaped}/"]))
;;

let to_display_string (t : t) = if is_empty t then "all" else to_normalized_string t

(** Parse a single non-regex token into a filter term. *)
let parse_simple_token token =
  let token = String.strip token in
  if String.is_prefix token ~prefix:"!pid:"
  then (
    let num_str = String.chop_prefix_exn token ~prefix:"!pid:" in
    match Int.of_string_opt num_str with
    | Some pid -> Term.Exclude_pid pid
    | None -> Term.Include_syscall token)
  else if String.is_prefix token ~prefix:"pid:"
  then (
    let num_str = String.chop_prefix_exn token ~prefix:"pid:" in
    match Int.of_string_opt num_str with
    | Some pid -> Term.Filter_pid pid
    | None -> Term.Include_syscall token)
  else if String.is_prefix token ~prefix:"rel:"
  then (
    let num_str = String.chop_prefix_exn token ~prefix:"rel:" in
    match Int.of_string_opt num_str with
    | Some pid -> Term.Filter_related_pid pid
    | None -> Term.Include_syscall token)
  else if String.is_prefix token ~prefix:"fd:"
  then (
    let fd_str = String.chop_prefix_exn token ~prefix:"fd:" in
    (* fd:N.G or fd:N *)
    match String.lsplit2 fd_str ~on:'.' with
    | Some (num_str, gen_str) ->
      (match Int.of_string_opt num_str, Int.of_string_opt gen_str with
       | Some fd_number, Some generation ->
         Term.Filter_fd { fd_number; generation = Some generation }
       | _ -> Term.Include_syscall token)
    | None ->
      (match Int.of_string_opt fd_str with
       | Some fd_number -> Term.Filter_fd { fd_number; generation = None }
       | None -> Term.Include_syscall token))
  else if String.is_prefix token ~prefix:"%"
  then (
    (* Family: try to match against known families *)
    let family =
      List.find Syscall_schema.Family.all ~f:(fun f ->
        String.equal (Syscall_schema.Family.to_display_string f) token)
    in
    match family with
    | Some f -> Term.Include_family f
    | None -> Term.Include_syscall token)
  else if String.is_prefix token ~prefix:"-" || String.is_prefix token ~prefix:"!"
  then Term.Exclude_syscall (String.drop_prefix token 1)
  else if String.is_prefix token ~prefix:"+"
  then Term.Include_syscall (String.drop_prefix token 1)
  else Term.Include_syscall token
;;

(** Parse the body of a regex token (content between slashes), handling backslash escapes.
    A backslash-slash becomes a literal slash; any other backslash-char is kept as a
    literal backslash. *)
let parse_regex_body body =
  let buf = Buffer.create (String.length body) in
  let len = String.length body in
  let i = ref 0 in
  while !i < len do
    let c = String.get body !i in
    if Char.equal c '\\' && !i + 1 < len
    then (
      let next = String.get body (!i + 1) in
      if Char.equal next '/'
      then (
        Buffer.add_char buf '/';
        i := !i + 2)
      else (
        Buffer.add_char buf '\\';
        i := !i + 1))
    else (
      Buffer.add_char buf c;
      i := !i + 1)
  done;
  Buffer.contents buf
;;

(** Compile a pattern string into a [Term.Regex], returning [None] if the pattern is empty
    (matches everything, so can be dropped). *)
let make_regex_term pattern =
  if String.is_empty pattern
  then None
  else (
    let re =
      match Re2.create pattern with
      | Ok re -> re
      | Error _ ->
        (* If the pattern is invalid, treat it as a literal string *)
        Re2.escape pattern |> Re2.create_exn
    in
    Some (Term.Regex re))
;;

(** Tokenize a filter string into raw string segments, handling regex [/…/] tokens
    specially: a regex token runs from an opening [/] to the next unescaped [/] or end of
    string. Everything else is split on spaces. Returns a list of [`Plain token] or
    [`Regex body] values. *)
let tokenize s =
  let len = String.length s in
  let tokens = Queue.create () in
  let buf = Buffer.create 32 in
  let flush_plain () =
    let content = Buffer.contents buf in
    Buffer.clear buf;
    String.split content ~on:' '
    |> List.iter ~f:(fun tok ->
      let tok = String.strip tok in
      if not (String.is_empty tok) then Queue.enqueue tokens (`Plain tok))
  in
  let i = ref 0 in
  while !i < len do
    let c = String.get s !i in
    if Char.equal c '/'
    then (
      (* flush any pending plain text *)
      flush_plain ();
      (* scan for the closing slash *)
      let j = ref (!i + 1) in
      while
        !j < len
        && not
             (Char.equal (String.get s !j) '/'
              && if !j > 0 then not (Char.equal (String.get s (!j - 1)) '\\') else true)
      do
        j := !j + 1
      done;
      let body = String.sub s ~pos:(!i + 1) ~len:(!j - !i - 1) in
      Queue.enqueue tokens (`Regex body);
      if !j < len then i := !j + 1 else i := !j)
    else (
      Buffer.add_char buf c;
      i := !i + 1)
  done;
  flush_plain ();
  Queue.to_list tokens
;;

(** Parse a filter expression string. Terms are space-separated, except for regex tokens
    [/pattern/] which can contain spaces.
    - [%desc], [%file], etc. → Include_family
    - [-read], [!read] → Exclude_syscall
    - [+futex], [futex] → Include_syscall
    - [/pattern/] or [/pattern] → Regex *)
let parse s =
  let s = String.strip s in
  if String.is_empty s
  then []
  else
    tokenize s
    |> List.filter_map ~f:(fun segment ->
      match segment with
      | `Plain token -> Some (parse_simple_token token)
      | `Regex body ->
        let pattern = parse_regex_body body in
        make_regex_term pattern)
;;

(** Parse a filter string, removing empty regexes and normalizing whitespace, then
    re-serialize to a canonical string. *)
let normalize s =
  let terms = parse s in
  to_normalized_string terms
;;

(** Add an exclusion for a syscall name *)
let add_exclusion t ~syscall_name = t @ [ Term.Exclude_syscall syscall_name ]

(** Add an inclusion for a syscall name *)
let add_inclusion t ~syscall_name = t @ [ Term.Include_syscall syscall_name ]

(** Add a pid filter *)
let add_pid_filter t ~pid = t @ [ Term.Filter_pid pid ]

(** Add a pid exclusion *)
let add_pid_exclusion t ~pid = t @ [ Term.Exclude_pid pid ]

module Syscall_info = struct
  type t =
    { syscall_name : string
    ; pid : int
    ; fd_ids : Fd_tracker.Fd_id.t list
    ; raw_line : string
    }
end

(** Evaluate the filter for a given syscall name.

    Rules:
    - If there are no terms, everything passes (all).
    - If there are only exclusions, everything passes except excluded names.
    - If there are any inclusions, only included names pass (then exclusions are applied
      on top). *)
let is_ancestor fd_tracker ~pid ~target =
  let rec walk current ~visited =
    if Int.equal current pid
    then true
    else if Set.mem visited current
    then false
    else (
      let visited = Set.add visited current in
      match Fd_tracker.parent_pid fd_tracker ~pid:current with
      | Some parent -> walk parent ~visited
      | None -> false)
  in
  walk target ~visited:Int.Set.empty
;;

let is_related fd_tracker ~pid ~target =
  Int.equal pid target
  || is_ancestor fd_tracker ~pid ~target
  || is_ancestor fd_tracker ~pid:target ~target:pid
;;

let passes t (info : Syscall_info.t) ~fd_tracker =
  let { Syscall_info.syscall_name; pid; fd_ids; raw_line } = info in
  ignore (fd_tracker : Fd_tracker.t);
  if is_empty t
  then true
  else (
    let has_inclusions =
      List.exists t ~f:(fun term ->
        match term with
        | Include_family _ | Include_syscall _ -> true
        | Exclude_syscall _
        | Filter_pid _
        | Exclude_pid _
        | Filter_fd _
        | Filter_related_pid _
        | Regex _ -> false)
    in
    (* Start with the base set *)
    let included =
      if has_inclusions
      then
        List.exists t ~f:(fun term ->
          match term with
          | Include_family f -> Syscall_schema.Family.includes f ~syscall_name
          | Include_syscall name -> String.equal name syscall_name
          | Exclude_syscall _
          | Filter_pid _
          | Exclude_pid _
          | Filter_fd _
          | Filter_related_pid _
          | Regex _ -> false)
      else true
    in
    (* Apply exclusions *)
    let excluded =
      List.exists t ~f:(fun term ->
        match term with
        | Exclude_syscall name -> String.equal name syscall_name
        | _ -> false)
    in
    (* Apply pid/fd constraints *)
    let pid_ok =
      List.for_all t ~f:(fun term ->
        match term with
        | Filter_pid p -> Int.equal pid p
        | Exclude_pid p -> not (Int.equal pid p)
        | Filter_related_pid p -> is_related fd_tracker ~pid ~target:p
        | _ -> true)
    in
    let fd_ok =
      List.for_all t ~f:(fun term ->
        match term with
        | Filter_fd { fd_number; generation } ->
          List.exists fd_ids ~f:(fun (fd_id : Fd_tracker.Fd_id.t) ->
            Int.equal fd_id.fd_number fd_number
            &&
            match generation with
            | None -> true
            | Some g -> Int.equal fd_id.generation g)
        | _ -> true)
    in
    (* Apply regex constraints *)
    let regex_ok =
      List.for_all t ~f:(fun term ->
        match term with
        | Regex re -> Re2.matches re raw_line
        | _ -> true)
    in
    included && (not excluded) && pid_ok && fd_ok && regex_ok)
;;
