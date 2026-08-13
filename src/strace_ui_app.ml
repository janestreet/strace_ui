open! Core
open Async
open! Bonsai_term
open Bonsai.Let_syntax

(** Rendering mode for binary data *)
module Render_mode = struct
  type t =
    | Auto
    | Hexdump
    | String
  [@@deriving sexp_of, equal]

  let cycle = function
    | Auto -> Hexdump
    | Hexdump -> String
    | String -> Auto
  ;;

  (* Check if a string should be shown as hexdump in Auto mode. Decodes escape sequences
     and checks the raw bytes for non-text content. *)
  let should_hexdump_in_auto escaped_content =
    let decoded = Display_utils.decode_strace_escapes escaped_content in
    String.exists decoded ~f:(fun c ->
      let n = Char.to_int c in
      n > 127
      || ((not (Char.is_print c))
          && (not (Char.equal c '\n'))
          && (not (Char.equal c '\r'))
          && (not (Char.equal c '\t'))
          && not (Char.equal c ' ')))
  ;;

  (** Whether to use hexdump for a given string value *)
  let to_short_string = function
    | Auto -> "auto"
    | Hexdump -> "hex"
    | String -> "str"
  ;;

  let use_hexdump t ~escaped_content =
    match t with
    | Hexdump -> true
    | String -> false
    | Auto -> should_hexdump_in_auto escaped_content
  ;;
end

module Focus = struct
  type t =
    | Syscall_list
    | Detail_pane
  [@@deriving sexp_of, equal]
end

(** App state *)
module Model = struct
  type t =
    { syscall_list : Strace_parser.Parsed_line.t Virtual_list.State.t
    ; fd_tracker : Fd_tracker.t
    ; syscall_filter : Syscall_filter.t
    ; render_mode : Render_mode.t
    ; next_index : int
    ; show_man_page : bool
    ; man_page_cache : string String.Map.t
    ; dns_cache : string String.Map.t (** Map from IP address to resolved hostname *)
    ; focus : Focus.t
    ; show_help : bool
    ; filter_editor : Filter_editor.t
    ; pending_syscalls : int Int.Map.t
    (** Map from pid to the index in [syscall_list] of the unfinished call *)
    ; resolved_fds : Fd_tracker.Fd_id.t list Int.Map.t
    (** Map from syscall index to resolved [Fd_id.t] values. Computed eagerly when the
        line is first processed, so generation tracking is baked in. *)
    ; pid_map : Pid_map.t
    ; resolve_pid_info : (int -> Pid_map.Pid_info.t option[@sexp.opaque])
    (** Given a PID, try to look up its process info (e.g. from procfs). *)
    }
  [@@deriving sexp_of]

  let selected_index t = Virtual_list.State.selected_index t.syscall_list
  let fd_tracker t = t.fd_tracker
  let pid_map t = t.pid_map
  let filtered_count t = Virtual_list.State.filtered_count t.syscall_list
  let get_filtered t i = Virtual_list.State.get_filtered t.syscall_list i
  let get_selected t = Virtual_list.State.get_selected t.syscall_list
end

module Action = struct
  type t =
    | Add_line of string
    | Select_up
    | Select_down
    | Select_top
    | Select_bottom
    | Jump_to_index of int
    | Set_filter of string
    | Hide_selected
    | Show_only_selected
    | Filter_selected_pid
    | Exclude_selected_pid
    | Cycle_preset_filter
    | Filter_edit of Filter_editor.Action.t
    | Toggle_help
    | Toggle_render_mode
    | Toggle_man_page
    | Set_man_page of
        { name : string
        ; content : string
        }
    | Set_dns_entry of
        { ip : string
        ; hostname : string
        }
    | Toggle_focus
    | Jump_to_filtered_index of int
    | Follow_fd
    | Jump_fd_prev
    | Jump_fd_next
    | Jump_fd_origin
  [@@deriving sexp_of]
end

let fork_syscalls = String.Set.of_list [ "clone"; "clone3"; "fork"; "vfork" ]

let is_fd_return_type ~syscall_name ~args_raw =
  match Syscall_schema.lookup syscall_name with
  | Some info ->
    let sig_ =
      Syscall_schema.Syscall_info.best_signature
        info
        ~arg_count:(List.length (Strace_parser.split_args args_raw))
    in
    Syscall_schema.Return_type.is_file_descriptor
      (Syscall_schema.Signature.return_type sig_)
  | None -> false
;;

(** Extract all FD numbers from a parsed syscall line (from args and return value) *)
let extract_fd_numbers (line : Strace_parser.Parsed_line.t) =
  let args = Strace_parser.split_args line.args_raw in
  let schema = Syscall_schema.lookup line.syscall_name in
  let arg_fds =
    match schema with
    | Some info ->
      let sig_ =
        Syscall_schema.Syscall_info.best_signature info ~arg_count:(List.length args)
      in
      List.concat_mapi (Syscall_schema.Signature.args sig_) ~f:(fun i spec ->
        if Syscall_schema.Arg_type.is_file_descriptor
             (Syscall_schema.Arg_spec.arg_type spec)
        then (
          match List.nth args i with
          | None -> []
          | Some arg_raw ->
            let s = String.strip arg_raw in
            if String.is_prefix s ~prefix:"["
            then (
              (* Bracket notation like [3, 4] from pipe/socketpair *)
              let inside =
                String.chop_prefix_if_exists s ~prefix:"["
                |> String.chop_suffix_if_exists ~suffix:"]"
              in
              String.split inside ~on:','
              |> List.filter_map ~f:(fun part ->
                Strace_parser.extract_fd_number (String.strip part)))
            else Strace_parser.extract_fd_number s |> Option.to_list)
        else [])
    | None ->
      (* Without schema, try to extract FD from first arg if it looks like a number *)
      (match args with
       | first :: _ ->
         (match Strace_parser.extract_fd_number (String.strip first) with
          | Some fd -> [ fd ]
          | None -> [])
       | [] -> [])
  in
  let return_fds =
    if is_fd_return_type ~syscall_name:line.syscall_name ~args_raw:line.args_raw
    then (
      match Strace_parser.extract_return_int line.result with
      | Some fd when fd >= 0 -> [ fd ]
      | _ -> [])
    else []
  in
  arg_fds @ return_fds
;;

(** Resolve all FD references in a syscall line to [Fd_id.t] values. Untracked fds get a
    synthesized generation-0 Fd_id (for fds that existed before tracing started). *)
let resolve_fds (line : Strace_parser.Parsed_line.t) ~fd_tracker =
  let fd_numbers = extract_fd_numbers line in
  List.filter_map fd_numbers ~f:(fun fd_num ->
    Fd_tracker.resolve_fd_or_default fd_tracker ~pid:line.pid ~fd_number:fd_num)
;;

(** After a fork/clone is processed, re-resolve fds for any child syscalls that arrived
    before the child's fd table existed (e.g. when clone was unfinished and child syscalls
    interleaved before clone resumed). *)
let re_resolve_child_fds
  ~syscall_list
  ~fd_tracker
  ~resolved_fds
  (line : Strace_parser.Parsed_line.t)
  =
  if Set.mem fork_syscalls line.syscall_name
  then (
    match Strace_parser.extract_return_int line.result with
    | Some child_pid when child_pid > 0 ->
      let total = Virtual_list.State.total_count syscall_list in
      let rec loop resolved_fds i =
        if i >= total
        then resolved_fds
        else (
          let item : Strace_parser.Parsed_line.t =
            Virtual_list.State.get_raw syscall_list i
          in
          let resolved_fds =
            if Int.equal item.pid child_pid
               &&
               match Map.find resolved_fds item.index with
               | None | Some [] -> true
               | Some _ -> false
            then (
              let fd_ids = resolve_fds item ~fd_tracker in
              Map.set resolved_fds ~key:item.index ~data:fd_ids)
            else resolved_fds
          in
          loop resolved_fds (i + 1))
      in
      loop resolved_fds 0
    | _ -> resolved_fds)
  else resolved_fds
;;

let passes_filter
  ~syscall_filter
  ~fd_tracker
  ~resolved_fds
  (line : Strace_parser.Parsed_line.t)
  =
  let fd_ids =
    Map.find resolved_fds line.index
    |> Option.value ~default:(resolve_fds line ~fd_tracker)
  in
  Syscall_filter.passes
    syscall_filter
    { syscall_name = line.syscall_name; pid = line.pid; fd_ids; raw_line = line.raw_line }
    ~fd_tracker
;;

(** Build the fd-follow filter for a syscall line — the same filter that Shift-F applies.
    Returns [None] if the line has no fd to follow. *)
let fd_follow_filter (model : Model.t) (line : Strace_parser.Parsed_line.t) =
  let fd_ids = Map.find model.resolved_fds line.index |> Option.value ~default:[] in
  match List.hd fd_ids with
  | Some (fd_id : Fd_tracker.Fd_id.t) ->
    Some
      (Syscall_filter.parse
         [%string "rel:%{line.pid#Int} fd:%{fd_id.fd_number#Int}.%{fd_id.generation#Int}"])
  | None ->
    let fd_numbers = extract_fd_numbers line in
    (match List.hd fd_numbers with
     | Some fd_num ->
       Some (Syscall_filter.parse [%string "rel:%{line.pid#Int} fd:%{fd_num#Int}"])
     | None -> None)
;;

(** Starting from filtered index [from], scan in direction [dir] to find the next syscall
    matching [filter]. Returns the filtered index if found, or [from] if not. *)
let find_filtered_index_matching_filter (model : Model.t) ~filter ~from ~dir =
  let filtered_count = Model.filtered_count model in
  let target = ref from in
  let found = ref false in
  let i = ref (from + dir) in
  while !i >= 0 && !i < filtered_count && not !found do
    (match Model.get_filtered model !i with
     | Some candidate ->
       if passes_filter
            ~syscall_filter:filter
            ~fd_tracker:model.fd_tracker
            ~resolved_fds:model.resolved_fds
            candidate
       then (
         target := !i;
         found := true)
     | None -> ());
    i := !i + dir
  done;
  !target
;;

let filtered_syscalls (model : Model.t) =
  List.init (Model.filtered_count model) ~f:(fun i ->
    Option.value_exn (Model.get_filtered model i))
;;

let update_filter_from_selected
  (model : Model.t)
  ~(f : Syscall_filter.t -> Strace_parser.Parsed_line.t -> Syscall_filter.t)
  =
  match Model.get_selected model with
  | None -> model
  | Some line ->
    let new_filter = f model.syscall_filter line in
    let syscall_list =
      Virtual_list.State.refilter
        model.syscall_list
        ~passes_filter:
          (passes_filter
             ~syscall_filter:new_filter
             ~fd_tracker:model.fd_tracker
             ~resolved_fds:model.resolved_fds)
    in
    { model with syscall_filter = new_filter; syscall_list }
;;

let rec apply_action_pure (model : Model.t) (action : Action.t) =
  match action with
  | Add_line raw_line ->
    (match Strace_parser.parse_line ~index:model.next_index raw_line with
     | None -> { model with next_index = model.next_index + 1 }
     | Some parsed ->
       let is_new_pid = Option.is_none (Pid_map.short_id model.pid_map parsed.pid) in
       let pid_map = Pid_map.register model.pid_map parsed.pid in
       let pid_map =
         if is_new_pid
         then (
           match model.resolve_pid_info parsed.pid with
           | Some pid_info -> Pid_map.set_info pid_map ~pid:parsed.pid pid_info
           | None -> pid_map)
         else pid_map
       in
       let model = { model with pid_map } in
       (match parsed.result with
        | Unfinished ->
          (* Record as pending; add to the list but don't update fd_tracker yet. Resolve
             fds with current tracker state (before the unfinished call modifies
             anything). *)
          let fd_ids = resolve_fds parsed ~fd_tracker:model.fd_tracker in
          let resolved_fds = Map.set model.resolved_fds ~key:parsed.index ~data:fd_ids in
          let syscall_list =
            Virtual_list.State.append
              model.syscall_list
              parsed
              ~passes_filter:
                (passes_filter
                   ~syscall_filter:model.syscall_filter
                   ~fd_tracker:model.fd_tracker
                   ~resolved_fds
                   parsed)
          in
          let pending_idx = Virtual_list.State.total_count syscall_list - 1 in
          let pending_syscalls =
            Map.set model.pending_syscalls ~key:parsed.pid ~data:pending_idx
          in
          { model with
            syscall_list
          ; pending_syscalls
          ; resolved_fds
          ; next_index = model.next_index + 1
          }
        | Resumed _ ->
          (* Find the matching unfinished call and update it *)
          (match Map.find model.pending_syscalls parsed.pid with
           | Some pending_idx ->
             let original = Virtual_list.State.get_raw model.syscall_list pending_idx in
             let merged = Strace_parser.merge_resumed ~original ~resumed:parsed in
             let syscall_list =
               Virtual_list.State.set_item model.syscall_list pending_idx merged
             in
             (* Resolve before AND after update to handle both close (fd exists before)
                and open (fd exists after) *)
             let fd_ids_before = resolve_fds merged ~fd_tracker:model.fd_tracker in
             let fd_tracker = Fd_tracker.update model.fd_tracker merged in
             let fd_ids_after = resolve_fds merged ~fd_tracker in
             let fd_ids =
               List.dedup_and_sort
                 ~compare:[%compare: Fd_tracker.Fd_id.t]
                 (fd_ids_before @ fd_ids_after)
             in
             let resolved_fds =
               Map.set model.resolved_fds ~key:merged.index ~data:fd_ids
             in
             let resolved_fds =
               re_resolve_child_fds ~syscall_list ~fd_tracker ~resolved_fds merged
             in
             let pending_syscalls = Map.remove model.pending_syscalls parsed.pid in
             { model with
               syscall_list
             ; fd_tracker
             ; pending_syscalls
             ; resolved_fds
             ; next_index = model.next_index + 1
             }
           | None ->
             (* No matching unfinished call; just add as-is *)
             let fd_ids_before = resolve_fds parsed ~fd_tracker:model.fd_tracker in
             let fd_tracker = Fd_tracker.update model.fd_tracker parsed in
             let fd_ids_after = resolve_fds parsed ~fd_tracker in
             let fd_ids =
               List.dedup_and_sort
                 ~compare:[%compare: Fd_tracker.Fd_id.t]
                 (fd_ids_before @ fd_ids_after)
             in
             let resolved_fds =
               Map.set model.resolved_fds ~key:parsed.index ~data:fd_ids
             in
             let syscall_list =
               Virtual_list.State.append
                 model.syscall_list
                 parsed
                 ~passes_filter:
                   (passes_filter
                      ~syscall_filter:model.syscall_filter
                      ~fd_tracker
                      ~resolved_fds
                      parsed)
             in
             let resolved_fds =
               re_resolve_child_fds ~syscall_list ~fd_tracker ~resolved_fds parsed
             in
             { model with
               syscall_list
             ; fd_tracker
             ; resolved_fds
             ; next_index = model.next_index + 1
             })
        | _ ->
          (* Normal completed syscall: resolve before AND after update *)
          let fd_ids_before = resolve_fds parsed ~fd_tracker:model.fd_tracker in
          let fd_tracker = Fd_tracker.update model.fd_tracker parsed in
          let fd_ids_after = resolve_fds parsed ~fd_tracker in
          let fd_ids =
            List.dedup_and_sort
              ~compare:[%compare: Fd_tracker.Fd_id.t]
              (fd_ids_before @ fd_ids_after)
          in
          let resolved_fds = Map.set model.resolved_fds ~key:parsed.index ~data:fd_ids in
          let syscall_list =
            Virtual_list.State.append
              model.syscall_list
              parsed
              ~passes_filter:
                (passes_filter
                   ~syscall_filter:model.syscall_filter
                   ~fd_tracker
                   ~resolved_fds
                   parsed)
          in
          { model with
            syscall_list
          ; fd_tracker
          ; resolved_fds
          ; next_index = model.next_index + 1
          }))
  | Select_up ->
    { model with
      syscall_list = Virtual_list.State.apply_action model.syscall_list Select_up
    }
  | Select_down ->
    { model with
      syscall_list = Virtual_list.State.apply_action model.syscall_list Select_down
    }
  | Select_top ->
    { model with
      syscall_list = Virtual_list.State.apply_action model.syscall_list Select_top
    }
  | Select_bottom ->
    { model with
      syscall_list = Virtual_list.State.apply_action model.syscall_list Select_bottom
    }
  | Jump_to_index index ->
    let target = ref (Model.selected_index model) in
    for i = 0 to Model.filtered_count model - 1 do
      match Model.get_filtered model i with
      | Some line when line.index = index -> target := i
      | _ -> ()
    done;
    { model with
      syscall_list =
        Virtual_list.State.apply_action
          model.syscall_list
          (Jump_to_filtered_index !target)
    }
  | Set_filter filter_str ->
    let new_filter = Syscall_filter.parse filter_str in
    let syscall_list =
      Virtual_list.State.refilter
        model.syscall_list
        ~passes_filter:
          (passes_filter
             ~syscall_filter:new_filter
             ~fd_tracker:model.fd_tracker
             ~resolved_fds:model.resolved_fds)
    in
    { model with syscall_filter = new_filter; syscall_list }
  | Hide_selected ->
    update_filter_from_selected model ~f:(fun filter line ->
      Syscall_filter.add_exclusion filter ~syscall_name:line.syscall_name)
  | Show_only_selected ->
    update_filter_from_selected model ~f:(fun filter line ->
      Syscall_filter.add_inclusion filter ~syscall_name:line.syscall_name)
  | Filter_selected_pid ->
    update_filter_from_selected model ~f:(fun filter line ->
      Syscall_filter.add_pid_filter filter ~pid:line.pid)
  | Exclude_selected_pid ->
    update_filter_from_selected model ~f:(fun filter line ->
      Syscall_filter.add_pid_exclusion filter ~pid:line.pid)
  | Cycle_preset_filter ->
    (* Cycle through: (empty) -> %desc -> %file -> %memory -> %net -> %process -> %signal
       -> %ipc -> (empty) *)
    let families =
      List.filter Syscall_schema.Family.all ~f:(fun f ->
        not ([%equal: Syscall_schema.Family.t] f All))
    in
    let presets = "" :: List.map families ~f:Syscall_schema.Family.to_display_string in
    let current_str = Syscall_filter.to_normalized_string model.syscall_filter in
    let current_idx =
      List.findi presets ~f:(fun _ p -> String.equal p current_str)
      |> Option.value_map ~default:(-1) ~f:fst
    in
    let next_idx = (current_idx + 1) % List.length presets in
    let next_str = List.nth_exn presets next_idx in
    apply_action_pure model (Set_filter next_str)
  | Filter_edit action ->
    let new_editor, submitted =
      Filter_editor.apply_action
        model.filter_editor
        ~current_filter:model.syscall_filter
        action
    in
    let model = { model with filter_editor = new_editor } in
    (match submitted with
     | Some filter_str -> apply_action_pure model (Set_filter filter_str)
     | None -> model)
  | Toggle_help -> { model with show_help = not model.show_help }
  | Toggle_render_mode -> { model with render_mode = Render_mode.cycle model.render_mode }
  | Toggle_man_page -> { model with show_man_page = not model.show_man_page }
  | Set_man_page { name; content } ->
    { model with man_page_cache = Map.set model.man_page_cache ~key:name ~data:content }
  | Set_dns_entry { ip; hostname } ->
    { model with dns_cache = Map.set model.dns_cache ~key:ip ~data:hostname }
  | Jump_to_filtered_index idx ->
    { model with
      syscall_list =
        Virtual_list.State.apply_action model.syscall_list (Jump_to_filtered_index idx)
    }
  | Follow_fd ->
    (match Model.get_selected model with
     | None -> model
     | Some line ->
       let filter_str =
         match fd_follow_filter model line with
         | Some filter -> Syscall_filter.to_normalized_string filter
         | None -> [%string "rel:%{line.pid#Int}"]
       in
       apply_action_pure model (Set_filter filter_str))
  | Toggle_focus ->
    let focus : Focus.t =
      match model.focus with
      | Syscall_list -> Detail_pane
      | Detail_pane -> Syscall_list
    in
    { model with focus }
  | Jump_fd_prev | Jump_fd_next ->
    let dir =
      match action with
      | Jump_fd_prev -> -1
      | _ -> 1
    in
    (match Model.get_selected model with
     | None -> model
     | Some line ->
       (match fd_follow_filter model line with
        | None -> model
        | Some filter ->
          let target =
            find_filtered_index_matching_filter
              model
              ~filter
              ~from:(Model.selected_index model)
              ~dir
          in
          { model with
            syscall_list =
              Virtual_list.State.apply_action
                model.syscall_list
                (Jump_to_filtered_index target)
          }))
  | Jump_fd_origin ->
    (match Model.get_selected model with
     | None -> model
     | Some line ->
       let fd_ids = Map.find model.resolved_fds line.index |> Option.value ~default:[] in
       (match List.hd fd_ids with
        | None -> model
        | Some fd_id ->
          (match Fd_tracker.lookup_origin model.fd_tracker fd_id with
           | None -> model
           | Some origin ->
             apply_action_pure
               model
               (Jump_to_index (Fd_tracker.Fd_origin.syscall_index origin)))))
;;

let resolve_pid_info_via_procfs pid =
  try
    let proc_dir = [%string "/proc/%{pid#Int}"] in
    let cmdline =
      In_channel.read_all [%string "%{proc_dir}/cmdline"]
      |> String.rstrip ~drop:(Char.equal '\000')
      |> String.tr ~target:'\000' ~replacement:' '
    in
    let thread_name = In_channel.read_all [%string "%{proc_dir}/comm"] |> String.rstrip in
    let is_thread =
      let status = In_channel.read_all [%string "%{proc_dir}/status"] in
      match
        String.split_lines status
        |> List.find_map ~f:(fun line ->
          match String.chop_prefix line ~prefix:"Tgid:" with
          | Some rest -> Some (String.strip rest |> Int.of_string)
          | None -> None)
      with
      | Some tgid -> not (Int.equal tgid pid)
      | None -> false
    in
    let cmdline = if String.is_empty cmdline then thread_name else cmdline in
    Some { Pid_map.Pid_info.cmdline; thread_name; is_thread }
  with
  | _ -> None
;;

let default_model ?primary_pid ?(resolve_pid_info = resolve_pid_info_via_procfs) () =
  let pid_map =
    match primary_pid with
    | None -> Pid_map.empty
    | Some pid ->
      let pid_map = Pid_map.register Pid_map.empty pid in
      (match resolve_pid_info pid with
       | Some info -> Pid_map.set_info pid_map ~pid info
       | None -> pid_map)
  in
  { Model.syscall_list = Virtual_list.State.create ()
  ; fd_tracker = Fd_tracker.empty
  ; pending_syscalls = Int.Map.empty
  ; resolved_fds = Int.Map.empty
  ; syscall_filter = Syscall_filter.empty
  ; render_mode = Auto
  ; next_index = 0
  ; show_man_page = false
  ; man_page_cache = String.Map.empty
  ; dns_cache = String.Map.empty
  ; focus = Syscall_list
  ; show_help = false
  ; filter_editor = Filter_editor.empty
  ; pid_map
  ; resolve_pid_info
  }
;;

module Theme = struct
  type t =
    { fg : Attr.Color.t
    ; bg : Attr.Color.t
    ; highlight : Attr.Color.t
    ; accent : Attr.Color.t
    ; green : Attr.Color.t
    ; red : Attr.Color.t
    ; yellow : Attr.Color.t
    ; dim : Attr.Color.t
    ; blue : Attr.Color.t
    ; teal : Attr.Color.t
    ; key_hint : Attr.Color.t
    }

  let text t ?(attrs = []) s = View.text ~attrs:([ Attr.fg t.fg; Attr.bg t.bg ] @ attrs) s
  let dim_text t s = View.text ~attrs:[ Attr.fg t.dim; Attr.bg t.bg ] s

  let section_header t s =
    View.text ~attrs:[ Attr.fg t.yellow; Attr.bold; Attr.bg t.bg ] s
  ;;

  let of_flavor (flavor : Bonsai_term_color_scheme.Flavor.t) =
    let c = Bonsai_term_color_scheme.color ~flavor in
    { fg = c Text
    ; bg = c Crust
    ; highlight = c Surface1
    ; accent = c Mauve
    ; green = c Green
    ; red = c Red
    ; yellow = c Yellow
    ; dim = c Overlay0
    ; blue = c Blue
    ; teal = c Teal
    ; key_hint = c Peach
    }
  ;;
end

let text ~theme = Theme.text theme
let dim_text ~theme = Theme.dim_text theme

let render_result
  ~(theme : Theme.t)
  ?(value_color = theme.green)
  (result : Strace_parser.Result.t)
  =
  match result with
  | Value v ->
    View.text ~attrs:[ Attr.fg value_color; Attr.bg theme.bg ] [%string "= %{v}"]
  | Error { errno; description } ->
    View.hcat
      [ View.text ~attrs:[ Attr.fg theme.red; Attr.bg theme.bg ] [%string "= -1 %{errno}"]
      ; dim_text ~theme [%string " (%{description})"]
      ]
  | Unfinished ->
    View.text ~attrs:[ Attr.fg theme.yellow; Attr.bg theme.bg ] "<unfinished>"
  | Resumed _ -> View.text ~attrs:[ Attr.fg theme.yellow; Attr.bg theme.bg ] "<resumed>"
  | Signal s -> View.text ~attrs:[ Attr.fg theme.yellow; Attr.bg theme.bg ] s
  | Exit s -> View.text ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ] s
;;

let render_syscall_line
  ~(theme : Theme.t)
  (line : Strace_parser.Parsed_line.t)
  ~is_selected
  ~width
  ~pid_map
  ~selected_pid
  =
  let bg = if is_selected then theme.highlight else theme.bg in
  let short_id = Pid_map.short_id pid_map line.pid |> Option.value ~default:0 in
  let pid_display_width = Pid_map.display_width pid_map in
  let pid_str =
    if short_id = 0
    then String.make pid_display_width ' '
    else String.pad_left (Int.to_string short_id) ~len:pid_display_width
  in
  let pid_is_selected = [%equal: int] line.pid selected_pid in
  let pid_color = if pid_is_selected then theme.fg else theme.dim in
  let pid_view =
    View.text ~attrs:[ Attr.fg pid_color; Attr.bg bg ] [%string "%{pid_str}"]
  in
  let name_view =
    View.text ~attrs:[ Attr.fg theme.accent; Attr.bold; Attr.bg bg ] line.syscall_name
  in
  let compact_args = Display_utils.compact_args_raw line.args_raw in
  let result_width = 6 in
  let args_truncated =
    (* Fixed overhead: pid " " name "(" args ")" " " result *)
    let overhead =
      String.length pid_str
      + 1
      + String.length line.syscall_name
      + 1
      + 1
      + 1
      + result_width
    in
    let max_args_len = Int.max 0 (width - overhead) in
    if String.length compact_args > max_args_len
    then
      if max_args_len <= 3
      then ""
      else String.prefix compact_args (max_args_len - 3) ^ "..."
    else compact_args
  in
  let args_view =
    View.text ~attrs:[ Attr.fg theme.fg; Attr.bg bg ] [%string "(%{args_truncated})"]
  in
  let result_view =
    let truncate_result s color =
      if String.length s > result_width
      then
        View.hcat
          [ View.text
              ~attrs:[ Attr.fg color; Attr.bg bg ]
              (String.prefix s (result_width - 1))
          ; View.text ~attrs:[ Attr.fg theme.dim; Attr.bg bg ] ">"
          ]
      else View.text ~attrs:[ Attr.fg color; Attr.bg bg ] s
    in
    match line.result with
    | Value v ->
      let short_val =
        Display_utils.strip_fd_annotations v
        |> String.lstrip
        |> fun s ->
        (* Strip parenthetical annotations like "0 (Timeout)" -> "0" *)
        match String.lsplit2 s ~on:' ' with
        | Some (num, rest) when String.is_prefix (String.lstrip rest) ~prefix:"(" -> num
        | _ -> s
      in
      truncate_result
        short_val
        (if is_fd_return_type ~syscall_name:line.syscall_name ~args_raw:line.args_raw
         then theme.yellow
         else theme.green)
    | Error { errno; _ } -> truncate_result errno theme.red
    | Unfinished -> View.text ~attrs:[ Attr.fg theme.yellow; Attr.bg bg ] "..."
    | Resumed _ -> View.text ~attrs:[ Attr.fg theme.yellow; Attr.bg bg ] "..."
    | Signal _ -> View.text ~attrs:[ Attr.fg theme.yellow; Attr.bg bg ] "SIG"
    | Exit _ -> View.text ~attrs:[ Attr.fg theme.dim; Attr.bg bg ] "EXIT"
  in
  let left_part =
    View.hcat [ pid_view; View.text ~attrs:[ Attr.bg bg ] " "; name_view; args_view ]
  in
  let result_actual_width = View.width result_view in
  let left_width = View.width left_part in
  let gap = Int.max 1 (width - left_width - result_actual_width) in
  let row =
    View.hcat
      [ left_part
      ; View.rectangle ~width:gap ~height:1 ~attrs:[ Attr.bg bg ] ()
      ; result_view
      ]
  in
  let row_width = View.width row in
  if row_width < width
  then
    View.hcat
      [ row
      ; View.rectangle ~width:(width - row_width) ~height:1 ~attrs:[ Attr.bg bg ] ()
      ]
  else View.crop ~r:(Int.max 0 (row_width - width)) row
;;

let hexdump_views ~(theme : Theme.t) ?(attrs = []) ?bytes_per_line s =
  Hexdump_view.render
    ~attrs
    ?bytes_per_line
    { fg = theme.fg
    ; bg = theme.bg
    ; dim = theme.dim
    ; blue = theme.blue
    ; teal = theme.teal
    }
    s
;;

let tree_views ~(theme : Theme.t) ~render_string_views parsed =
  let lines = ref [] in
  let indent_view indent v =
    if String.is_empty indent
    then v
    else View.hcat [ View.text ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ] indent; v ]
  in
  let prefix_view prefix =
    View.text ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ] prefix
  in
  Strace_value.fold_tree
    parsed
    ~emit:(fun v -> lines := v :: !lines)
    ~render_atom:(fun ~indent s -> indent_view indent (text ~theme s))
    ~render_string:(fun s -> render_string_views s)
    ~render_call:(fun ~indent name arg ->
      indent_view indent (text ~theme [%string "%{name}(%{arg})"]))
    ~render_prefix:(fun ~indent prefix label ->
      indent_view indent (View.hcat [ prefix_view prefix; text ~theme label ]))
    ~render_prefix_with_value:(fun ~indent prefix key value ->
      indent_view
        indent
        (View.hcat [ prefix_view prefix; text ~theme [%string "%{key} = %{value}"] ]))
    ~render_prefix_with_multi:(fun ~emit ~indent ~child_indent prefix key views ->
      match views with
      | [] -> ()
      | [ single ] ->
        let label =
          if String.is_empty key
          then View.hcat [ prefix_view prefix; single ]
          else View.hcat [ prefix_view prefix; text ~theme [%string "%{key} = "]; single ]
        in
        emit (indent_view indent label)
      | first :: rest when String.is_empty key ->
        (* Array element: inline first line with prefix *)
        emit (indent_view indent (View.hcat [ prefix_view prefix; first ]));
        List.iter rest ~f:(fun v -> emit (indent_view child_indent v))
      | _ ->
        (* Struct field: label on own line, all content below *)
        emit
          (indent_view
             indent
             (View.hcat [ prefix_view prefix; text ~theme [%string "%{key} ="] ]));
        List.iter views ~f:(fun v -> emit (indent_view child_indent v)));
  List.rev !lines
;;

(* For common syscalls, determine the meaningful byte count for a buffer argument. Returns
   [Some n] if the buffer at [arg_index] has [n] meaningful bytes. *)
let buffer_meaningful_length
  ~syscall_name
  ~arg_index
  ~(args : string list)
  ~(result : Strace_parser.Result.t)
  =
  let return_int () = Strace_parser.extract_return_int result in
  let arg_int i =
    Option.bind (List.nth args i) ~f:(fun s ->
      Int.of_string_opt (String.strip (Display_utils.strip_fd_annotations s)))
  in
  match syscall_name, arg_index with
  | ("read" | "pread64"), 1 -> return_int ()
  | ("readlink" | "readlinkat"), 1 -> return_int ()
  | "recvfrom", 1 -> return_int ()
  | "recvmsg", 1 -> return_int ()
  | "getrandom", 0 -> return_int ()
  | "getcwd", 0 -> return_int ()
  | ("write" | "pwrite64"), 1 -> arg_int 2
  | "sendto", 1 -> arg_int 2
  | "sendmsg", 1 -> arg_int 2
  | _ -> None
;;

(* Render a buffer value with meaningful/trailing distinction *)
let render_buffer_value ~(theme : Theme.t) ~arg_raw ~meaningful_bytes ~render_mode ~width =
  (* Strip surrounding quotes *)
  let content =
    arg_raw
    |> String.chop_prefix_if_exists ~prefix:"\""
    |> String.chop_suffix_if_exists ~suffix:"\""
  in
  let has_trailing_ellipsis = String.is_suffix arg_raw ~suffix:"\"..." in
  let content =
    if has_trailing_ellipsis
    then content |> String.chop_suffix_if_exists ~suffix:"..."
    else content
  in
  if Render_mode.use_hexdump render_mode ~escaped_content:content
  then (
    let meaningful_part, trailing_part =
      Display_utils.split_escaped_at_byte content ~byte_count:meaningful_bytes
    in
    let meaningful_bytes_decoded = Display_utils.decode_strace_escapes meaningful_part in
    let trailing_bytes_decoded = Display_utils.decode_strace_escapes trailing_part in
    let total_bytes =
      String.length meaningful_bytes_decoded + String.length trailing_bytes_decoded
    in
    let hex_bytes_per_line =
      Display_utils.hexdump_bytes_per_line ~width:(width - 1) ~total_bytes
    in
    let meaningful_views =
      hexdump_views ~theme ~bytes_per_line:hex_bytes_per_line meaningful_bytes_decoded
    in
    let trailing_views =
      hexdump_views
        ~theme
        ~attrs:[ Attr.fg theme.dim ]
        ~bytes_per_line:hex_bytes_per_line
        trailing_bytes_decoded
    in
    let views = meaningful_views @ trailing_views in
    true, View.vcat views)
  else (
    let meaningful_part, trailing_part =
      Display_utils.split_escaped_at_byte content ~byte_count:meaningful_bytes
    in
    let views =
      [ View.text ~attrs:[ Attr.fg theme.fg; Attr.bg theme.bg ] ("\"" ^ meaningful_part) ]
      @ (if String.is_empty trailing_part
         then []
         else [ View.text ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ] trailing_part ])
      @ [ View.text
            ~attrs:[ Attr.fg theme.fg; Attr.bg theme.bg ]
            (if has_trailing_ellipsis then "\"..." else "\"")
        ]
    in
    false, View.hcat views)
;;

let render_detail_header
  ~(theme : Theme.t)
  (line : Strace_parser.Parsed_line.t)
  ~schema
  ~pid_map
  =
  let time_span = Time_ns.Span.of_sec line.timestamp in
  let time_ns = Time_ns.of_span_since_epoch time_span in
  let zone = force Time_ns.Zone.local in
  let time_str = Time_ns.to_ofday time_ns ~zone |> Time_ns.Ofday.to_string_trimmed in
  let pid_str = Int.to_string line.pid in
  let short_id = Pid_map.short_id pid_map line.pid |> Option.value ~default:0 in
  let summary_line =
    match Pid_map.summary pid_map line.pid with
    | Some summary -> [ text ~theme summary ]
    | None -> []
  in
  let sig_lines =
    match schema with
    | Some info ->
      List.map (Syscall_schema.Syscall_info.signatures info) ~f:(fun s ->
        dim_text ~theme (Syscall_schema.Signature.c_signature s))
    | None -> []
  in
  View.vcat
    ([ View.hcat
         [ View.text
             ~attrs:[ Attr.fg theme.accent; Attr.bold; Attr.bg theme.bg ]
             line.syscall_name
         ; text ~theme [%string "  pid %{pid_str} (#%{short_id#Int})  %{time_str}"]
         ; (match line.duration with
            | Some d ->
              let duration_str = sprintf "  %.6fs" d in
              View.text ~attrs:[ Attr.fg theme.fg; Attr.bg theme.bg ] duration_str
            | None -> View.none)
         ]
     ]
     @ summary_line
     @ [ (match schema with
          | Some info -> dim_text ~theme (Syscall_schema.Syscall_info.brief info)
          | None -> dim_text ~theme "Unknown syscall")
       ]
     @ sig_lines
     @ [ View.text ~attrs:[ Attr.bg theme.bg ] "" ])
;;

let render_arg_value
  ~(theme : Theme.t)
  ~render_mode
  ~width
  ~name_label
  ~is_buffer
  ~(line : Strace_parser.Parsed_line.t)
  ~arg_index
  ~(args : string list)
  arg_raw
  =
  let meaningful_bytes =
    if is_buffer
    then
      buffer_meaningful_length
        ~syscall_name:line.syscall_name
        ~arg_index
        ~args
        ~result:line.result
    else None
  in
  match meaningful_bytes with
  | Some n when is_buffer ->
    render_buffer_value ~theme ~arg_raw ~meaningful_bytes:n ~render_mode ~width
  | _ ->
    let escaped_content =
      if is_buffer
      then
        arg_raw
        |> String.chop_prefix_if_exists ~prefix:"\""
        |> String.chop_suffix_if_exists ~suffix:"\""
      else ""
    in
    if is_buffer && Render_mode.use_hexdump render_mode ~escaped_content
    then (
      let content = Display_utils.decode_strace_escapes escaped_content in
      let hex_bytes_per_line =
        Display_utils.hexdump_bytes_per_line
          ~width:(width - 1)
          ~total_bytes:(String.length content)
      in
      let hex_views = hexdump_views ~theme ~bytes_per_line:hex_bytes_per_line content in
      true, View.vcat hex_views)
    else if String.is_prefix arg_raw ~prefix:"{" || String.is_prefix arg_raw ~prefix:"["
    then (
      let render_string_views s =
        if Render_mode.use_hexdump render_mode ~escaped_content:s
        then (
          let decoded = Display_utils.decode_strace_escapes s in
          let hex_bytes_per_line =
            Display_utils.hexdump_bytes_per_line
              ~width:(width - 7)
              ~total_bytes:(String.length decoded)
          in
          hexdump_views ~theme ~bytes_per_line:hex_bytes_per_line decoded)
        else [ text ~theme [%string {|"%{s}"|}] ]
      in
      let parsed = Strace_value.parse arg_raw in
      let views = tree_views ~theme ~render_string_views parsed in
      true, View.vcat views)
    else (
      let label_width = View.width name_label in
      let wrap_width = Int.max 20 (width - label_width - 1) in
      if String.length arg_raw <= wrap_width
      then false, text ~theme arg_raw
      else (
        let lines = Display_utils.wrap_string arg_raw ~width:wrap_width in
        match lines with
        | [] -> false, text ~theme arg_raw
        | first :: rest ->
          false, View.vcat (text ~theme first :: List.map rest ~f:(fun l -> text ~theme l))))
;;

let render_detail_args
  ~(theme : Theme.t)
  ~render_mode
  ~width
  ~fd_tracker
  ~dns_cache
  ~best_sig
  (line : Strace_parser.Parsed_line.t)
  =
  let args = Strace_parser.split_args line.args_raw in
  let arg_specs =
    match best_sig with
    | Some s -> Syscall_schema.Signature.args s
    | None -> []
  in
  let arg_lines =
    List.mapi args ~f:(fun i arg_raw ->
      let arg_raw = String.strip arg_raw in
      let spec = List.nth arg_specs i in
      let name_label =
        match spec with
        | Some s ->
          View.text
            ~attrs:[ Attr.fg theme.blue; Attr.bg theme.bg ]
            [%string "%{Syscall_schema.Arg_spec.name s}: "]
        | None ->
          View.text
            ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ]
            [%string "arg%{i#Int}: "]
      in
      let is_fd =
        match spec with
        | Some s ->
          Syscall_schema.Arg_type.is_file_descriptor (Syscall_schema.Arg_spec.arg_type s)
        | None -> false
      in
      let arg_raw =
        if is_fd then Display_utils.resolve_ips_in_string arg_raw ~dns_cache else arg_raw
      in
      let is_buffer = String.is_prefix arg_raw ~prefix:"\"" in
      let is_hexdump, value_view =
        render_arg_value
          ~theme
          ~render_mode
          ~width
          ~name_label
          ~is_buffer
          ~line
          ~arg_index:i
          ~args
          arg_raw
      in
      let fd_info =
        if is_fd
        then (
          match Strace_parser.extract_fd_number arg_raw with
          | Some fd_num ->
            (match Fd_tracker.lookup fd_tracker ~pid:line.pid ~fd_number:fd_num with
             | Some origin ->
               View.vcat
                 [ View.text
                     ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ]
                     [%string
                       "    \xe2\x86\xb3 fd %{fd_num#Int} from: \
                        %{Fd_tracker.Fd_origin.summary origin} (index \
                        #%{Fd_tracker.Fd_origin.syscall_index origin#Int})"]
                 ]
             | None -> View.none)
          | None -> View.none)
        else View.none
      in
      if is_hexdump
      then View.vcat [ name_label; value_view; fd_info ]
      else View.vcat [ View.hcat [ name_label; value_view ]; fd_info ])
  in
  View.vcat
    ([ Theme.section_header theme "Arguments" ]
     @ arg_lines
     @ [ View.text ~attrs:[ Attr.bg theme.bg ] "" ])
;;

let render_detail_result
  ~(theme : Theme.t)
  (line : Strace_parser.Parsed_line.t)
  ~best_sig
  ~dns_cache
  =
  View.vcat
    [ Theme.section_header theme "Result"
    ; (let is_fd =
         is_fd_return_type ~syscall_name:line.syscall_name ~args_raw:line.args_raw
       in
       let result =
         match is_fd, line.result with
         | true, Value v ->
           Strace_parser.Result.Value (Display_utils.resolve_ips_in_string v ~dns_cache)
         | _ -> line.result
       in
       render_result
         ~theme
         ~value_color:(if is_fd then theme.yellow else theme.green)
         result)
    ; (match best_sig with
       | Some s
         when Syscall_schema.Return_type.is_file_descriptor
                (Syscall_schema.Signature.return_type s) ->
         (match Strace_parser.extract_return_int line.result with
          | Some fd_num when fd_num >= 0 ->
            View.text
              ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ]
              [%string "  (new file descriptor %{fd_num#Int})"]
          | _ -> View.none)
       | _ -> View.none)
    ; View.text ~attrs:[ Attr.bg theme.bg ] ""
    ]
;;

let render_detail_raw ~(theme : Theme.t) (line : Strace_parser.Parsed_line.t) =
  View.vcat
    [ Theme.section_header theme "Raw"
    ; text ~theme line.raw_line
    ; View.text ~attrs:[ Attr.bg theme.bg ] ""
    ]
;;

let render_detail_man ~(theme : Theme.t) ~show_man_page ~man_page_content ~schema =
  if show_man_page
  then (
    match schema with
    | Some info ->
      let name = Syscall_schema.Syscall_info.name info in
      (match man_page_content with
       | Some content ->
         let man_lines =
           String.split_lines content
           |> List.map ~f:(fun line ->
             View.text ~attrs:[ Attr.fg theme.fg; Attr.bg theme.bg ] line)
         in
         View.vcat
           ([ Theme.section_header theme [%string "Man Page: %{name}"] ]
            @ man_lines
            @ [ View.text ~attrs:[ Attr.bg theme.bg ] "" ])
       | None ->
         View.vcat
           [ Theme.section_header theme "Man Page"
           ; dim_text ~theme [%string "Loading man page for %{name}..."]
           ; View.text ~attrs:[ Attr.bg theme.bg ] ""
           ])
    | None ->
      View.vcat
        [ Theme.section_header theme "Man Page"
        ; dim_text ~theme "No man page available for this syscall"
        ])
  else View.none
;;

let render_detail
  ~(theme : Theme.t)
  (line : Strace_parser.Parsed_line.t)
  ~fd_tracker
  ~dns_cache
  ~render_mode
  ~show_man_page
  ~man_page_content
  ~width
  ~pid_map
  =
  let schema = Syscall_schema.lookup line.syscall_name in
  let actual_args = Strace_parser.split_args line.args_raw in
  let best_sig =
    Option.map schema ~f:(fun info ->
      Syscall_schema.Syscall_info.best_signature info ~arg_count:(List.length actual_args))
  in
  let header = render_detail_header ~theme line ~schema ~pid_map in
  let args_section =
    render_detail_args ~theme ~render_mode ~width ~fd_tracker ~dns_cache ~best_sig line
  in
  let result_section = render_detail_result ~theme line ~best_sig ~dns_cache in
  let raw_section = render_detail_raw ~theme line in
  let man_section = render_detail_man ~theme ~show_man_page ~man_page_content ~schema in
  let content =
    View.pad
      ~l:1
      ~t:0
      (View.vcat [ header; args_section; result_section; raw_section; man_section ])
  in
  let content_width = View.width content in
  if content_width > width then View.crop ~r:(content_width - width) content else content
;;

(** The main app component.

    [model_var] is a mutable variable that is updated from outside the Bonsai computation
    by the strace pipe reader. The Bonsai computation reads from it to render the UI. User
    interactions (selection, filtering, etc.) also update it directly via [Var.update]. *)
let help_content : (string list * string) list =
  [ [ "F1"; "?" ], "Toggle this help"
  ; [ "Tab" ], "Switch focus between list and details"
  ; [ "f" ], "Edit filter expression"
  ; [ "/" ], "Grep (start regex filter)"
  ; [ "%" ], "Cycle family presets"
  ; [ "h" ], "Hide selected syscall"
  ; [ "H" ], "Show only selected syscall"
  ; [ "p" ], "Filter to selected PID"
  ; [ "P" ], "Exclude selected PID"
  ; [ "x" ], "Cycle display mode (auto/hex/str)"
  ; [ "m" ], "Toggle man page"
  ; [ "d"; "u" ], "Page down / up"
  ; [ "g"; "G" ], "Jump to top / bottom"
  ; [ "F" ], "Follow selected FD"
  ; [ "<"; ">" ], "Jump to prev / next syscall on same FD"
  ; [ "^" ], "Jump to FD origin (open/socket/etc.)"
  ; [ "Alt-f" ], "Clear filter"
  ; [ "Ctrl-c" ], "Quit"
  ]
;;

let render_help_modal ~(theme : Theme.t) ~width ~height =
  let max_key_width =
    List.fold help_content ~init:0 ~f:(fun acc (keys, _) ->
      let w =
        List.sum (module Int) keys ~f:String.length + (3 * (List.length keys - 1))
      in
      Int.max acc w)
  in
  let rows =
    List.map help_content ~f:(fun (keys, desc) ->
      let key_view =
        View.hcat
          (List.intersperse
             (List.map keys ~f:(fun k ->
                View.text ~attrs:[ Attr.fg theme.key_hint; Attr.bold; Attr.bg theme.bg ] k))
             ~sep:(View.text ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ] " / "))
      in
      let key_width = View.width key_view in
      let padding = Int.max 0 (max_key_width + 2 - key_width) in
      View.hcat
        [ key_view
        ; View.text ~attrs:[ Attr.bg theme.bg ] (String.make padding ' ')
        ; View.text ~attrs:[ Attr.fg theme.fg; Attr.bg theme.bg ] desc
        ])
  in
  let content =
    View.vcat
      ([ View.text
           ~attrs:[ Attr.fg theme.accent; Attr.bold; Attr.bg theme.bg ]
           "Keyboard Shortcuts"
       ; View.text ~attrs:[ Attr.bg theme.bg ] ""
       ]
       @ rows
       @ [ View.text ~attrs:[ Attr.bg theme.bg ] ""
         ; View.text ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ] "Esc to close"
         ])
  in
  let bordered =
    Bonsai_term_border_box.view
      ~line_type:Round_corners
      ~attrs:[ Attr.fg theme.accent; Attr.bg theme.bg ]
      ~left_padding:1
      ~right_padding:1
      content
  in
  View.center bordered ~within:{ Dimensions.width; height }
;;

let is_ctrl_key (event : Event.t) ~char =
  let lower = Char.lowercase char in
  let upper = Char.uppercase char in
  let code = Char.to_int lower - Char.to_int 'a' + 1 in
  match event with
  | Key_press { key = ASCII c; mods = [ Ctrl ] } ->
    Char.equal c lower || Char.equal c upper
  | Key_press { key = ASCII c; mods = _ } -> Char.to_int c = code
  | Key_press { key = Uchar uchar; mods = [ Ctrl ] } ->
    Uchar.equal uchar (Uchar.of_char lower) || Uchar.equal uchar (Uchar.of_char upper)
  | _ -> false
;;

let app
  ~dimensions
  ~(model_var : Model.t Bonsai.Expert.Var.t)
  ~(exit : (int -> unit Effect.t) Bonsai.t)
  (local_ graph)
  =
  let model = Bonsai.Expert.Var.value model_var in
  let theme =
    let%arr flavor = Bonsai_term_color_scheme.flavor graph in
    Theme.of_flavor flavor
  in
  let inject : (Action.t -> unit Effect.t) Bonsai.t =
    let%arr _ = dimensions in
    fun (action : Action.t) ->
      Effect.of_sync_fun
        (fun () ->
          Bonsai.Expert.Var.update model_var ~f:(fun model ->
            apply_action_pure model action))
        ()
  in
  (* Scroller for the left pane. Border boxes add 2 chars width each (left+right border),
     so we subtract 4 total for two boxes, then split the remaining space. *)
  let left_pane_dimensions =
    let%arr { Dimensions.width; height } = dimensions in
    let content_width = width - 4 in
    (* Golden ratio split: list gets ~38.2%, details gets ~61.8% *)
    let left_width = Int.min 50 (content_width * 382 / 1000) |> Int.max 10 in
    { Dimensions.width = left_width; height = Int.max 3 (height - 2) }
  in
  let right_pane_dimensions =
    let%arr { Dimensions.width; height } = dimensions
    and { Dimensions.width = left_width; _ } = left_pane_dimensions in
    let content_width = width - 4 in
    { Dimensions.width = Int.max 10 (content_width - left_width)
    ; height = Int.max 3 (height - 2)
    }
  in
  let left_content =
    let%arr model
    and theme
    and { Dimensions.width; height } = left_pane_dimensions in
    Virtual_list.render
      ~state:model.syscall_list
      ~viewport_height:height
      ~viewport_width:width
      ~render_item:(fun ~is_selected ~width line ->
        let selected_pid =
          match Model.get_selected model with
          | Some sel -> sel.pid
          | None -> -1
        in
        render_syscall_line
          ~theme
          line
          ~is_selected
          ~width
          ~pid_map:model.pid_map
          ~selected_pid)
      ~render_empty:(fun ~width ->
        View.center
          (dim_text ~theme "Waiting for syscalls...")
          ~within:{ width; height = 1 })
  in
  let left_view = left_content in
  let detail_view =
    let%arr model
    and theme
    and { Dimensions.width; _ } = right_pane_dimensions in
    match Model.get_selected model with
    | None ->
      View.center (dim_text ~theme "No syscall selected") ~within:{ width; height = 1 }
    | Some line ->
      let man_page_content = Map.find model.man_page_cache line.syscall_name in
      render_detail
        ~theme
        line
        ~fd_tracker:model.fd_tracker
        ~dns_cache:model.dns_cache
        ~render_mode:model.render_mode
        ~show_man_page:model.show_man_page
        ~man_page_content
        ~width
        ~pid_map:model.pid_map
  in
  (* Fetch man pages when needed *)
  let man_page_key =
    let%arr model in
    if model.Model.show_man_page
    then (
      match Model.get_selected model with
      | None -> None
      | Some line ->
        let name = line.syscall_name in
        if Map.mem model.man_page_cache name then None else Some name)
    else None
  in
  Bonsai.Edge.on_change
    ~equal:[%equal: string option]
    ~trigger:`Before_display
    man_page_key
    ~callback:
      (let%arr inject
       and { Dimensions.width = detail_width; _ } = right_pane_dimensions in
       fun name_opt ->
         match name_opt with
         | None -> Effect.Ignore
         | Some name ->
           let schema = Syscall_schema.lookup name in
           let section =
             match schema with
             | Some info -> Syscall_schema.Syscall_info.man_section info
             | None -> 2
           in
           let man_width = Int.to_string (Int.max 40 (detail_width - 2)) in
           Effect.of_deferred_fun
             (fun () ->
               let%map.Deferred result =
                 Process.run
                   ~prog:"man"
                   ~args:[ "--nj"; Int.to_string section; name ]
                   ~env:(`Extend [ "MANWIDTH", man_width ])
                   ()
               in
               match result with
               | Ok stdout -> stdout
               | Error _ -> [%string "Could not load man page for %{name}"])
             ()
           |> Effect.bind ~f:(fun content -> inject (Set_man_page { name; content })))
    graph;
  (* Resolve IP addresses in the selected syscall's args *)
  let unresolved_ips =
    let%arr model in
    match Model.get_selected model with
    | None -> []
    | Some line ->
      Display_utils.extract_ip_addresses line.args_raw
      |> List.filter ~f:(fun ip -> not (Map.mem model.dns_cache ip))
  in
  Bonsai.Edge.on_change
    ~equal:[%equal: string list]
    ~trigger:`Before_display
    unresolved_ips
    ~callback:
      (let%arr inject in
       fun ips ->
         List.map ips ~f:(fun ip ->
           Effect.of_deferred_fun
             (fun () ->
               let%map.Deferred hostname =
                 match%map.Deferred
                   Monitor.try_with (fun () ->
                     let addr = Unix.Inet_addr.of_string ip in
                     Unix.Host.getbyaddr_exn addr)
                 with
                 | Ok host_entry ->
                   let name = host_entry.name in
                   name
                 | Error _ -> ip
               in
               hostname)
             ()
           |> Effect.bind ~f:(fun hostname -> inject (Set_dns_entry { ip; hostname })))
         |> Effect.Many)
    graph;
  let detail_scroller =
    Bonsai_term_scroller.component
      ~crop_width_if_too_big:`No
      ~dimensions:right_pane_dimensions
      detail_view
      graph
  in
  let view =
    let%arr { Dimensions.width; height } = dimensions
    and model
    and theme
    and left_view
    and { Bonsai_term_scroller.view = right_view; _ } = detail_scroller in
    let left_focused = [%equal: Focus.t] model.focus Syscall_list in
    let right_focused = [%equal: Focus.t] model.focus Detail_pane in
    let left_bordered =
      let title_color = if left_focused then theme.accent else theme.dim in
      let tab = if left_focused then "" else " <tab>" in
      let box =
        Bonsai_term_border_box.view
          ~line_type:Round_corners
          ~attrs:[ Attr.fg title_color; Attr.bg theme.bg ]
          ~title:[%string "Syscalls%{tab}"]
          ~title_attrs:[ Attr.fg title_color; Attr.bold; Attr.bg theme.bg ]
          left_view
      in
      let box_width = View.width box in
      let box_height = View.height box in
      let title_len = String.length tab + 12 in
      let max_filter_chars = Int.max 5 (box_width - title_len - 1) in
      let filter_label =
        Filter_editor.render_label
          model.filter_editor
          ~current_filter:model.syscall_filter
          ~params:
            { key_hint_color = theme.key_hint
            ; title_color
            ; fg_color = theme.fg
            ; accent_color = theme.accent
            ; bg_color = theme.bg
            ; max_chars = max_filter_chars
            }
      in
      let filter_width = View.width filter_label in
      let padded_filter =
        View.pad ~l:(Int.max 0 (box_width - filter_width - 1)) filter_label
      in
      (* Scroll position in bottom-right corner *)
      let filtered_count = Model.filtered_count model in
      let total_str = Int.to_string filtered_count in
      let selected = Int.to_string (Model.selected_index model + 1) in
      let pos_label =
        View.text
          ~attrs:[ Attr.fg title_color; Attr.bg theme.bg ]
          [%string " %{selected}/%{total_str} "]
      in
      let pos_width = View.width pos_label in
      let padded_pos =
        View.pad ~l:(Int.max 0 (box_width - pos_width - 1)) ~t:(box_height - 1) pos_label
      in
      View.zcat [ padded_filter; padded_pos; box ]
    in
    let right_bordered =
      let title_color = if right_focused then theme.accent else theme.dim in
      let tab = if right_focused then "" else " <tab>" in
      let box =
        Bonsai_term_border_box.view
          ~line_type:Round_corners
          ~attrs:[ Attr.fg title_color; Attr.bg theme.bg ]
          ~title:[%string "Details%{tab}"]
          ~title_attrs:[ Attr.fg title_color; Attr.bold; Attr.bg theme.bg ]
          right_view
      in
      let hint_label =
        View.hcat
          [ View.text ~attrs:[ Attr.fg theme.key_hint; Attr.bold; Attr.bg theme.bg ] " x"
          ; View.text
              ~attrs:[ Attr.fg title_color; Attr.bold; Attr.bg theme.bg ]
              [%string ":%{Render_mode.to_short_string model.render_mode} "]
          ; View.text ~attrs:[ Attr.fg theme.key_hint; Attr.bold; Attr.bg theme.bg ] "m"
          ; View.text ~attrs:[ Attr.fg title_color; Attr.bold; Attr.bg theme.bg ] ":man "
          ]
      in
      let box_width = View.width box in
      let hint_width = View.width hint_label in
      let padded_hint = View.pad ~l:(Int.max 0 (box_width - hint_width - 1)) hint_label in
      View.zcat [ padded_hint; box ]
    in
    let panes = View.hcat [ left_bordered; right_bordered ] in
    let content = panes in
    let backdrop = View.rectangle ~height ~width ~attrs:[ Attr.bg theme.bg ] () in
    let base = View.zcat [ content; backdrop ] in
    if model.show_help
    then View.zcat [ render_help_modal ~theme ~width ~height; base ]
    else base
  in
  let handler =
    let%arr inject
    and model
    and { Bonsai_term_scroller.inject = detail_scroll_inject; _ } = detail_scroller
    and { Dimensions.height = left_height; _ } = left_pane_dimensions
    and exit in
    fun (event : Event.t) ->
      match event with
      | event when is_ctrl_key event ~char:'c' -> exit 0
      | Key_press { key = Function 1; mods = [] }
      | Key_press { key = ASCII '?'; mods = _ } -> inject Toggle_help
      | _ when model.show_help ->
        (* Help is showing: any key closes it *)
        inject Toggle_help
      | Key_press { key = Tab; mods = [] } | Key_press { key = Tab; mods = [ Shift ] } ->
        inject Toggle_focus
      | _ when Filter_editor.is_editing model.filter_editor ->
        (* Filter editing mode: capture all keys *)
        (match event with
         | Key_press { key = Enter; mods = [] } -> inject (Filter_edit Submit)
         | Key_press { key = Escape; mods = [] } -> inject (Filter_edit Cancel)
         | Key_press { key = Backspace; mods = [] } -> inject (Filter_edit Backspace)
         | Key_press { key = Delete; mods = [] } -> inject (Filter_edit Delete_forward)
         | Key_press { key = Arrow `Left; mods = [] } -> inject (Filter_edit Move_left)
         | Key_press { key = Arrow `Right; mods = [] } -> inject (Filter_edit Move_right)
         | Key_press { key = Home; mods = [] } -> inject (Filter_edit Move_to_start)
         | Key_press { key = End; mods = [] } -> inject (Filter_edit Move_to_end)
         | event when is_ctrl_key event ~char:'a' -> inject (Filter_edit Move_to_start)
         | event when is_ctrl_key event ~char:'e' -> inject (Filter_edit Move_to_end)
         | event when is_ctrl_key event ~char:'b' -> inject (Filter_edit Move_left)
         | event when is_ctrl_key event ~char:'f' -> inject (Filter_edit Move_right)
         | event when is_ctrl_key event ~char:'d' -> inject (Filter_edit Delete_forward)
         | event when is_ctrl_key event ~char:'k' -> inject (Filter_edit Kill_to_end)
         | event when is_ctrl_key event ~char:'u' -> inject (Filter_edit Kill_to_start)
         | event when is_ctrl_key event ~char:'w' ->
           inject (Filter_edit Kill_word_backward)
         | Key_press { key = ASCII ('f' | 'F'); mods = [ Meta ] } ->
           inject (Filter_edit Move_word_forward)
         | Key_press { key = ASCII ('b' | 'B'); mods = [ Meta ] } ->
           inject (Filter_edit Move_word_backward)
         | Key_press { key = ASCII c; mods = [] } -> inject (Filter_edit (Key c))
         | _ -> Effect.Ignore)
      | Key_press { key = ASCII 'f'; mods = [] } -> inject (Filter_edit Start)
      | Key_press { key = ASCII '/'; mods = [] } -> inject (Filter_edit Start_regex)
      | Key_press { key = ASCII '%'; mods = _ } -> inject Cycle_preset_filter
      | Key_press { key = ASCII 'h'; mods = [] } -> inject Hide_selected
      | Key_press { key = ASCII 'H'; mods = [] } -> inject Show_only_selected
      | Key_press { key = ASCII 'p'; mods = [] } -> inject Filter_selected_pid
      | Key_press { key = ASCII 'P'; mods = [] } -> inject Exclude_selected_pid
      | Key_press { key = ASCII 'x'; mods = [] } -> inject Toggle_render_mode
      | Key_press { key = ASCII 'm'; mods = [] } -> inject Toggle_man_page
      | Key_press { key = ASCII 'j' | Arrow `Down; mods = [] } ->
        (match model.focus with
         | Syscall_list -> inject Select_down
         | Detail_pane -> detail_scroll_inject Down)
      | Key_press { key = ASCII 'k' | Arrow `Up; mods = [] } ->
        (match model.focus with
         | Syscall_list -> inject Select_up
         | Detail_pane -> detail_scroll_inject Up)
      | Key_press { key = ASCII 'g'; mods = [] } ->
        (match model.focus with
         | Syscall_list -> inject Select_top
         | Detail_pane -> detail_scroll_inject Top)
      | Key_press { key = ASCII 'G'; mods = [] } ->
        (match model.focus with
         | Syscall_list -> inject Select_bottom
         | Detail_pane -> detail_scroll_inject Bottom)
      | Key_press { key = ASCII ('d' | 'D'); mods = [ Ctrl ] | [] }
      | Key_press { key = Page `Down; mods = [] } ->
        (match model.focus with
         | Syscall_list ->
           let filtered_count = Model.filtered_count model in
           let next =
             Int.min (filtered_count - 1) (Model.selected_index model + left_height)
           in
           inject (Jump_to_filtered_index next)
         | Detail_pane -> detail_scroll_inject Down_half_screen)
      | Key_press { key = ASCII ('u' | 'U'); mods = [ Ctrl ] | [] }
      | Key_press { key = Page `Up; mods = [] } ->
        (match model.focus with
         | Syscall_list ->
           let next = Int.max 0 (Model.selected_index model - left_height) in
           inject (Jump_to_filtered_index next)
         | Detail_pane -> detail_scroll_inject Up_half_screen)
      | Key_press { key = ASCII 'f'; mods = [ Meta ] } ->
        (* Alt-f: clear the filter *)
        inject (Set_filter "")
      | Key_press { key = ASCII '<'; mods = _ } -> inject Jump_fd_prev
      | Key_press { key = ASCII '>'; mods = _ } -> inject Jump_fd_next
      | Key_press { key = ASCII '^'; mods = _ } -> inject Jump_fd_origin
      | Key_press { key = ASCII 'F'; mods = [] } -> inject Follow_fd
      | _ -> Effect.Ignore
  in
  ~view, ~handler
;;

let command =
  Command.async_or_error
    ~summary:"strace-ui - interactive strace viewer"
    (let%map_open.Command anon_args = anon (maybe (sequence ("PROGRAM" %: string)))
     and escape_args = flag "--" escape ~doc:"PROGRAM run PROGRAM"
     and attach_pid = flag "-p" (optional int) ~doc:"PID Attach to an existing process"
     and trace_expr =
       flag
         "-e"
         (optional string)
         ~doc:"EXPR Trace expression passed to strace (e.g. trace=%net)"
     and flavor_name =
       let all_themes =
         List.map
           Bonsai_term_color_scheme.Flavor_name.all
           ~f:Bonsai_term_color_scheme.Flavor_name.to_string
         |> String.concat ~sep:", "
       in
       flag
         "-theme"
         (optional_with_default
            (Bonsai_term_color_scheme.Flavor_name.Catppuccin Mocha)
            (Arg_type.create Bonsai_term_color_scheme.Flavor_name.of_string))
         ~doc:[%string "THEME Color theme (%{all_themes})"]
     in
     fun () ->
       let open Deferred.Or_error.Let_syntax in
       (* Create a pipe for strace output. Using -o /dev/fd/N ensures strace always
          includes PIDs in the output, even for single-process traces. *)
       let strace_output_read_fd, strace_output_write_fd =
         Core_unix.pipe ~close_on_exec:false ()
       in
       let write_fd_int = Core_unix.File_descr.to_int strace_output_write_fd in
       let strace_args =
         [ "-ttt"
         ; "-T"
         ; "-f"
         ; "-x"
         ; "-yy"
         ; "-v"
         ; "-s"
         ; "1024"
         ; "-o"
         ; [%string "/dev/fd/%{write_fd_int#Int}"]
         ]
         @ (match trace_expr with
            | Some expr -> [ "-e"; expr ]
            | None -> [])
         @
         match attach_pid with
         | Some pid -> [ "-p"; Int.to_string pid ]
         | None ->
           let program_and_args =
             Option.value anon_args ~default:[] @ Option.value escape_args ~default:[]
           in
           (match program_and_args with
            | prog :: args -> [ "--"; prog ] @ args
            | [] -> raise_s [%message "Must specify either -p PID or a program to trace"])
       in
       let%bind strace_process = Process.create ~prog:"strace" ~args:strace_args () in
       (* Close the write end in the parent so we get EOF when strace exits *)
       Core_unix.close strace_output_write_fd;
       let reader =
         Reader.create
           (Fd.create Char strace_output_read_fd (Info.of_string "strace-output"))
       in
       let pipe = Reader.lines reader in
       let model_var =
         Bonsai.Expert.Var.create (default_model ?primary_pid:attach_pid ())
       in
       (* Read strace lines in the background and update the model *)
       don't_wait_for
         (Pipe.iter_without_pushback pipe ~f:(fun line ->
            Bonsai.Expert.Var.update model_var ~f:(fun model ->
              apply_action_pure model (Add_line line))));
       let strace_error : string option ref = ref None in
       let exit_ref : (int -> unit Effect.t) ref = ref (fun _ -> Effect.Ignore) in
       (* Monitor strace for early exit (e.g. bad -e expression). Only exit the app if
          strace itself failed before it could start tracing. If strace already produced
          output (next_index > 0), the nonzero exit is from the traced program, not
          strace. *)
       don't_wait_for
         (let%bind.Deferred exit_status = Process.wait strace_process in
          match exit_status with
          | Ok () -> Deferred.unit
          | Error _ ->
            let model = Bonsai.Expert.Var.get model_var in
            if model.next_index > 0
            then
              (* strace successfully started and produced output; the nonzero exit is from
                 the traced program. Keep running so the user can browse. *)
              Deferred.unit
            else (
              let%map.Deferred stderr_first_line =
                let%map.Deferred result =
                  Reader.read_line (Process.stderr strace_process)
                in
                match result with
                | `Ok line -> line
                | `Eof -> ""
              in
              let stderr_first_line = String.strip stderr_first_line in
              strace_error
              := Some
                   (if String.is_empty stderr_first_line
                    then "strace exited with an error"
                    else [%string "strace: %{stderr_first_line}"]);
              Bonsai.Effect.Expert.handle ~on_exn:ignore (!exit_ref 1)));
       let flavor = Bonsai_term_color_scheme.Flavor_name.to_flavor flavor_name in
       let%bind.Deferred result =
         Bonsai_term.start_with_exit (fun ~exit ~dimensions graph ->
           exit_ref := exit;
           Bonsai_term_color_scheme.set_flavor_within_app
             (Bonsai.return flavor)
             (fun graph -> app ~dimensions ~model_var ~exit:(Bonsai.return exit) graph)
             graph)
       in
       let%bind (_ : int) = Deferred.return result in
       (* Kill strace when the app exits *)
       let (_ : [ `Ok | `No_such_process ]) =
         Signal_unix.send Signal.term (`Pid (Process.pid strace_process))
       in
       match !strace_error with
       | Some msg -> Deferred.Or_error.error_string msg
       | None -> Deferred.Or_error.return ())
;;
