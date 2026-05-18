open! Core

(** strace-ui - an interactive TUI for strace.

    Runs strace on a given process or command and displays the syscall trace in a two-pane
    layout: syscall list on the left, details on the right. *)

module Model : sig
  type t [@@deriving sexp_of]

  val selected_index : t -> int
  val fd_tracker : t -> Fd_tracker.t
  val pid_map : t -> Pid_map.t
end

module Action : sig
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

val default_model
  :  ?primary_pid:int
  -> ?resolve_pid_info:(int -> Pid_map.Pid_info.t option)
  -> unit
  -> Model.t

val apply_action_pure : Model.t -> Action.t -> Model.t
val filtered_syscalls : Model.t -> Strace_parser.Parsed_line.t list

val app
  :  dimensions:Bonsai_term.Dimensions.t Bonsai.t
  -> model_var:Model.t Bonsai.Expert.Var.t
  -> exit:(int -> unit Bonsai_term.Effect.t) Bonsai.t
  -> local_ Bonsai.graph
  -> view:Bonsai_term.View.t Bonsai.t
     * handler:(Bonsai_term.Event.t -> unit Bonsai_term.Effect.t) Bonsai.t

val command : Command.t
