open! Core

module Result = struct
  type t =
    | Value of string
    | Error of
        { errno : string
        ; description : string
        }
    | Unfinished
    | Resumed of t
    | Signal of string
    | Exit of string
  [@@deriving sexp_of]
end

module Parsed_line = struct
  type t =
    { index : int
    ; pid : int
    ; timestamp : float
    ; syscall_name : string
    ; args_raw : string
    ; result : Result.t
    ; duration : float option
    ; raw_line : string
    }
  [@@deriving sexp_of, fields ~getters]
end

open Angstrom
open Angstrom.Let_syntax

let is_digit c = Char.is_digit c
let is_whitespace c = Char.is_whitespace c
let whitespace = skip_while is_whitespace
let digits = take_while1 is_digit
let integer = digits >>| Int.of_string

let float_number =
  let%bind whole = digits in
  let%bind dot = char '.' in
  let%bind frac = digits in
  return (Float.of_string (whole ^ String.of_char dot ^ frac))
;;

(* Parse duration: <0.000910> *)
let _duration =
  char '<' *> take_while1 (fun c -> Char.is_digit c || Char.equal c '.')
  <* char '>'
  >>| Float.of_string
;;

(* Parse the result portion: "= value", "= -1 ERRNO (desc)", or "<unfinished ...>" *)
let parse_result =
  let errno_result =
    let%bind _ = string "= " in
    let%bind _neg = string "-1 " in
    let%bind errno = take_while1 (fun c -> Char.is_uppercase c || Char.is_digit c) in
    let%bind _ = whitespace in
    let%bind description =
      char '(' *> take_while1 (fun c -> not (Char.equal c ')')) <* char ')'
    in
    return (Result.Error { errno; description })
  in
  let value_result =
    let%bind _ = string "= " in
    let%bind rest = take_while (fun _ -> true) in
    return (Result.Value (String.strip rest))
  in
  let unfinished = string "<unfinished ...>" *> return Result.Unfinished in
  unfinished <|> errno_result <|> value_result
;;

(* Extract a trailing duration from a result value string. "3<UNIX-STREAM:[123]>
   <0.000025>" -> ("3<UNIX-STREAM:[123]>", Some 0.000025) "0 <0.000025>" -> ("0", Some
   0.000025) "0" -> ("0", None) *)
let extract_duration_from_value s =
  let s = String.rstrip s in
  match String.rsplit2 s ~on:'<' with
  | Some (before, after) when String.is_suffix after ~suffix:">" ->
    let dur_str = String.chop_suffix_exn after ~suffix:">" |> String.strip in
    (match Float.of_string_opt dur_str with
     | Some d -> String.rstrip before, Some d
     | None -> s, None)
  | _ -> s, None
;;

(* Parse result + optional duration *)
let result_and_duration =
  let%bind result = parse_result in
  match result with
  | Value v ->
    let v, dur = extract_duration_from_value v in
    return (Result.Value (String.strip v), dur)
  | Error _ ->
    (* Consume any trailing whitespace and duration *)
    let%bind rest = take_while (fun _ -> true) in
    let _, dur = extract_duration_from_value rest in
    return (result, dur)
  | other -> return (other, None)
;;

(* Collect args up to the matching close paren, handling nesting and quoted strings *)
let args_until_close_paren =
  let buf = Buffer.create 128 in
  let rec go depth =
    any_char
    >>= fun c ->
    match c with
    | ')' when depth = 0 ->
      let result = Buffer.contents buf in
      Buffer.clear buf;
      return result
    | ')' ->
      Buffer.add_char buf c;
      go (depth - 1)
    | '(' ->
      Buffer.add_char buf c;
      go (depth + 1)
    | '"' ->
      Buffer.add_char buf c;
      quoted_string buf >>= fun () -> go depth
    | _ ->
      Buffer.add_char buf c;
      go depth
  and quoted_string buf =
    any_char
    >>= fun c ->
    Buffer.add_char buf c;
    match c with
    | '"' -> return ()
    | '\\' ->
      (* Consume the next char as part of the escape *)
      any_char
      >>= fun c2 ->
      Buffer.add_char buf c2;
      quoted_string buf
    | _ -> quoted_string buf
  in
  go 0
;;

(* Parse a signal line: --- SIGCHLD ... --- *)
let signal_line = string "---" *> take_while (fun _ -> true) >>| fun rest -> "---" ^ rest

(* Parse an exit line: +++ exited with 0 +++ *)
let exit_line = string "+++" *> take_while (fun _ -> true) >>| fun rest -> "+++" ^ rest

(* Parse a resumed line: <... name resumed>remaining_args) = result <duration> *)
let resumed_line =
  let%bind _ = string "<... " in
  let%bind name = take_while1 (fun c -> not (Char.is_whitespace c)) in
  let%bind _ = whitespace *> string "resumed>" in
  let%bind after_gt = take_while (fun _ -> true) in
  (* Split on ") = " to separate remaining args from result *)
  let args_raw, after_close =
    match String.substr_index after_gt ~pattern:") = " with
    | Some idx ->
      let args = String.prefix after_gt idx in
      let rest = String.drop_prefix after_gt (idx + 2) in
      String.strip args, String.lstrip rest
    | None ->
      let args = String.rstrip after_gt |> String.chop_suffix_if_exists ~suffix:")" in
      String.strip args, ""
  in
  (* Parse the result and duration from after_close *)
  let result, dur =
    match parse_string ~consume:Consume.All result_and_duration after_close with
    | Ok (result, dur) -> result, dur
    | _ -> Result.Value (String.strip after_close), None
  in
  return (name, args_raw, Result.Resumed result, dur)
;;

(* Parse a normal syscall: name(args) = result <duration> *)
let normal_syscall =
  let%bind name = take_while1 (fun c -> not (Char.equal c '(')) in
  let%bind _ = char '(' in
  let%bind rest = take_while (fun _ -> true) in
  let name = String.strip name in
  (* Check for unfinished *)
  if String.is_suffix (String.rstrip rest) ~suffix:"<unfinished ...>"
  then (
    let args_raw =
      String.chop_suffix_exn (String.rstrip rest) ~suffix:"<unfinished ...>"
      |> String.rstrip
    in
    return (name, args_raw, Result.Unfinished, None))
  else (
    (* Find the matching close paren using the buffer-based approach *)
    match parse_string ~consume:Consume.Prefix args_until_close_paren rest with
    | Error _ -> fail "could not find matching close paren"
    | Ok args_raw ->
      let after_close_start = String.length args_raw + 1 in
      let after_close =
        if after_close_start >= String.length rest
        then ""
        else String.drop_prefix rest after_close_start |> String.lstrip
      in
      let result, dur =
        match parse_string ~consume:Consume.All result_and_duration after_close with
        | Ok (result, dur) -> result, dur
        | _ -> Result.Value (String.strip after_close), None
      in
      return (name, args_raw, result, dur))
;;

(* Top-level line parser *)
let strace_line =
  let%bind pid = integer in
  let%bind _ = whitespace in
  let%bind timestamp = float_number in
  let%bind _ = whitespace in
  (* Dispatch based on what follows the timestamp *)
  let%bind name, args_raw, result, duration =
    signal_line
    >>| (fun s -> "<<signal>>", "", Result.Signal s, None)
    <|> (exit_line >>| fun s -> "<<exit>>", "", Result.Exit s, None)
    <|> resumed_line
    <|> normal_syscall
  in
  return (pid, timestamp, name, args_raw, result, duration)
;;

let parse_line ~index line : Parsed_line.t option =
  let line_stripped = String.lstrip line in
  match parse_string ~consume:Consume.All strace_line line_stripped with
  | Ok (pid, timestamp, syscall_name, args_raw, result, duration) ->
    Some
      { Parsed_line.index
      ; pid
      ; timestamp
      ; syscall_name
      ; args_raw
      ; result
      ; duration
      ; raw_line = line_stripped
      }
  | Error _ -> None
;;

let merge_resumed ~(original : Parsed_line.t) ~(resumed : Parsed_line.t) : Parsed_line.t =
  let left = String.rstrip original.args_raw in
  let right = String.lstrip resumed.args_raw in
  let args_raw =
    if String.is_empty left
    then right
    else if String.is_empty right
    then left
    else (
      let left = String.chop_suffix_if_exists left ~suffix:"," |> String.rstrip in
      left ^ ", " ^ right)
  in
  let result =
    match resumed.result with
    | Resumed actual -> actual
    | other -> other
  in
  { original with
    args_raw
  ; result
  ; duration = resumed.duration
  ; raw_line = original.raw_line ^ " ... " ^ resumed.raw_line
  }
;;

let split_args raw_args =
  if String.is_empty (String.strip raw_args)
  then []
  else Display_utils.split_top_level raw_args ~on:',' |> List.map ~f:String.strip
;;

let extract_fd_number arg_str =
  let s = String.strip arg_str in
  match String.lsplit2 s ~on:'<' with
  | Some (num_str, _) -> Int.of_string_opt (String.strip num_str)
  | None -> if String.is_prefix s ~prefix:"AT_FDCWD" then None else Int.of_string_opt s
;;

let extract_return_int (result : Result.t) =
  match result with
  | Value s ->
    let s = String.strip s in
    (match String.lsplit2 s ~on:'<' with
     | Some (num_str, _) -> Int.of_string_opt (String.strip num_str)
     | None ->
       if String.is_prefix s ~prefix:"0x"
       then (
         try Some (Int.of_string s) with
         | _ -> None)
       else (
         match String.lsplit2 s ~on:' ' with
         | Some (num_str, _) -> Int.of_string_opt (String.strip num_str)
         | None -> Int.of_string_opt s))
  | _ -> None
;;
