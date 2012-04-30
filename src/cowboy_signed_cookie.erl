-module(cowboy_signed_cookie).

-export([set_resp_cookie/4, cookie/2, cookie/3]).

-include_lib("cowboy/include/http.hrl").

-spec set_resp_cookie(binary(), binary(), term(), #http_req{}) -> {ok, #http_req{}w}.
set_resp_cookie(Name, Value, Options, Req) ->
    Mac = create_hmac(Value),
    {ok, Req1} = cowboy_http_req:set_resp_cookie(Name, Value, Options, Req),
    {ok, Req2} = cowboy_http_req:set_resp_cookie(<<Name/binary, "_s">>, Mac, Options, Req1),
    {ok, Req2}.

-spec cookie(binary(), #http_req{}) -> {any(), #http_req{}}.
cookie(Name, Req) when is_binary(Name) ->
    cookie(Name, Req, undefined).

-spec cookie(binary(), binary(), #http_req{}) -> {any(), #http_req{}}.
cookie(Name, Req, Default) when is_binary(Name) ->
    case cowboy_http_req:cookie(Name, Req) of
	{undefined, Req1} ->
	    {Default, Req1};
	{Name, Value} ->
	    validate_hmac(Name, Value, Req)
    end.

-spec validate_hmac(binary(), binary(), #http_req{}) -> {invalid_cookie, #http_req{}} | {binary(), #http_req{}}.
validate_hmac(Name, Value, Req) ->
    Name1 = <<Name/binary, "_s">>,
    case cowboy_http_req:cookie(Name1, Req) of
	{undefined, Req1} ->
	    {invalid_cookie, Req1}; %% @todo invalidate cookies
	{Name1, Mac} ->
	    {validate_hmac(Value, Mac), Req}
    end.

-spec validate_hmac(binary(), binary()) -> binary() | invalid_cookie.
validate_hmac(Value, Mac) ->
    Mac1 = create_hmac(Value),
    if Mac1 =:= Mac ->
	    Value;
       true ->
	    invalid_cookie
    end.

-spec create_hmac(binary()) -> binary().
create_hmac(Value) ->
    {ok, Secret} = application:get_env(app_secret),
    C1 = crypto:hmac_init(sha, Secret),
    C2 = crypto:hmac_update(C1, Value),
    crypto:hmac_final(C2).
