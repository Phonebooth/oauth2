-module(oauth2).

-export([authorize/4, authorize/6]).
-export([verify_token/3, verify_token/4, verify_token/5]).
-export([invalidate_token/3]).
-export([calculate_expires_in/1, microseconds_since_epoch/1, calculate_expires_in_sec/1]).

-include_lib("include/oauth2.hrl").

-define(DEF_AUTH_CODE_EXPIRE, 2 * 60 * 1000000).
-define(DEF_ACCESS_TOKEN_EXPIRE, 60 * 60 * 2 * 1000000).
-define(BEARER_TOKEN_TYPE, "Bearer").

authorize(client_credentials, Db, ClientId, Scope) ->
    Data = #oauth2{client_id=ClientId,
                   expires=microseconds_since_epoch(?DEF_ACCESS_TOKEN_EXPIRE),
                   scope=Scope},
    AccessToken = generate_access_token(),
    Db:set(access, AccessToken, Data),
    {ok, [{access_token, AccessToken},
            {token_type, ?BEARER_TOKEN_TYPE},
            {expires_in, calculate_expires_in_sec(Data#oauth2.expires)}
        ]}.

authorize(ResponseType, Db, ClientId, RedirectUri, Scope, State) ->
    case Db:verify_redirect_uri(ClientId, RedirectUri) of
        false ->
            {error, redirect_uri_mismatch};
        true ->
            {Code, Expires} = case ResponseType of
                token ->
                    Data = #oauth2{client_id=ClientId,
                                   expires=microseconds_since_epoch(?DEF_ACCESS_TOKEN_EXPIRE),
                                   scope=Scope},
                    AccessToken = generate_access_token(),
                    Db:set(access, AccessToken, Data),
                    {AccessToken, Data#oauth2.expires};
                code ->
                    Data = #oauth2{client_id=ClientId,
                                   expires=microseconds_since_epoch(?DEF_AUTH_CODE_EXPIRE),
                                   scope=Scope},
                    AuthCode = generate_auth_code(),
                    Key = generate_key(ClientId, AuthCode),
                    Db:set(auth, Key, Data),
                    {AuthCode, Data#oauth2.expires}
            end,
            NewRedirectUri = get_redirect_uri(ResponseType, {Code, Expires}, RedirectUri, State),
            {ok, Code, NewRedirectUri, calculate_expires_in_sec(Expires)}
    end.

verify_token(access_token, Db, Token) ->
    case Db:get(access, Token) of
        {ok, Data} ->
            ClientId = Data#oauth2.client_id,
            Expires = Data#oauth2.expires,
            Scope = Data#oauth2.scope,

            case calculate_expires_in(Expires) > 0 of
                false ->
                    Db:delete(access,  Token),
                    {error, invalid_token};
                true ->
                    {ok, [{audience, ClientId},
                          {scope, Scope},
                          {expires_in, calculate_expires_in_sec(Expires)}
                         ]}
            end;
        _ ->
            {error, invalid_token}
    end.

verify_token(_, _Db, _Token, _ClientId) ->
    {error, invalid_token}.

verify_token(authorization_code, Db, Token, ClientId, RedirectUri) ->
    case Db:verify_redirect_uri(ClientId, RedirectUri) of
        false ->
            {error, redirect_uri_mismatch};
        true ->
            case Db:get(auth, generate_key(ClientId, Token)) of
                {ok, Data} ->
                    ClientId = Data#oauth2.client_id,
                    Expires = Data#oauth2.expires,
                    Scope = Data#oauth2.scope,
                    Db:delete(auth,  generate_key(ClientId, Token)),

                    case calculate_expires_in(Expires) > 0 of
                        false ->
                            {error, invalid_grant};
                        true ->
                            AccessToken = generate_access_token(),
                            AccessData = #oauth2{client_id=ClientId,
                                                 expires=microseconds_since_epoch(?DEF_ACCESS_TOKEN_EXPIRE),
                                                 scope=Scope},
                            Db:set(access, AccessToken, AccessData),

                            {ok, [{access_token, AccessToken},
                                  {token_type, ?BEARER_TOKEN_TYPE},
                                  {expires_in, calculate_expires_in_sec(AccessData#oauth2.expires)}
                                 ]}
                    end;
                _ ->
                    {error, invalid_grant}
            end
    end;
verify_token(_, _Db, _Token, _ClientId, _RedirectUri) ->
    {error, invalid_token}.

invalidate_token(access_token, Db, Token) ->
    Db:delete(access, Token),
    ok.

%% Internal API
%%
get_redirect_uri(Type, Code, Uri, State) ->
    get_redirect_uri(Type, Code, Uri, State, []).

get_redirect_uri(Type, {Code, Expires}, Uri, State, _ExtraQuery) ->
    {S, N, P, Q, _} = mochiweb_util:urlsplit(Uri),
    State2 = case State of
        "" -> [];
        undefined -> [];
        StateVal -> [{state, StateVal}]
    end,
    Q2 = mochiweb_util:parse_qs(Q),
    case Type of
        token ->
            CF = [{access_token, Code}, 
                  {expires_in, calculate_expires_in_sec(Expires)}, 
                  {token_type, ?BEARER_TOKEN_TYPE}] ++ State2,
            CF2 = mochiweb_util:urlencode(CF),
            Query = mochiweb_util:urlencode(Q2),
            mochiweb_util:urlunsplit({S, N, P, Query, CF2});
        code ->
            CF = [{code, Code}],
            Q3 = lists:append([CF, State2, Q2]),
            Query = mochiweb_util:urlencode(Q3),
            mochiweb_util:urlunsplit({S, N, P, Query, ""})
    end.

generate_key(ClientId, AuthCode) ->
    lists:flatten([ClientId, "#", AuthCode]).

generate_access_token() ->
    strong_random_hex(32).

generate_auth_code() ->
    strong_random_hex(32).

strong_random_hex(Length) when (Length rem 2 =:= 0) ->
    RandBytes = case catch crypto:strong_rand_bytes(Length div 2) of
        {'EXIT', {low_entropy, _}} ->
            crypto:rand_bytes(Length div 2);
        Value ->
            Value
    end,
    binary_to_base16(RandBytes).

binary_to_base16(Bin) ->
    binary_to_base16(Bin, []).

binary_to_base16(<<>>, Result) ->
    lists:reverse(Result);
binary_to_base16(<<N:4, Rest/bitstring>>, Result) when N =< 9 ->
    binary_to_base16(Rest, [48+N|Result]);
binary_to_base16(<<N:4, Rest/bitstring>>, Result) ->
    binary_to_base16(Rest, [97+(N-10)|Result]).

calculate_expires_in_sec(Expire) ->
    erlang:trunc(calculate_expires_in(Expire) / 1000000).

calculate_expires_in(Expire) -> 
    Expire - microseconds_since_epoch(0).

microseconds_since_epoch(Diff) ->
    {Mega, Secs, Micro} = now(),
    (Mega * 1000000 + Secs)*1000000 + Micro + Diff.

