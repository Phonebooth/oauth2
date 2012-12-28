-module(oauth2).

-export([authorize/4, authorize/5, authorize/6]).
-export([verify_token/3, verify_token/5]).
-export([invalidate_token/3]).
-export([calculate_expires_in/1, microseconds_since_epoch/1, calculate_expires_in_sec/1]).

-include_lib("include/oauth2.hrl").

-define(DEF_AUTH_CODE_EXPIRE, 2 * 60 * 1000000).
-define(DEF_ACCESS_TOKEN_EXPIRE, 60 * 60 * 2 * 1000000).
-define(BEARER_TOKEN_TYPE, "Bearer").

%% Creates an access token for a client_credentials grant. The client is authenticated in the web layer.
authorize(client_credentials, Db, ClientId, Scope) ->
    success_response(create_access_token(Db, ClientId, Scope, true)).

%% Exchanges a refresh token for a new access token.
authorize(refresh_token, Db, RefreshToken, ClientId, Scope) ->
    case is_refresh_enabled(Db, ClientId) of
        true ->
            case Db:get(refresh, RefreshToken) of
                {ok, #oauth2{client_id=ClientId, scope=Scope, related=OldAccessToken}} ->
                    {NewAccessToken, NewAccessTokenData, NewRefreshToken} = create_access_token(Db, ClientId, Scope, true),
                    Db:redeem(refresh, RefreshToken, OldAccessToken, NewAccessToken),
                    success_response({NewAccessToken, NewAccessTokenData, NewRefreshToken});
                _ ->
                    {error, invalid_token}
            end;
        _ ->
            {error, insufficient_client_privileges}
    end.


%% Creates either an authorization code or an access token depending on the
%% specified response type. 'token' indicates the implicit flow and creates
%% an access token. 'code' indicates the authorization_code flow and creates
%% a short-lived authorization code.
authorize(ResponseType, Db, ClientId, RedirectUri, Scope, State) ->
    case Db:verify_redirect_uri(ClientId, RedirectUri) of
        false ->
            {error, redirect_uri_mismatch};
        true ->
            {Code, Expires} = case ResponseType of
                token ->
                    % this is the implicit flow, so no refresh token ever
                    {AccessToken, AccessTokenData, _} = create_access_token(Db, ClientId, Scope, false),
                    {AccessToken, AccessTokenData#oauth2.expires};
                code ->
                    {AuthCode, AuthCodeData} = create_auth_code(Db, ClientId, Scope),
                    {AuthCode, AuthCodeData#oauth2.expires}
            end,
            NewRedirectUri = get_redirect_uri(ResponseType, {Code, Expires}, RedirectUri, State),
            {ok, Code, NewRedirectUri, calculate_expires_in_sec(Expires)}
    end.

%% Verifies the validity of an access token and, given that the token is
%% valid, returns the data associated with that token.
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

%% Verifies the validity of an authorization code and, given that the code
%% is valid, exchanges the authorization code for an access token.
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
                            success_response(create_access_token(Db, ClientId, Scope, is_refresh_enabled(Db, ClientId)))
                    end;
                _ ->
                    {error, invalid_grant}
            end
    end;
verify_token(_, _Db, _Token, _ClientId, _RedirectUri) ->
    {error, invalid_token}.

invalidate_token(access_token, Db, Token) ->
    case Db:get(access, Token) of
        {ok, #oauth2{related=undefined}} ->
            ok;
        {ok, #oauth2{related=Refresh}} ->
            Db:delete(refresh, Refresh);
        _ ->
            ok
    end,
    Db:delete(access, Token),
    ok.

%% Internal API
%%

create_auth_code(Db, ClientId, Scope) ->
    AuthCode = generate_auth_code(),
    Key = generate_key(ClientId, AuthCode),
    AuthCodeData = #oauth2{
        client_id=ClientId,
        scope=Scope,
        expires=microseconds_since_epoch(?DEF_AUTH_CODE_EXPIRE)
    },
    Db:set(auth, Key, AuthCodeData),
    {AuthCode, AuthCodeData}.

create_access_token(Db, ClientId, Scope, HasRefresh) ->
    AccessToken = generate_access_token(),
    RefreshToken = case HasRefresh of
        true ->
            RT = generate_access_token(),
            RTData = #oauth2{client_id=ClientId, scope=Scope, related=AccessToken},
            Db:set(refresh, RT, RTData),
            RT;
        _ ->
            undefined
    end,
    AccessTokenData = #oauth2{
        client_id=ClientId, 
        scope=Scope, 
        expires=microseconds_since_epoch(?DEF_ACCESS_TOKEN_EXPIRE),
        related=RefreshToken
    },
    Db:set(access, AccessToken, AccessTokenData),
    {AccessToken, AccessTokenData, RefreshToken}.

success_response({AccessToken, #oauth2{expires=Expires}, RefreshToken}) ->
    {ok, [{access_token, AccessToken},
            {token_type, ?BEARER_TOKEN_TYPE},
            {expires_in, calculate_expires_in_sec(Expires)},
            {refresh_token, RefreshToken}
        ]}.

is_refresh_enabled(Db, ClientId) ->
    Db:verify_client_capability(ClientId, refresh_tokens).

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

