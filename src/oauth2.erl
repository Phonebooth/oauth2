-module(oauth2).

-export([authorize/4, authorize/6]).
-export([verify_token/3, verify_token/4, verify_token/5]).

-include_lib("include/oauth2.hrl").

-define(DEF_AUTH_CODE_EXPIRE, 30).
-define(DEF_ACCESS_TOKEN_EXPIRE, 60 * 60 *2).
-define(BEARER_TOKEN_TYPE, "Bearer").

authorize(client_credentials, Db, ClientId, Scope) ->
    Data = #oauth2{client_id=ClientId,
                   expires=seconds_since_epoch(?DEF_ACCESS_TOKEN),
                   scope=Scope},
    AccessToken = generate_access_token(Data#oauth2.expires, ClientId),
    Db:set(access, AccessToken, Data),
    {AccessToken, Data#oauth2.expires}.

authorize(ResponseType, Db, ClientId, RedirectUri, Scope, State) ->
    case Db:verify_redirect_uri(ClientId, RedirectUri) of
        false ->
            {error, redirect_uri_mismatch};
        true ->
            {Code, Expires} = case ResponseType of
                token ->
                    Data = #oauth2{client_id=ClientId,
                                   expires=seconds_since_epoch(?DEF_ACCESS_TOKEN_EXPIRE),
                                   scope=Scope},
                    AccessToken = generate_access_token(Data#oauth2.expires, ClientId),
                    Db:set(access, AccessToken, Data),
                    {AccessToken, Data#oauth2.expires};
                code ->
                    Data = #oauth2{client_id=ClientId,
                                   expires=seconds_since_epoch(?DEF_AUTH_CODE_EXPIRE),
                                   scope=Scope},
                    AuthCode = generate_auth_code(),
                    Key = generate_key(ClientId, AuthCode),
                    Db:set(auth, Key, Data),
                    {AuthCode, Data#oauth2.expires}
            end,
            NewRedirectUri = get_redirect_uri(ResponseType, {Code, Expires}, RedirectUri, State),
            {ok, Code, NewRedirectUri, calculate_expires_in(Expires)}
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
                          {expires_in, calculate_expires_in(Expires)}
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
                            AccessToken = generate_access_token(Expires, ClientId),
                            AccessData = #oauth2{client_id=ClientId,
                                                 expires=seconds_since_epoch(?DEF_ACCESS_TOKEN_EXPIRE),
                                                 scope=Scope},
                            Db:set(access, AccessToken, AccessData),

                            {ok, [{access_token, AccessToken},
                                  {token_type, ?BEARER_TOKEN_TYPE},
                                  {expires_in, calculate_expires_in(AccessData#oauth2.expires)}
                                 ]}
                    end;
                _ ->
                    {error, invalid_grant}
            end
    end;
verify_token(_, _Db, _Token, _ClientId, _RedirectUri) ->
    {error, invalid_token}.

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
            Q3 = lists:append([State2, Q2]),
            CF = [{access_token, Code}, 
                  {expires_in, calculate_expires_in(Expires)}, 
                  {token_type, ?BEARER_TOKEN_TYPE}],
            CF2 = mochiweb_util:urlencode(CF),
            Query = mochiweb_util:urlencode(Q3),
            mochiweb_util:urlunsplit({S, N, P, Query, CF2});
        code ->
            CF = [{code, Code}],
            Q3 = lists:append([CF, State2, Q2]),
            Query = mochiweb_util:urlencode(Q3),
            mochiweb_util:urlunsplit({S, N, P, Query, ""})
    end.

generate_key(ClientId, AuthCode) ->
    lists:flatten([ClientId, "#", AuthCode]).

generate_access_token(Expires, ClientId) ->
    S1 = generate_rnd_chars(15),
    S2 = generate_rnd_chars(15),
    S3 = binary_to_list(crypto:md5(ClientId)),
    Token = string:join([S1, S2, integer_to_list(Expires), S3], "."),
    mochiweb_util:quote_plus(base64:encode_to_string(Token)).

generate_auth_code() ->
    generate_rnd_chars(30).

generate_rnd_chars(N) ->
    Chars = list_to_tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"),
    random:seed(now()),
    rnd_auth(N, Chars).

rnd_auth(0, _) ->
    [];
rnd_auth(Len, C) ->
    [rnd_auth(C)|rnd_auth(Len-1, C)].
rnd_auth(C) ->
    element(random:uniform(tuple_size(C)), C).

calculate_expires_in(Expire) ->
    Expire - seconds_since_epoch(0).

seconds_since_epoch(Diff) ->
    {Mega, Secs, _Micro} = now(),
    Mega * 1000000 + Secs + Diff.

