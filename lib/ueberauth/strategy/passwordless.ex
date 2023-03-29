defmodule Ueberauth.Strategy.Passwordless do
  @moduledoc """
  Passwordless Strategy for Ueberauth

  ### Setup

  Create a Module which implements the behaviour specified in Ueberauth.Strategy.Passwordless.Mailer.

  Include the provider in your configuration for Ueberauth

      config :ueberauth, Ueberauth,
        providers: [
          passwordless: {Ueberauth.Strategy.Passwordless, []}
        ]


  Then include the configuration for this strategy

      config :ueberauth, Ueberauth.Strategy.Passwordless,
        token_secret: System.get_env("PASSWORDLESS_TOKEN_SECRET"),
        # default mailer
        mailer: MyApp.MyMailerModule,
        # (Optional) Specify additional mailers
        mailers: [
          my_other_mailer: MyApp.MyOtherMailerModule
        ]
        # (Optional) Specify how long a login token should be valid (here 30 minutes)
        ttl: 30 * 60,
        # (Optional) Specify a default path or url to which Passwordless should redirect
        # after the request phase is completed (i.e. the Email was sent)
        redirect_url: "/login-link-sent"


  If you haven't already, create a pipeline and setup routes for your callback handler

      pipeline :auth do
        Ueberauth.plug "/auth"
      end

      scrope "/auth" do
        pipe_through [:browser, :auth]

        get "/:provider", AuthController, :request
        get "/:provider/callback", AuthController, :callback
      end

  Create an endpoint for the callback where you handle the `Ueberauth.Auth` struct

      defmodule MyApp.AuthController do
        use MyApp.Web, :controller

        def callback(%{assigns: %{ueberauth_failure: errors}} = conn, _params) do
          # do things with the failure
        end

        def callback(%{assigns: %{ueberauth_auth: auth}} = conn, _params) do
          # do things with the auth
        end
      end


  ### How to use

  Use in a login form like this

      <%= form_for @conn, Routes.auth_path(@conn, :request, "passwordless"), [method: get], fn f -> %>
        <%= text_input f, :email %>
        <%= submit "Submit" %>
      <% end %>

  You can optionally specify a `redirect_url` (URL or Path) to which Passwordless will redirect after the request phase was completed (i.e. the Email was sent)

      <%= form_for @conn, Routes.auth_path(@conn, :request, "passwordless"), [method: get], fn f -> %>
        <%= hidden_input f, :redirect_url, value: "/my-redirect-path"%>
        <%= text_input f, :email %>
        <%= submit "Submit" %>
      <% end %>

  Per default, Passwordless will redirect to "/" after the request phase is completed.
  """

  use Ueberauth.Strategy, ignores_csrf_attack: true

  alias Ueberauth.Auth.{Extra, Info}
  alias Ueberauth.Strategy.Passwordless.Store

  @defaults [
    # Default TTL for Tokens is 15 Minutes.
    # After the TTL, the tokens are invalid and will be garbage collected.
    ttl: 15 * 60,
    redirect_url: "/",
    use_store: true,
    # Garbage collect the token :ets store every Minute
    garbage_collection_interval: 1000 * 60,
    store_process_name: Ueberauth.Strategy.Passwordless.Store.Ets,
    store_table_name: :passwordless_token_store,
    store_module: Ueberauth.Strategy.Passwordless.Store.Ets
  ]

  @doc """
    Handles the request phase of the authentication flow.
  """
  def handle_request!(%Plug.Conn{params: %{"email" => email} = params} = conn) do
    conn =
      conn
      |> put_private(:passwordless_email, email)

    mailer =
      Map.get(params, "mailer", "default")
      |> String.to_existing_atom()
      |> then(&config(:mailers)[&1])

    conn
    |> create_link(email, params)
    |> send_email(email, mailer)

    redirect_to_url!(conn)
  end

  @doc false
  def handle_request!(conn) do
    set_errors!(conn, [error("missing_email", "No email provided")])
  end

  @doc """
    Handles the callback phase of the authentication flow.
  """
  def handle_callback!(%Plug.Conn{params: %{"token" => token}} = conn) do
    with {:ok, {token, payload}} <- invalidate_token(token),
         {:ok, email} <- extract_email(token) do
      conn
      |> put_private(:passwordless_email, email)
      |> put_private(:passwordless_payload, payload)
    else
      _error -> set_errors!(conn, [error("invalid_token", "Token was invalid")])
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_token", "No token received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:passwordless_email, nil)
    |> put_private(:passwordless_payload, nil)
  end

  @doc """
  Stores the information obtained from the callback.

  This sturct is available in your callback function with `ueberauth_auth.info`
  """
  def info(conn) do
    email = conn.private.passwordless_email

    %Info{
      email: email
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the callback.

  This sturct is available in your callback function with `ueberauth_auth.extra`
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.params["token"],
        email: conn.private.passwordless_email,
        payload: conn.private.passwordless_payload
      }
    }
  end

  @doc """
  Creates a callback link which has a token as a parameter.

  The token contains a unforgeable HMAC token that expire after a TTL (Time-to-live).
  """
  def create_link(conn, email, req_params \\ %{}, opts \\ []) do
    {:ok, token} = create_token(email, opts)

    params =
      [
        token: token
      ]
      |> Ueberauth.Strategy.Helpers.with_state_param(conn)

    if config(:use_store), do: Store.add(token, params: req_params)
    callback_url(conn, params)
  end

  def create_token(email, opts \\ []) do
    ExCrypto.Token.create(email, config(:token_secret), opts)
  end

  defp send_email(link, email, mailer), do: mailer.send_email(link, email)

  defp redirect_to_url!(conn) do
    redirect_url = conn.params["redirect_url"] || config(:redirect_url)
    redirect_url_with_params = set_redirect_params(conn, redirect_url)
    redirect!(conn, redirect_url_with_params)
  end

  defp set_redirect_params(conn, redirect_url) do
    email = conn.private[:passwordless_email]
    "#{redirect_url}?email=#{email}"
  end

  defp extract_email(token),
    do: ExCrypto.Token.verify(token, config(:token_secret), config(:ttl))

  defp invalidate_token(token) do
    if not config(:use_store) do
      {:ok, {token, nil}}
    else
      case Store.exists?(token) do
        {true, payload} ->
          Store.remove(token)
          {:ok, {token, payload}}

        false ->
          {:error, :token_already_used}
      end
    end
  end

  def config(key), do: get_config() |> Keyword.fetch!(key)

  defp get_config() do
    config = Application.get_env(:ueberauth, __MODULE__, [])

    if Keyword.get(config, :token_secret) |> is_nil(),
      do: raise(KeyError, message: "You must set a :token_secret in your config.")

    if Keyword.get(config, :mailer) |> is_nil(),
      do: raise(KeyError, message: "You must set a :mailer Module in your config.")

    mailers =
      Keyword.get(config, :mailers, [])
      |> Keyword.put(:default, config[:mailer])

    config = Keyword.put(config, :mailers, mailers)

    @defaults |> Keyword.merge(config)
  end
end
