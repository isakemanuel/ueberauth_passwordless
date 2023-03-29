defmodule Ueberauth.Strategy.Passwordless.Store do
  @moduledoc """
  The store module that is used to satisfy the requirement that a token can only be used once.
  """

  import Ueberauth.Strategy.Passwordless, only: [config: 1]

  defmodule Behavior do
    @moduledoc """
    The behaviour that a store module must implement.
    """
    @type token :: String.t()
    @type timestamp :: DateTime.t()
    @type opts :: Keyword.t()

    @callback add(token, timestamp, opts) :: :ok
    @callback remove(token) :: :ok
    @callback exists?(token) :: {true, any()} | false
  end

  def add(token, opts \\ []) do
    {timestamp, opts} = Keyword.pop(opts, :timestamp, DateTime.utc_now())
    store_module().add(token, timestamp, opts)
  end

  def remove(token), do: store_module().remove(token)

  def exists?(token), do: store_module().exists?(token)

  def store_module(), do: config(:store_module)
end
