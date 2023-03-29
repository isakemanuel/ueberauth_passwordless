defmodule Ueberauth.Strategy.Passwordless.Store.Ets do
  @moduledoc """
  The uses an :ets store to satisfy the requirement that a token can only be used once.

  Tokens are stored in an :ets table together with a timestamp.
  The table is garbage collected, meaning that in fixed intervals all tokens
  with timestamps older than the ttl are removed from the table.
  """
  use GenServer

  alias Ueberauth.Strategy.Passwordless.Store
  @behaviour Store.Behavior

  import Ueberauth.Strategy.Passwordless, only: [config: 1]

  @me __MODULE__

  ## Client API

  def start_link(opts), do: GenServer.start_link(@me, opts, name: config(:store_process_name))

  @impl Store.Behavior
  def add(token, timestamp, _opts),
    do: GenServer.call(@me, {:add, token, timestamp})

  @impl Store.Behavior
  def remove(token), do: GenServer.call(@me, {:remove, token})

  @impl Store.Behavior
  def exists?(token) do
    case :ets.member(config(:store_table_name), token) do
      true -> {true, nil}
      false -> false
    end
  end

  ## Server callbacks

  @impl GenServer
  def handle_call({:add, token, timestamp}, _from, init_args) do
    :ets.insert(config(:store_table_name), {token, timestamp})
    {:reply, :ok, init_args}
  end

  def handle_call({:remove, token}, _from, init_args) do
    :ets.delete(config(:store_table_name), token)
    {:reply, :ok, init_args}
  end

  @impl GenServer
  def init(init_args) do
    create_store()
    schedule_garbage_collection()
    {:ok, init_args}
  end

  defp create_store(), do: :ets.new(config(:store_table_name), [:set, :protected, :named_table])

  defp schedule_garbage_collection(),
    do: Process.send_after(self(), :collect_garbage, config(:garbage_collection_interval))

  @impl GenServer
  def handle_info(:collect_garbage, init_args) do
    now = DateTime.utc_now()
    ttl = config(:ttl)

    :ets.tab2list(config(:store_table_name))
    |> Enum.each(fn {token, timestamp} ->
      diff = DateTime.diff(now, timestamp) |> abs()

      if diff >= ttl, do: :ets.delete(config(:store_table_name), token)
    end)

    schedule_garbage_collection()

    {:noreply, init_args}
  end
end
