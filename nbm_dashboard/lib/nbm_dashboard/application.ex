defmodule NbmDashboard.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      NbmDashboardWeb.Telemetry,
      {DNSCluster, query: Application.get_env(:nbm_dashboard, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: NbmDashboard.PubSub},
      # Start a worker by calling: NbmDashboard.Worker.start_link(arg)
      # {NbmDashboard.Worker, arg},
      # Start to serve requests, typically the last entry
      NbmDashboardWeb.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: NbmDashboard.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    NbmDashboardWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
