defmodule NbmDashboardWeb.PageController do
  use NbmDashboardWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
