defmodule NbmDashboardWeb.PageController do
  use NbmDashboardWeb, :controller

  def home(conn, _params) do
    analysis_result =
      "../data/analysis_result.json"
      |> File.read!()
      |> Jason.decode!()

    render(conn, :home, analysis_result: analysis_result)
  end
end
