defmodule NbmDashboardWeb.PageController do
  use NbmDashboardWeb, :controller

  @analysis_file "../data/analysis_result.json"

  def home(conn, _params) do
    analysis_result =
      @analysis_file
      |> File.read!()
      |> Jason.decode!()

    render(conn, :home, analysis_result: analysis_result)
  end

  def run_analysis(conn, _params) do
    project_root = Path.expand("..", File.cwd!())
    python_script = Path.join(project_root, "src/main.py")

    case System.cmd("py", [python_script], cd: project_root, stderr_to_stdout: true) do
      {output, 0} ->
        conn
        |> put_flash(:info, "Analysis completed successfully.")
        |> redirect(to: ~p"/")

      {output, exit_code} ->
        conn
        |> put_flash(
          :error,
          "Analysis failed with exit code #{exit_code}: #{output}"
        )
        |> redirect(to: ~p"/")
    end
  end
end
