import subprocess
from importlib.resources import as_file, files


def main():
    with as_file(files("fannagent_pgvector").joinpath("engine")) as path:
        subprocess.run(["bash", str(path / "build.sh")], check=True)


if __name__ == "__main__":
    main()
