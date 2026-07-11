from __future__ import annotations

from hovel_sdk import serve

from hovel_ms17_010_survey.module import MS17010Survey


def main() -> None:
    serve(MS17010Survey())


if __name__ == "__main__":
    main()
