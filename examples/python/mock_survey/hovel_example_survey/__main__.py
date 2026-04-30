from __future__ import annotations

from hovel_example_survey.module import MockSurvey
from hovel_sdk import serve


def main() -> None:
    serve(MockSurvey())


if __name__ == "__main__":
    main()
