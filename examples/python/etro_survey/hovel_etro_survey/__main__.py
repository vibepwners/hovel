from __future__ import annotations

from hovel_etro_survey.module import EtroSurvey
from hovel_sdk import serve


def main() -> None:
    serve(EtroSurvey())


if __name__ == "__main__":
    main()
