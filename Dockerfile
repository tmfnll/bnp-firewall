FROM python:3.13.1-bullseye AS base

ARG UID=1000
ARG GID=1000
ARG USER=app_user
ARG GROUP=app_group

ENV APP_USER=${USER}
ENV APP_GROUP=${GROUP}

RUN addgroup --system --gid "$GID" "$GROUP"
RUN adduser --system --uid "$UID" --ingroup "$GROUP" "$USER"

RUN pip install --upgrade pip==22.2.2

ENV POETRY_HOME=/home/${USER}/.poetry
ENV POETRY_VIRTUALENVS_CREATE=false
RUN curl -sSL https://install.python-poetry.org | python - --yes --version 1.8.5
ENV PATH="$POETRY_HOME/bin:$PATH"

WORKDIR /app
RUN mkdir -p /app && chown -R ${APP_USER}:${APP_GROUP} /app

COPY pyproject.toml .
COPY poetry.lock .

RUN poetry lock --check

RUN poetry install --without dev --no-interaction

ARG DD_ENV
ARG DD_SERVICE
ARG DD_VERSION

FROM base AS dev

RUN poetry install --only dev --no-interaction

COPY .env.dev .env

COPY --chown=${APP_USER}:${APP_GROUP} . .

USER $APP_USER

CMD ["bash", "-c", "flask db upgrade && flask run --host 0.0.0.0 --port 80"]

FROM base AS prod

COPY --chown=${APP_USER}:${APP_GROUP} . .

USER $APP_USER

