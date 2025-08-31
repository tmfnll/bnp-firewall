# FireFlow

FireFlow is an example Flask application that can be run in a Docker container.

I've tried to demonstrate what I consider to be best practices for building a Flask application.  However, in order to 
avoid overcomplicating the exercise, I've left a few things in a less developed state that I 
would do if I were deploying this to Production.

Further improvements would include:

- Reporting of errors to an external service such as Sentry.
- Reporting of metrics and tracing to an external service such as Datadog or Prometheus/Grafana.
- Structured logging to an external service such as Datadog as well as more logs.
- Using PostgreSQL rather than SQLite.
- Completing the Helm chart (see notes below).
- Configuring a proper application server such as Gunicorn or uWSGI rather than using the Flask development server.
- At the moment the test DB gets destroyed between test runs.  A better approach would be to run each test in a transaction
  and roll back the transaction at the end of the test.
- Maybe avoiding `Flask-SQLAlchemy` and using `SQLAlchemy` directly to avoid the tight coupling to Flask.  
  (This is perhaps controversial.  I'm more than happy to discuss!)
- A more expressive filtering syntax.

## Running Locally in [Docker](https://www.docker.com/get-started) 🐳

1. Build Docker image using `docker compose`
 
This builds a `dev` image that includes all the dependencies needed to run the application.

```shell
docker compose build fireflow
```
2. Run checks to ensure that everything is working

These checks would normally be run in a CI/CD pipeline

```shell
docker compose run --rm fireflow make ci
```

3. Run the application, exposing it on port 8080

```shell
docker compose up fireflow
```

4. Open your browser and view the [swagger documentation](http://localhost:8080/docs/swagger-ui)

5. Generate a new test JWT and copy it to your clipboard

```shell
docker compose run --rm fireflow make jwt
```

6. Configure authentication by clicking the `Authorize` button and entering the JWT 

7. Explore the API by trying out the endpoints in the swagger documentation.

## Running Locally 🐍

1. Install the version of python defined in `.python-version` using [pyenv](https://github.com/pyenv/pyenv) 

```shell
pyenv install
```

2. Install [Poetry](https://python-poetry.org/docs/#installation)
3. Install the dependencies

```shell
poetry install --with dev
```

3. Run checks to ensure that everything is working

```shell
poetry run make ci
```

4. Run the application

```shell
poetry run make local_run
```

5. Open your browser and inspect the [swagger documentation](http://localhost:8080/docs/swagger-ui) as outlined above.

## Running In Minikube 🚢

⚠️ This is a very basic example of how to deploy and application to Kubernetes.  A more complete example would include:
- A separate `Job` to run migrations before deployment.
- A `PersistentVolume` to store the database data. (At the moment, the database is ephemeral and will be lost when the pod is deleted).
- A `HorizontalPodAutoscaler` to scale the application based on load.
- An `Ingress` to expose the application outside the cluster (if needed).
- Pod disruption budgets to prevent downtime during node maintenance/deployments.

Minikube is a tool that runs a single-node Kubernetes cluster on your local machine for development and testing purposes.

1. Install [Minikube](https://minikube.sigs.k8s.io/docs/start/)
2. Install [Helm](https://helm.sh/docs/intro/install/)
3. Install [Skaffold](https://skaffold.dev/docs/install/)
4. Install [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
5. Start Minikube (this should activate the `minikube` context in `kubectl`)

```shell
minikube start
```

6. Use Skaffold to build the Docker image and deploy the application to Minikube

```shell
skaffold run
```
7. Open the Minikube dashboard to inspect the deployed application

```shell
minikube dashboard
```

8. Forward the application port to your local machine

```shell
kubectl port-forward service/fireflow 8080:80
```

9. Open your browser and inspect the [swagger documentation](http://localhost:8080/docs/swagger-ui) as outlined above.