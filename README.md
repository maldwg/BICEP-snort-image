<div align="center">
<img alt="Docker Image Version (tag)" src="https://img.shields.io/docker/v/maxldwg/bicep-snort/latest?style=for-the-badge&logo=docker&label=Latest%20Version&link=https%3A%2F%2Fhub.docker.com%2Fr%2Fmaxldwg%2Fbicep-snort">
<img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/maxldwg/bicep-snort?style=for-the-badge&logo=docker&logoColor=blue&link=https%3A%2F%2Fhub.docker.com%2Fr%2Fmaxldwg%2Fbicep-snort">
<img alt="Codecov" src="https://img.shields.io/codecov/c/github/maldwg/BICEP-snort-image?style=for-the-badge">
<img alt="GitHub branch status" src="https://img.shields.io/github/checks-status/maldwg/BICEP-snort-image/main?style=for-the-badge&label=Tests">

<br>

</div>

# BICEP-snort-image
Snort docker image adapated for BICEP

The image holds every dependency necessary along with the necessary interface implemented, in order to work with the BICEP application

The main BICEP project is available [here](https://github.com/maldwg/BICEP/tree/main)

## Usage

If you want to use the resulting image with the BICEP framework, keep in mind that in its current version, the Snort container will need a config that outputs alerts to /opt/logs/alerts_and_anomalies.json. If you do not log to this location, the analysis willnot work properly. A feature for including a whole use selected directory is planned.


## Initialize project

In order to be able to start the project you will need to initialize it first. Do this by running:

```
git submodule update --init --recursive
```
This fetches the newest version of the submodule for the backend code and is necessary for the application to work seamlessly.



## Building the project
To build a local version of the image for testing purposes, simply run:
``` 
cd ./bicep-snort
docker buildx build . --build-arg BASE_IMAGE=maxldwg/snort --build-arg VERSION=3.6.2.0 -t maxldwg/bicep-snort:latest --no-cache
```
Change the version to your desried one