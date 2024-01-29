# gcloud-libcurl-example
An example of how to upload JSON data into Google Cloud Pub/Sub via HTTPS and service account key - implemented in C using libcurl and openssl

This in "C" written example code shows how to authenticate against Google Cloud via a service account key and obtaining an OAuth2 token which is then used to send some test data in the GCP pub/sub.


![GCP authentication and communication flow](doc/GCP-Communication-Flow.svg)