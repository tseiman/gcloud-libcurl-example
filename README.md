# gcloud-libcurl-example
An example of how to upload JSON data into **G**oogle **C**loud **P**latform (GCP) PubSub via HTTPS and service account key - implemented in C using libcurl and openssl

This in "C" written example code shows how to authenticate against Google Cloud via a service account key and obtaining an OAuth2 token which is then used to send some test data in the GCP PubSub.

![GCP authentication and communication flow](doc/sequence.svg)

For further information you may want to check:
* https://developers.google.com/identity/protocols/oauth2/service-account#httprest
* https://curl.se/libcurl/c/
* https://www.openssl.org/docs/

# Was tested with

* OpenSSL 1.1.1
* libcurl 7.58.0

further requirements

* cmake

optional
* plantuml

# Build
Build the Application: ```cmake --build ./build --config Release --target all```  
Clean the target: ```cmake --build ./build/ --target clean --```  
For Documentation you might need to install plantuml  ```apt-get install plantuml```.

# Configure
The JSON configuration file (a sample config file is in the "keys" folder) can be obtained from the service account console of GCP (**IAM & Admin --> Service Accounts  --> select service account --> Keys**).
The Service Account Keys console offers to download the Key file as **.p12** or as **.JSON** - select **JSON** the file has to be extended with the following parameters:

* pubsub_topic_url
* scope
* expire

This measn that the JSON file, downloaded from GCP needs to be extended by that parameters. A complete JSOn config file looks like that (substiute the values with some are relevant to you):

```json
{
  "type": "service_account",
  "project_id": "gcp-project-123456",
  "private_key_id": "12345a1b2...",
  "private_key": "-----BEGIN PRIVATE KEY-----\ns.....adfm123456789......\n-----END PRIVATE KEY-----\n",
  "client_email": "gcp-service-account-123@gcp-project-123456.iam.gserviceaccount.com",
  "client_id": "12345678909...",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://www.googleapis.com/oauth2/v4/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/gcp-service-account-123%40gcp-project-123456.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com",
  "scope": "https://www.googleapis.com/auth/pubsub",
  "expire": 3600,
  "pubsub_topic_url": "https://pubsub.googleapis.com/v1/projects/<MY PROJECT>/topics/<MY TOPIC>:publish"
}

```


# Run
Required is the **-k <config file including absolute or relative path>**  pointing to the JSON configuration file.
The application supports log level 0-3 given with the command line parameter **-v** e.g. ```-v3``` while the log levels correspond to:
* 0 = no logging output - only error messages (written to STDERR). Data is collected and sent - succesful operation can be veryfied by the return code of the application.
* 1 = Informational logging - very high level information logged to STDOUT
* 2 = Debugging information - different dumps of parameters and assembled data
* 3 = memory debugging

An example execution looks like: ```./cloud-libcurl-example -k keys/SAMPLE_Config.json -v1```.

The complete help screen looks like (```./cloud-libcurl-example -h```):
```
   -h                         Help (this print basically)
   -k <pathAndKeyfile>        give path to keyfile
   -v <level 0-3>             verbosity levelv 0= only errors
                                               1= Info       
                                               2= Debug      
                                               3= Memeory Debug
   
    Basic Usage:
      cloud-libcurl-example -k key/googleKey-1234.json
```

# Data transmitted 
In dataSource.c is a demo implementation of how Key Performance Indicators (KPIs) are obtained. To obtain other parameters it might be useful to change the code here.
In this demo the schema for GCP PubSub looks as following:

```json
{
  "type": "record",
  "name": "Avro",
  "fields": [
    {
      "name": "localtime",
      "type": "long"
    },
    {
      "name": "uptime",
      "type": "long"
    },
    {
      "name": "totalram",
      "type": "long"
    },
    {
      "name": "freeram",
      "type": "long"
    },
    {
      "name": "proc_count",
      "type": "long"
    },
    {
      "name": "loadavarage1",
      "type": "long"
    },
    {
      "name": "loadavarage5",
      "type": "long"
    },
    {
      "name": "loadavarage15",
      "type": "long"
    },
    {
      "name": "client_email",
      "type": "string"
    }
  ]
}
```
**Schema is not a must on GCP for PubSub, however if it is enabled the data only accepted when is matching to the schema. If you change the optained datastructure and when you have enabled schemas in GCP PubSub you must adopt it accordingly**

# Automatic run
The example can be run by systemd or chron periodically - e.g. every 5 minutes.
Example files and documentation how to achive this with systemd is part of this example.
In the **./doc/** folder you can find the following files:
```
    gcloud-libcurl-example.service
    gcloud-libcurl-example.timer
```
To enable periodic start by systemd add a linux user which runns the executeable with it's own rights:
```shell
    sudo useradd -M -r -s /bin/false -U gcloud-libcurl-example
```
create a folder in ```/etc``` for the example configuration:
copy the just built example executeable ```/bin/gcloud-libcurl-example``` to a suitable binary folder, e.g. ```/usr/local/bin``` and ensure it is executable.
```shell
sudo mkdir /etc/gcloud-libcurl-example
```
Edit the sample configuration file from ```./keys/SAMPLE_Config.json``` or download a valid file from GCP service acount key section 
(see Configure section above) and place it in ```/etc/gcloud-libcurl-example``` - make sure it gets the right access rights:
```shell
    sudo chown -R gcloud-libcurl-example:gcloud-libcurl-example /etc/gcloud-libcurl-example
```
Edit the ```gcloud-libcurl-example.service``` file and update the path to the binary and the configuration file. 
You may change or add also the verbosity command line parameter (e.g. ```-v1```) - the output of the gcloud-libcurl-example can be obtained e.g. with ```journalctl -f```.
Review ```gcloud-libcurl-example.timer``` for the timer interval (check with systemd timer service file documentation).
Copy the both (timer and service) files to the systemd service file directory (e.g. ```/etc/systemd/system``` or ```/lib/systemd/system```):
```shell
    sudo cp doc/gcloud-libcurl-example.* /lib/systemd/system/
```
Verify your configuration:
```shell
    sudo systemd-analyze verify /lib/systemd/system/gcloud-libcurl-example.*
```
Enable the periodic call of the programm with the following commands:
```shell
    sudo systemctl start gcloud-libcurl-example.timer
    sudo systemctl enable gcloud-libcurl-example.timer
```
Check with ```journalctl -f``` for any output of the example program.