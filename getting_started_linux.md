# Prerequisites

## Setup ESP-IDF
Follow the instructions [here](https://docs.espressif.com/projects/esp-idf/en/v4.3.2/esp32/get-started/index.html)
to setup ESP-IDF.

## Create AWS Account
Follow the instructions [here](https://aws.amazon.com/premiumsupport/knowledge-center/create-and-activate-aws-account/)
to create an AWS account.

## Setup AWS CLI
Follow the instructions [here](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
to setup AWS CLI.

## Install JojoDiff Utility
Download the JojoDiff Utility from [here](https://sourceforge.net/projects/jojodiff/files/jojodiff/jojodiff07/)
and build it from source:
```sh
unzip jojodiff07.zip
cd jojodiff07/src
make GCC4=gcc
sudo cp jdiff.exe /usr/local/bin/
```

## Install jq and OpenSSL
If you are using Ubuntu, you can use the following commands to install them:
```
sudo apt install jq openssl
```

## Clone Source Code
To clone using HTTPS:
```
git clone https://github.com/FreeRTOS/Labs-Project-Espressif-Demos.git --recurse-submodules
```

Using SSH:
```
git clone git@github.com:FreeRTOS/Labs-Project-Espressif-Demos.git --recurse-submodules
```

If you have downloaded the repo without using the `--recurse-submodules` argument, you need to run:
```
git submodule update --init --recursive
```

# Instructions
The following instructions are written for Power Shell on Windows. Execute
all the commands from the `Labs-Project-Espressif-Demos/demos/delta_ota` directory.

## Set variables

Set some variables which are used in later commands. Execute the
following commands after replacing the values in angle brackets:

* <delta_ota_bucket_name> - Name of the Amazon S3 bucket to store your update.
* <delta_ota_thing_name> - Thing name used in the demo.
* <delta_ota_aws_region> - AWS region in which all the AWS resources are created.
The same region must be configured as the AWS CLI default region.
* <delta_ota_aws_account_id> - AWS account ID.
* <delta_ota_common_name> - Common Name used in the signer certificate.

```sh
export DELTA_OTA_BUCKET_NAME="<delta_ota_bucket_name>"
export DELTA_OTA_THING_NAME="<delta_ota_thing_name>"
export DELTA_OTA_AWS_REGION="<delta_ota_aws_region>"
export DELTA_OTA_AWS_ACCOUNT_ID="<delta_ota_aws_account_id>"
export DELTA_OTA_COMMON_NAME="<delta_ota_common_name>"
```

Example:
```sh
export DELTA_OTA_BUCKET_NAME="delta-ota-demo"
export DELTA_OTA_AWS_REGION="us-west-2"
export DELTA_OTA_AWS_ACCOUNT_ID="1234567890"
export DELTA_OTA_COMMON_NAME="abc@xyz.com"
export DELTA_OTA_THING_NAME="delta-ota-thing"
```

## Create an Amazon S3 bucket to store your update

1. Create the bucket:

```sh
aws s3api create-bucket \
    --bucket $DELTA_OTA_BUCKET_NAME \
    --region $DELTA_OTA_AWS_REGION \
    --create-bucket-configuration LocationConstraint=$DELTA_OTA_AWS_REGION
```

2. Enable versioning for the bucket:

```sh
aws s3api put-bucket-versioning \
    --bucket $DELTA_OTA_BUCKET_NAME \
    --versioning-configuration Status=Enabled
```

## Create an OTA Update service role

1. Create the role:

```sh
jq -n '
{
    "Version": "2012-10-17",
    "Statement": {
      "Effect": "Allow",
      "Principal": {"Service": "iot.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
}
' > "ota_role_policy.json"

response=`aws iam create-role \
                --role-name $DELTA_OTA_THING_NAME-role \
                --assume-role-policy-document file://ota_role_policy.json`

DELTA_OTA_ROLE_ARN=`echo $response | jq -r '.Role.Arn'`

rm "ota_role_policy.json"
```

2. Add OTA update permissions to your OTA service role:

```sh
aws iam attach-role-policy \
    --role-name $DELTA_OTA_THING_NAME-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonFreeRTOSOTAUpdate
```

3. Add the required IAM permissions to your OTA service role:

```sh
jq -n \
    --arg DELTA_OTA_ROLE_ARN $DELTA_OTA_ROLE_ARN \
'
{
    "Version": "2012-10-17",
    "Statement": [
      {
            "Effect": "Allow",
            "Action": [
                "iam:GetRole",
                "iam:PassRole"
            ],
            "Resource": $DELTA_OTA_ROLE_ARN
      }
    ]
}
' > "ota_role_iam_policy.json"

aws iam put-role-policy \
    --role-name $DELTA_OTA_THING_NAME-role \
    --policy-name $DELTA_OTA_THING_NAME-role-iam-policy \
    --policy-document file://ota_role_iam_policy.json

rm "ota_role_iam_policy.json"
```

4. Add the required Amazon S3 permissions to your OTA service role:

```sh
jq -n \
    --arg DELTA_OTA_BUCKET_NAME $DELTA_OTA_BUCKET_NAME \
'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObjectVersion",
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:s3:::" + $DELTA_OTA_BUCKET_NAME + "/*"
            ]
        }
    ]
}
' > "ota_role_s3_policy.json"

aws iam put-role-policy \
    --role-name $DELTA_OTA_THING_NAME-role \
    --policy-name $DELTA_OTA_THING_NAME-role-s3-policy \
    --policy-document file://ota_role_s3_policy.json

rm "ota_role_s3_policy.json"
```

## Create code signing certificate

1. Create a certificate config file:

```sh
echo "
[ req ]
prompt             = no
distinguished_name = my_dn

[ my_dn ]
commonName = $DELTA_OTA_COMMON_NAME

[ my_exts ]
keyUsage         = digitalSignature
extendedKeyUsage = codeSigning
" > "cert_config.txt"
```

2. Create an ECDSA code-signing private key:

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -outform PEM -out ecdsasigner.key
```

3. Create an ECDSA code-signing certificate:

```sh
openssl req -new -x509 -config cert_config.txt -extensions my_exts -nodes -days 365 -key ecdsasigner.key -out ecdsasigner.crt
```

4. Import the code-signing certificate, private key, and certificate chain into AWS Certificate Manager:

```sh
response=`aws acm import-certificate \
            --certificate fileb://ecdsasigner.crt \
            --private-key fileb://ecdsasigner.key`

DELTA_OTA_SIGNER_CERT_ARN=`echo $response | jq -r '.CertificateArn'`
```

5. Delete the certificate config file created in step 1:

```sh
rm "cert_config.txt"
```

## Create Thing and Device Credentials

1. Create a thing:

```sh
response=`aws iot create-thing --thing-name $DELTA_OTA_THING_NAME`

DELTA_OTA_THING_ARN=`echo $response | jq -r '.thingArn'`
```

2. Create Certificate and Keys:

```sh
response=`aws iot create-keys-and-certificate \
            --set-as-active \
            --certificate-pem-outfile "device.cert.pem" \
            --public-key-outfile "device.public.key" \
            --private-key-outfile "device.private.key"`

DELTA_OTA_DEVICE_CERT_ARN=`echo $response | jq -r '.certificateArn'`
DELTA_OTA_DEVICE_CERT_ID=`echo $response | jq -r '.certificateId'`
```

3. Create device policy:

```sh
jq -n \
    --arg DELTA_OTA_AWS_REGION $DELTA_OTA_AWS_REGION \
    --arg DELTA_OTA_AWS_ACCOUNT_ID $DELTA_OTA_AWS_ACCOUNT_ID \
'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iot:Connect",
            "Resource": ("arn:aws:iot:" + $DELTA_OTA_AWS_REGION + ":" + $DELTA_OTA_AWS_ACCOUNT_ID + ":client/${iot:Connection.Thing.ThingName}")
        },
        {
            "Effect": "Allow",
            "Action": "iot:Subscribe",
            "Resource": [
                "arn:aws:iot:" + $DELTA_OTA_AWS_REGION + ":" + $DELTA_OTA_AWS_ACCOUNT_ID + ":topicfilter/$aws/things/${iot:Connection.Thing.ThingName}/streams/*",
                "arn:aws:iot:" + $DELTA_OTA_AWS_REGION + ":" + $DELTA_OTA_AWS_ACCOUNT_ID + ":topicfilter/$aws/things/${iot:Connection.Thing.ThingName}/jobs/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "iot:Publish",
                "iot:Receive"
            ],
            "Resource": [
                "arn:aws:iot:" + $DELTA_OTA_AWS_REGION + ":" +$DELTA_OTA_AWS_ACCOUNT_ID + ":topic/$aws/things/${iot:Connection.Thing.ThingName}/streams/*",
                "arn:aws:iot:" + $DELTA_OTA_AWS_REGION + ":" +$DELTA_OTA_AWS_ACCOUNT_ID + ":topic/$aws/things/${iot:Connection.Thing.ThingName}/jobs/*"
            ]
        }
    ]
}
' > "ota_device_policy.json"

aws iot create-policy \
    --policy-name $DELTA_OTA_THING_NAME-policy \
    --policy-document file://ota_device_policy.json

rm "ota_device_policy.json"
```

4. Attach policy to the certificate:

```sh
aws iot attach-policy \
    --policy-name $DELTA_OTA_THING_NAME-policy \
    --target $DELTA_OTA_DEVICE_CERT_ARN
```

5. Attach certificate to the thing:

```sh
aws iot attach-thing-principal \
    --thing-name $DELTA_OTA_THING_NAME \
    --principal $DELTA_OTA_DEVICE_CERT_ARN
```

6. Get AWS IoT endpoint:

```sh
response=`aws iot describe-endpoint --endpoint-type iot:Data-ATS`

DELTA_OTA_AWS_IOT_ENDPOINT=`echo $response | jq '.endpointAddress'`
```

## Setup Credentials in Code

1. Set signer cert:

```sh
signer_cert=$(sed s/$/\\\\n\"\\\\/ ecdsasigner.crt | sed s/^/\"/)
newline=$'\n'
signer_cert="#define otapalconfigCODE_SIGNING_CERTIFICATE \\${newline}$signer_cert"
sed -i "/.*#define otapalconfigCODE_SIGNING_CERTIFICATE.*/c $signer_cert" config/ota_demo_config.h
```

2. Set device cert and private key:

```sh
device_cert=$(sed s/$/\\\\n\"\\\\/ device.cert.pem | sed s/^/\"/)
newline=$'\n'
device_cert="#define keyCLIENT_CERTIFICATE_PEM \\${newline}$device_cert"
sed -i "/.*#define keyCLIENT_CERTIFICATE_PEM.*/c $device_cert" config/aws_clientcredential_keys.h

device_key=$(sed s/$/\\\\n\"\\\\/ device.private.key | sed s/^/\"/)
newline=$'\n'
device_key="#define keyCLIENT_PRIVATE_KEY_PEM \\${newline}$device_key"
sed -i "/.*#define keyCLIENT_PRIVATE_KEY_PEM.*/c $device_key" config/aws_clientcredential_keys.h
```

3. Set thing name and AWS IoT endpoint:

```sh
broker_endpoint="#define clientcredentialMQTT_BROKER_ENDPOINT $DELTA_OTA_AWS_IOT_ENDPOINT"
sed -i "/.*#define clientcredentialMQTT_BROKER_ENDPOINT.*/c $broker_endpoint" config/aws_clientcredential.h

thing_name="#define clientcredentialIOT_THING_NAME \"$DELTA_OTA_THING_NAME\""
sed -i "/.*#define clientcredentialIOT_THING_NAME.*/c $thing_name" config/aws_clientcredential.h
```

4. Setup WiFi credentials:

```sh
idf.py menuconfig
```
Choose `Example Connection Configuration --> WiFi SSID` for setting WiFi SSID and
`Example Connection Configuration --> WiFi Password` for setting WiFi password.

## Install the initial version of firmware

1. Build:

```sh
idf.py build
```

2. Copy the initial firmware in a separate directory for later use:

```sh
mkdir current_firmware
cp build/delta-ota.bin current_firmware/
```

3. Flash [Run the following command in a separate terminal so that we
   can still use our variables in this terminal]:

```sh
idf.py flash monitor
```

The output should look like the following:
```
...
Current State=[WaitingForJob], Event=[ReceivedJobDocument], New state=[CreatingFile]
Received: 0   Queued: 0   Processed: 0   Dropped: 0
Received: 0   Queued: 0   Processed: 0   Dropped: 0
Received: 0   Queued: 0   Processed: 0   Dropped: 0
Received: 0   Queued: 0   Processed: 0   Dropped: 0
Received: 0   Queued: 0   Processed: 0   Dropped: 0
Received: 0   Queued: 0   Processed: 0   Dropped: 0
...
```

## Prepare patch

1. Update firmware version in code:

```sh
current_version_number=`grep "#define APP_VERSION_BUILD" config/ota_demo_config.h | sed 's/[^0-9]*//g'`
next_version_number=$(($current_version_number + 1))
version_number_line="#define APP_VERSION_BUILD $next_version_number"
sed -i "/.*#define APP_VERSION_BUILD.*/c $version_number_line" config/ota_demo_config.h
```

2. Build new firmware:

```sh
idf.py build
```

3. Copy the new firmware in a separate directory for later use:

```sh
mkdir new_firmware
cp build/delta-ota.bin new_firmware/
```

4. Create patch:

```sh
mkdir patch
jdiff.exe current_firmware/delta-ota.bin new_firmware/delta-ota.bin patch/delta-ota.patch
```

## Create an OTA update

1. Upload the patch file to S3:

```sh
aws s3 cp patch/delta-ota.patch s3://$DELTA_OTA_BUCKET_NAME/
```

2. Create a signing profile:

```sh
aws signer put-signing-profile \
    --profile-name delta_ota_signing_profile \
    --signing-material certificateArn=$DELTA_OTA_SIGNER_CERT_ARN \
    --platform AmazonFreeRTOS-Default \
    --signing-parameters certname=P11_CSK
```

3. Start signing job:

```sh
response=`aws s3api list-object-versions \
            --bucket $DELTA_OTA_BUCKET_NAME \
            --prefix delta-ota.patch \
            --max-items 1`

version_id=`echo $response | jq -r '.Versions[0].VersionId'`

response=`aws signer start-signing-job \
            --source "s3={bucketName=$DELTA_OTA_BUCKET_NAME,key=delta-ota.patch,version=$version_id}" \
            --destination "s3={bucketName=$DELTA_OTA_BUCKET_NAME}" \
            --profile-name delta_ota_signing_profile`

DELTA_OTA_SIGNING_JOB_ID=`echo $response | jq -r '.jobId'`
```

4. Create a stream:

```sh
jq -n \
    --arg DELTA_OTA_BUCKET_NAME $DELTA_OTA_BUCKET_NAME \
    --arg DELTA_OTA_SIGNING_JOB_ID $DELTA_OTA_SIGNING_JOB_ID \
'
[
  {
    "fileId":1,
    "s3Location":{
      "bucket":$DELTA_OTA_BUCKET_NAME,
      "key":$DELTA_OTA_SIGNING_JOB_ID
    }
  }
]
' > "ota_stream.json"

aws iot create-stream \
    --stream-id $DELTA_OTA_THING_NAME-stream \
    --description $DELTA_OTA_THING_NAME-stream \
    --files file://ota_stream.json \
    --role-arn $DELTA_OTA_ROLE_ARN

rm "ota_stream.json"
```

5. Create OTA update job:

```sh
jq -n \
    --arg DELTA_OTA_THING_NAME $DELTA_OTA_THING_NAME \
    --arg DELTA_OTA_THING_ARN $DELTA_OTA_THING_ARN \
    --arg DELTA_OTA_SIGNING_JOB_ID $DELTA_OTA_SIGNING_JOB_ID \
    --arg DELTA_OTA_ROLE_ARN $DELTA_OTA_ROLE_ARN \
'
{
    "otaUpdateId": ($DELTA_OTA_THING_NAME + "-delta-ota"),
    "description": "Delta OTA Update.",
    "targets": [
        $DELTA_OTA_THING_ARN
    ],
    "targetSelection": "SNAPSHOT",
    "awsJobExecutionsRolloutConfig": {
        "maximumPerMinute": 10
    },
    "files": [
        {
          "fileName": "delta-ota.patch",
          "fileLocation": {
            "stream": {
              "streamId": ($DELTA_OTA_THING_NAME + "-stream"),
              "fileId":1
            }
          },
          "codeSigning": {
            "awsSignerJobId": $DELTA_OTA_SIGNING_JOB_ID
          }
        }
    ],
    "roleArn": $DELTA_OTA_ROLE_ARN
}
' > "ota_update_job.json"

aws iot create-ota-update --cli-input-json file://ota_update_job.json

rm "ota_update_job.json"
```

6. The device should receive the OTA update and the output on the device
terminal should contain the line showing the application version as
`0.9.3`:

```
OTA over MQTT demo, Application version 0.9.3
```
