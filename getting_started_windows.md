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
and extract it to `C:\jojodiff07`.

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
all the commands from the `Labs-Project-Espressif-Demos\demos\delta_ota` directory.

## Set variables

Set some variables which are used in later commands. Execute the
following commands after replacing the values in angle brackets:

* <delta_ota_bucket_name> - Name of the Amazon S3 bucket to store your update.
* <delta_ota_thing_name> - Thing name used in the demo.
* <delta_ota_aws_region> - AWS region in which all the AWS resources are created.
The same region must be configured as the AWS CLI default region.
* <delta_ota_aws_account_id> - AWS account ID.
* <delta_ota_common_name> - Common Name used in the signer certificate.

```ps
$DELTA_OTA_BUCKET_NAME="<delta_ota_bucket_name>"
$DELTA_OTA_THING_NAME="<delta_ota_thing_name>"
$DELTA_OTA_AWS_REGION="<delta_ota_aws_region>"
$DELTA_OTA_AWS_ACCOUNT_ID="<delta_ota_aws_account_id>"
$DELTA_OTA_COMMON_NAME="<delta_ota_common_name>"
```

Example:
```ps
$DELTA_OTA_BUCKET_NAME="delta-ota-demo"
$DELTA_OTA_AWS_REGION="us-west-2"
$DELTA_OTA_AWS_ACCOUNT_ID="1234567890"
$DELTA_OTA_COMMON_NAME="abc@xyz.com"
$DELTA_OTA_THING_NAME="delta-ota-thing"
```

## Create an Amazon S3 bucket to store your update

1. Create the bucket:
```ps
aws s3api create-bucket `
    --bucket $DELTA_OTA_BUCKET_NAME `
    --region $DELTA_OTA_AWS_REGION `
    --create-bucket-configuration LocationConstraint=$DELTA_OTA_AWS_REGION
```

2. Enable versioning for the bucket:
```ps
aws s3api put-bucket-versioning `
    --bucket $DELTA_OTA_BUCKET_NAME `
    --versioning-configuration Status=Enabled
```

## Create an OTA Update service role

1. Create the role:

```ps
$ota_role_policy = @"
{
    "Version": "2012-10-17",
    "Statement": {
      "Effect": "Allow",
      "Principal": {"Service": "iot.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
}
"@

$ota_role_policy = $ota_role_policy | ConvertFrom-JSON

$ota_role_policy | ConvertTo-Json -depth 100 | Out-File "ota_role_policy.json"

$response = aws iam create-role `
                --role-name $DELTA_OTA_THING_NAME-role `
                --assume-role-policy-document file://ota_role_policy.json

$response = $response | ConvertFrom-Json

$DELTA_OTA_ROLE_ARN = $response.Role.Arn

rm "ota_role_policy.json"
```

2. Add OTA update permissions to your OTA service role:

```ps
aws iam attach-role-policy `
    --role-name $DELTA_OTA_THING_NAME-role `
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonFreeRTOSOTAUpdate
```

3. Add the required IAM permissions to your OTA service role:

```ps
$ota_role_iam_policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
      {
            "Effect": "Allow",
            "Action": [
                "iam:GetRole",
                "iam:PassRole"
            ],
            "Resource": "$DELTA_OTA_ROLE_ARN"
      }
    ]
}
"@

$ota_role_iam_policy = $ota_role_iam_policy | ConvertFrom-JSON

$ota_role_iam_policy | ConvertTo-Json -depth 100 | Out-File "ota_role_iam_policy.json"

aws iam put-role-policy `
    --role-name $DELTA_OTA_THING_NAME-role `
    --policy-name $DELTA_OTA_THING_NAME-role-iam-policy `
    --policy-document file://ota_role_iam_policy.json

rm "ota_role_iam_policy.json"
```

4. Add the required Amazon S3 permissions to your OTA service role:

```ps
$ota_role_s3_policy = @"
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
                "arn:aws:s3:::$DELTA_OTA_BUCKET_NAME/*"
            ]
        }
    ]
}
"@

$ota_role_s3_policy = $ota_role_s3_policy | ConvertFrom-JSON

$ota_role_s3_policy | ConvertTo-Json -depth 100 | Out-File "ota_role_s3_policy.json"

aws iam put-role-policy `
    --role-name $DELTA_OTA_THING_NAME-role `
    --policy-name $DELTA_OTA_THING_NAME-role-s3-policy `
    --policy-document file://ota_role_s3_policy.json

rm "ota_role_s3_policy.json"
```

## Create code signing certificate
We are using the `openssl.exe` installed with Git. It is usually installed
at the following location: `C:\Program Files\Git\usr\bin\openssl.exe`.

1. Create a certificate config file:
```ps
$cert_config = @"
[ req ]
prompt             = no
distinguished_name = my_dn

[ my_dn ]
commonName = $DELTA_OTA_COMMON_NAME

[ my_exts ]
keyUsage         = digitalSignature
extendedKeyUsage = codeSigning
"@

$cert_config | Out-File "cert_config.txt"
```

2. Create an ECDSA code-signing private key:

```ps
.'C:\Program Files\Git\usr\bin\openssl.exe' genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -outform PEM -out ecdsasigner.key
```

3. Create an ECDSA code-signing certificate:

```ps
.'C:\Program Files\Git\usr\bin\openssl.exe' req -new -x509 -config cert_config.txt -extensions my_exts -nodes -days 365 -key ecdsasigner.key -out ecdsasigner.crt
```

4. Import the code-signing certificate, private key, and certificate chain into AWS Certificate Manager:

```ps
$response = aws acm import-certificate `
                --certificate fileb://ecdsasigner.crt `
                --private-key fileb://ecdsasigner.key

$response = $response | ConvertFrom-Json

$DELTA_OTA_SIGNER_CERT_ARN = $response.CertificateArn
```

5. Delete the certificate config file created in step 1:
```ps
rm "cert_config.txt"
```

## Create Thing and Device Credentials

1. Create a thing:
```ps
$response = aws iot create-thing --thing-name $DELTA_OTA_THING_NAME

$response = $response | ConvertFrom-Json

$DELTA_OTA_THING_ARN = $response.thingArn
```

2. Create Certificate and Keys:
```ps
$response = aws iot create-keys-and-certificate `
                --set-as-active `
                --certificate-pem-outfile "device.cert.pem" `
                --public-key-outfile "device.public.key" `
                --private-key-outfile "device.private.key"

$response = $response | ConvertFrom-Json

$DELTA_OTA_DEVICE_CERT_ARN = $response.certificateArn
$DELTA_OTA_DEVICE_CERT_ID = $response.certificateId
```

3. Create device policy:

```ps
$ota_device_policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iot:Connect",
            "Resource": "arn:aws:iot:${DELTA_OTA_AWS_REGION}:${DELTA_OTA_AWS_ACCOUNT_ID}:client/`${iot:Connection.Thing.ThingName}"
        },
        {
            "Effect": "Allow",
            "Action": "iot:Subscribe",
            "Resource": [
                "arn:aws:iot:${DELTA_OTA_AWS_REGION}:${DELTA_OTA_AWS_ACCOUNT_ID}:topicfilter/`$aws/things/`${iot:Connection.Thing.ThingName}/streams/*",
                "arn:aws:iot:${DELTA_OTA_AWS_REGION}:${DELTA_OTA_AWS_ACCOUNT_ID}:topicfilter/`$aws/things/`${iot:Connection.Thing.ThingName}/jobs/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "iot:Publish",
                "iot:Receive"
            ],
            "Resource": [
                "arn:aws:iot:${DELTA_OTA_AWS_REGION}:${DELTA_OTA_AWS_ACCOUNT_ID}:topic/`$aws/things/`${iot:Connection.Thing.ThingName}/streams/*",
                "arn:aws:iot:${DELTA_OTA_AWS_REGION}:${DELTA_OTA_AWS_ACCOUNT_ID}:topic/`$aws/things/`${iot:Connection.Thing.ThingName}/jobs/*"
            ]
        }
    ]
}
"@

$ota_device_policy = $ota_device_policy | ConvertFrom-JSON

$ota_device_policy | ConvertTo-Json -depth 100 | Out-File "ota_device_policy.json"

aws iot create-policy `
    --policy-name $DELTA_OTA_THING_NAME-policy `
    --policy-document file://ota_device_policy.json

rm "ota_device_policy.json"
```

4. Attach policy to the certificate:
```ps
aws iot attach-policy `
    --policy-name $DELTA_OTA_THING_NAME-policy `
    --target $DELTA_OTA_DEVICE_CERT_ARN
```

5. Attach certificate to the thing:
```ps
aws iot attach-thing-principal `
    --thing-name $DELTA_OTA_THING_NAME `
    --principal $DELTA_OTA_DEVICE_CERT_ARN
```

6. Get AWS IoT endpoint:
```ps
$response =  aws iot describe-endpoint --endpoint-type iot:Data-ATS

$response = $response | ConvertFrom-Json

$DELTA_OTA_AWS_IOT_ENDPOINT = $response.endpointAddress
```

## Setup Credentials in Code

1. Set signer cert.
```ps
$signer_cert_content = Get-Content ecdsasigner.crt | foreach {'"' + $_ +  '\n" \'}
$signer_cert_content | Set-Content ecdsasigner.crt.tmp
$signer_cert_content = Get-Content -raw ecdsasigner.crt.tmp
$signer_cert_content = $signer_cert_content.Substring(0, $signer_cert_content.LastIndexOf(' \'))
rm ecdsasigner.crt.tmp

$ota_demo_config_content = Get-Content .\config\ota_demo_config.h

$find = $ota_demo_config_content | Select-String '#define otapalconfigCODE_SIGNING_CERTIFICATE' | Select-Object -ExpandProperty Line
$replace = "#define otapalconfigCODE_SIGNING_CERTIFICATE \`r`n $signer_cert_content"
$ota_demo_config_content = $ota_demo_config_content | ForEach-Object {$_ -replace $find, $replace}

$ota_demo_config_content | Set-Content .\config\ota_demo_config.h
```

2. Set device cert and private key.
```ps
$device_cert_content = Get-Content device.cert.pem | foreach {'"' + $_ +  '\n" \'}
$device_cert_content | Set-Content device.cert.pem.tmp
$device_cert_content = Get-Content -raw device.cert.pem.tmp
$device_cert_content = $device_cert_content.Substring(0, $device_cert_content.LastIndexOf(' \'))
rm device.cert.pem.tmp

$device_key_content = Get-Content device.private.key | foreach {'"' + $_ +  '\n" \'}
$device_key_content | Set-Content device.private.keytmp
$device_key_content = Get-Content -raw device.private.keytmp
$device_key_content = $device_key_content.Substring(0, $device_key_content.LastIndexOf(' \'))
rm device.private.keytmp

$aws_clientcredential_keys_content = Get-Content .\config\aws_clientcredential_keys.h

$find = $aws_clientcredential_keys_content | Select-String '#define keyCLIENT_CERTIFICATE_PEM' | Select-Object -ExpandProperty Line
$replace = "#define keyCLIENT_CERTIFICATE_PEM \`r`n $device_cert_content"
$aws_clientcredential_keys_content = $aws_clientcredential_keys_content | ForEach-Object {$_ -replace $find, $replace}

$find = $aws_clientcredential_keys_content | Select-String '#define keyCLIENT_PRIVATE_KEY_PEM' | Select-Object -ExpandProperty Line
$replace = "#define keyCLIENT_PRIVATE_KEY_PEM \`r`n $device_key_content"
$aws_clientcredential_keys_content = $aws_clientcredential_keys_content | ForEach-Object {$_ -replace $find, $replace}

$aws_clientcredential_keys_content | Set-Content .\config\aws_clientcredential_keys.h
```

3. Set thing name and AWS IoT endpoint:
```ps
$aws_clientcredential_content = Get-Content .\config\aws_clientcredential.h

$find = $aws_clientcredential_content | Select-String '#define clientcredentialIOT_THING_NAME' | Select-Object -ExpandProperty Line
$replace = "#define clientcredentialIOT_THING_NAME `"$DELTA_OTA_THING_NAME`""
$aws_clientcredential_content = $aws_clientcredential_content | ForEach-Object {$_ -replace $find, $replace}

$find = $aws_clientcredential_content | Select-String '#define clientcredentialMQTT_BROKER_ENDPOINT' | Select-Object -ExpandProperty Line
$replace = "#define clientcredentialMQTT_BROKER_ENDPOINT `"$DELTA_OTA_AWS_IOT_ENDPOINT`""
$aws_clientcredential_content = $aws_clientcredential_content | ForEach-Object {$_ -replace $find, $replace}

$aws_clientcredential_content | Set-Content .\config\aws_clientcredential.h
```

4. Setup WiFi credentials.
```ps
idf.py menuconfig
```
Choose `Example Connection Configuration --> WiFi SSID` for setting WiFi SSID and
`Example Connection Configuration --> WiFi Password` for setting WiFi password.

## Install the initial version of firmware

1. Build:
```ps
idf.py build
```

2. Copy the initial firmware in a separate directory for later use:
```ps
mkdir current_firmware
cp .\build\delta-ota.bin .\current_firmware\
```

3. Flash [Run the following command in a separate terminal so that we
   can still use our variables in this shell]:
```ps
idf.py flash monitor
```
The output should look like the following:
```
TODO
```

## Prepare patch

1. Update firmware version in code.
```ps
$ota_demo_config_content = Get-Content .\config\ota_demo_config.h

$find = $ota_demo_config_content | Select-String '#define APP_VERSION_BUILD' | Select-Object -ExpandProperty Line
$current_version_number = $find -replace "[^0-9]" , ''
$next_version_number = [int]$current_version_number + 1
$replace = "#define APP_VERSION_BUILD $next_version_number"
$ota_demo_config_content = $ota_demo_config_content | ForEach-Object {$_ -replace $find, $replace}

$ota_demo_config_content | Set-Content .\config\ota_demo_config.h
```

2. Build new firmware:
```ps
idf.py build
```
3. Copy the new firmware in a separate directory for later use:
```ps
mkdir new_firmware
cp .\build\delta-ota.bin .\new_firmware\
```

4. Create patch:
```ps
mkdir patch
.'C:\jojodiff07\win32\jdiff.exe' .\current_firmware\delta-ota.bin .\new_firmware\delta-ota.bin .\patch\delta-ota.patch

```

## Create an OTA update

1. Upload the patch file to S3:
```ps
aws s3 cp .\patch\delta-ota.patch s3://$DELTA_OTA_BUCKET_NAME/
```

2. Create a signing profile:
```ps
aws signer put-signing-profile `
    --profile-name delta_ota_signing_profile `
    --signing-material certificateArn=$DELTA_OTA_SIGNER_CERT_ARN `
    --platform AmazonFreeRTOS-Default `
    --signing-parameters certname=P11_CSK
```

3. Start signing job:
```ps
$response =  aws s3api list-object-versions `
                --bucket $DELTA_OTA_BUCKET_NAME `
                --prefix delta-ota.patch `
                --max-items 1

$response = $response | ConvertFrom-Json

$version_id = $response.Versions[0].VersionId

$response =   aws signer start-signing-job `
                --source "s3={bucketName=$DELTA_OTA_BUCKET_NAME,key=delta-ota.patch,version=$version_id}" `
                --destination "s3={bucketName=$DELTA_OTA_BUCKET_NAME}" `
                --profile-name delta_ota_signing_profile

$response = $response | ConvertFrom-Json

$DELTA_OTA_SIGNING_JOB_ID = $response.jobId
```

4. Create a stream:
```ps
$ota_stream = @"
[
  {
    "fileId":1,
    "s3Location":{
      "bucket":"$DELTA_OTA_BUCKET_NAME",
      "key":"$DELTA_OTA_SIGNING_JOB_ID"
    }
  }
]
"@

$ota_stream = $ota_stream | ConvertFrom-JSON

$ota_stream | ConvertTo-Json -depth 100 -AsArray | Out-File "ota_stream.json"

aws iot create-stream `
    --stream-id $DELTA_OTA_THING_NAME-stream `
    --description $DELTA_OTA_THING_NAME-stream `
    --files file://ota_stream.json `
    --role-arn $DELTA_OTA_ROLE_ARN

rm "ota_stream.json"
```
5. Create OTA update job:

```ps
$ota_update_job = @"
{
    "otaUpdateId": "$DELTA_OTA_THING_NAME-delta-ota",
    "description": "Delta OTA Update.",
    "targets": [
        "$DELTA_OTA_THING_ARN"
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
              "streamId": "$DELTA_OTA_THING_NAME-stream",
              "fileId":1
            }
          },
          "codeSigning": {
            "awsSignerJobId": "$DELTA_OTA_SIGNING_JOB_ID"
          }
        }
    ],
    "roleArn": "$DELTA_OTA_ROLE_ARN"
}
"@

$ota_update_job = $ota_update_job | ConvertFrom-JSON

$ota_update_job | ConvertTo-Json -depth 100 | Out-File "ota_update_job.json"

aws iot create-ota-update --cli-input-json file://ota_update_job.json

rm "ota_update_job.json"
```

6. The device should receive the OTA update and the output on the device
terminal should look like the following:
```
TODO
```
