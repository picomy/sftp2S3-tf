from alpine:3.12.4
run apk add curl
run apk add unzip
run apk add bash
run apk add python3
run apk add py3-pip
run pip install boto3
run pip install awscli
run pip install configparser
run curl https://rclone.org/install.sh | bash
#copy ./rclone-v1.54.1-linux-amd64/* /opt/rclone/
copy ./main.py /root/
ENTRYPOINT /usr/bin/python3 /root/main.py
