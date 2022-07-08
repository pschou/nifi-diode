ARG ARCH="amd64"
ARG OS="linux"
FROM scratch
LABEL description="Very simple reliable NiFi diode, built in golang" owner="dockerfile@paulschou.com"

EXPOSE      8080
ADD ./LICENSE /LICENSE
ADD ./nifi-diode "/nifi-diode"
ENTRYPOINT  [ "/nifi-diode" ]
