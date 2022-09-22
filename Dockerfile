FROM python:3.10.4-slim as pip-packages
ENV HDF5_DIR /usr/include/hdf5
ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_NO_CACHE_DIR=False

RUN mkdir -p /opt/wireguard-manager
ADD requirements.txt /opt/wireguard-manager/.
RUN pip3 install -r /opt/wireguard-manager/requirements.txt
RUN rm /opt/wireguard-manager/requirements.txt
ADD . /opt/wireguard-manager/.
EXPOSE 6000

WORKDIR /opt/wireguard-manager
ENV PYTHONPATH /opt/blah
CMD ["python3", "-u", "/opt/wireguard-manager/src/app.py"]
