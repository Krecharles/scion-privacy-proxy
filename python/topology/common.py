# Copyright 2018 ETH Zurich, Anapaya Systems
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Stdlib
from ipaddress import ip_address
import os
import subprocess
from urllib.parse import urlsplit
from typing import Mapping, Tuple, List

# SCION
from python.lib.scion_addr import ISD_AS
from python.topology.net import AddressProxy, NetworkDescription, IPNetwork

COMMON_DIR = 'endhost'

SCION_SERVICE_NAMES = (
    "control_service",
    "discovery_service",
    "border_routers",
    "colibri_service",
)

BR_CONFIG_NAME = 'br.toml'
BS_CONFIG_NAME = 'bs.toml'
CS_CONFIG_NAME = 'cs.toml'
PS_CONFIG_NAME = 'ps.toml'
CO_CONFIG_NAME = 'co.toml'
SD_CONFIG_NAME = 'sd.toml'
DISP_CONFIG_NAME = 'disp.toml'
SIG_CONFIG_NAME = 'sig.toml'

SD_API_PORT = 30255


class ArgsBase:
    def __init__(self, args):
        for k, v in vars(args).items():
            setattr(self, k, v)


class ArgsTopoConfig(ArgsBase):
    def __init__(self, args, topo_config):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param dict topo_config: The parsed topology config.
        """
        super().__init__(args)
        self.config = topo_config


class ArgsTopoDicts(ArgsBase):
    def __init__(self, args, topo_dicts):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param dict topo_dicts: The generated topo dicts from TopoGenerator.
        """
        super().__init__(args)
        self.topo_dicts = topo_dicts


class TopoID(ISD_AS):
    def ISD(self):
        return "ISD%s" % self.isd_str()

    def AS(self):
        return "AS%s" % self.as_str()

    def AS_file(self):
        return "AS%s" % self.as_file_fmt()

    def file_fmt(self):
        return "%s-%s" % (self.isd_str(), self.as_file_fmt())

    def base_dir(self, out_dir):
        return os.path.join(out_dir, self.AS_file())

    def __lt__(self, other):
        return str(self) < str(other)

    def __repr__(self):
        return "<TopoID: %s>" % self


def replace_port(addr: str, port: int) -> str:
    ip, _ = split_host_port(addr)
    return join_host_port(ip, port)


def split_host_port(addr: str) -> Tuple[str, int]:
    parts = urlsplit('//' + addr)
    if parts.port is None:
        raise ValueError("missing port in addr: {}".format(addr))
    # first remove the port, and strip ipv6 brackets:
    ip = parts.netloc.rsplit(sep=':{}'.format(parts.port),
                             maxsplit=1)[0].strip('[]')
    return (ip, parts.port)


def join_host_port(host: str, port: int) -> str:
    ip = ip_address(host)
    if ip.version == 4:
        return '{}:{}'.format(host, port)
    return '[{}]:{}'.format(host, port)


def sciond_ip(docker, topo_id, networks: Mapping[IPNetwork,
                                                 NetworkDescription]):
    for net_desc in networks.values():
        for prog, ip_net in net_desc.ip_net.items():
            if prog == 'sd%s' % topo_id.file_fmt():
                return ip_net.ip
    return None


def colibri_ip_list(docker, topo_id,
                    networks: Mapping[IPNetwork, NetworkDescription]) -> List[str]:
    list = []
    for net_desc in networks.values():
        for prog, ip_net in net_desc.ip_net.items():
            if '-'.join(prog.split('-')[0:2]) == 'co%s' % topo_id.file_fmt():
                list.append(str(ip_net.ip))
    return list


def prom_addr_dispatcher(docker, topo_id,
                         networks: Mapping[IPNetwork,
                                           NetworkDescription], port, name):
    if not docker:
        return "[127.0.0.1]:%s" % port
    target_name = ''
    if name.startswith('disp_br'):
        target_name = 'br%s%s_internal' % (topo_id.file_fmt(), name[-2:])
    elif name.startswith('disp_sig'):
        target_name = 'sig%s' % topo_id.file_fmt()
    else:
        target_name = 'disp%s' % topo_id.file_fmt()
    for net_desc in networks.values():
        if target_name in net_desc.ip_net:
            return '[%s]:%s' % (net_desc.ip_net[target_name].ip, port)
    return None


def docker_image(args, image):
    if args.docker_registry:
        image = '%s/%s' % (args.docker_registry, image)
    if args.image_tag:
        image = '%s:%s' % (image, args.image_tag)
    return image


def docker_host(docker, addr=None):
    if docker or not addr:
        # Using docker topology or there is no default addr,
        # we directly get the DOCKER0 IP
        addr = docker_ip()
    return addr


def docker_ip():
    return subprocess.check_output(['tools/docker-ip']).decode("utf-8").strip()


def remote_nets(networks, topo_id):
    """
    Returns the subnets of all remote ASes the SIG in topo_id is connected to.
    :param networks dict: Scion elem to subnet/IP map.
    :param topo_id: A key of a topo dict generated by TopoGenerator.
    :return: String of comma separated subnets.
    """
    rem_nets = []
    for key in networks:
        if 'sig' in key and topo_id.file_fmt() not in key:
            rem_nets.append(str(networks[key][0]['net']))
    return ','.join(rem_nets)


def sciond_name(topo_id):
    return 'sd%s' % topo_id.file_fmt()


def sciond_svc_name(topo_id):
    return 'scion_%s' % sciond_name(topo_id)


def json_default(o):
    if isinstance(o, AddressProxy):
        return str(o.ip)
    raise TypeError


def translate_features(features):
    f = dict(features)
    return f
