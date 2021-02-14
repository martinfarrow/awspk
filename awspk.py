#!/usr/bin/env python3
import boto3
from botocore.exceptions import ClientError
import os.path
import json
import dateutil.parser as dp
import datetime
import time
import click
import re
import logging 
import os
import sys
import pathlib
import ssmParameterManager as spm

import importlib.util
import fluentWrap as fl
import awsDataCollector

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', datefmt='%Y:%m:%d-%H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def add_options(options):
    """decoration to add a set of options to a function based on a passed list rather than explicitly """
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func

    return _add_options

class containerCategories():
    FRONTEND=re.compile('^frontend_', re.IGNORECASE)
    DOCSERVER=re.compile('doc_', re.IGNORECASE)
    DBLOADER=3
    AFFORD=4
    pass

ERROR_IGNORE = [
    'IncorrectInstanceState',
    'ScalingActivityInProgress',
    'InvalidInstanceID.NotFound'
]
def canSafelyIgnore(exc):
    if exc.response.get('Error', {}).get('Code') not in ERROR_IGNORE:
        raise(exc)



class printer():
    """A output formater for the display manager"""

    formats = {
            "AMI": "Id: {:<25} Date: {} Owner: {} Name: {:20.20}",
            "AMIshort": "Id: {:<25} Date: {} Owner: {}",
            "AMIname": (" " * 8) +" Name: {}",
            "AMIdesc": (" " * 8) +" Desc: {}",
            "MajorSep": "---",
            "MinorSep": "",
            "EC2": "{:.<32}.({}): {:^14}: PrivIP: {:<15} PubIP: {:<15} Uptime: {}",
            "EC2N": "{:<32} ({}): {:^14}: Launched: {}",
            "EC2rdns": "{:>20}: {}",
            "EC2SG": "{:>20}: {}",
            "EC2Price": "{:>20}: {} ({}) @ {:0.4f} hrs = {:0.2f}",
            "EC2xtra": "{:>20}: {}",
            "ECR": "  Name: {:.<30} Created {:<20} ({:<})",
            "ECRimages": (" " * 8) +" Tag: {:<30} Date: {} Size:{:6.2f}M",
            "ECRimagesUntagged": (" " * 8) +" Tag: {:<71} Date: {}, Size(M):{:6.2f}",
            "HostedZones": "{:.<30} FQDN:{:<20} Private: {:<6} Comment: {}",
            "HostedZone": "Hosted Zone({})",
            "RR": "{:>6}:{:<}",
            "RRvalues": "      : {}",
            "VPC": "{:<44} cidr: {:<15} Default:{:<5} id: {:<25}",
            "CacheCluster": "{:.<30}.({:^11}) Node: {:13} Engine: {} ({})",
            "RDS": "{:.<30}.({:^10}) Type: {:13} Storage: {:4d}GB Replica: {}",
            "RDSEngine": "{:>20}: {}({})",
            "RDSIndent": "{:>20}: {}",
            "RDSPrice": "{:>20}: {:9,.2f}",
            "Terse": "{}:{}",
            "ReplGroup": "Cluster: {} ({}), AutoFailover: {}, {}:{}",
            "LB": "{:.<40}.Type: {:<12}DNS: {:<}",
            "ASG": "{:.<32}.state:{:<12} Min-(Des-Actual)-Max:{:02d}-({:02d}-{:02d})-{:02d} Uptime: {}",
            "LC": "     Launch Config Created: {:<32} image: {:<12} pubIP: {:<16} {:<22} md5: {}",
            "NOLC": "     No Lanuch Config",
            "LCINSTMD5": "     {:<32} ({}): {:^14}: LifeCycle: {:<15} Health: {:<15} md5: {}",
            "LCINST": "     {:<32} ({}): {:^14}: LifeCycle: {:<15} Health: {:<15}",
            "SG": "  Security Group: {}",
            "SGS": "{:.<35}({:<})",
            "SGSIN": "  Ingress",
            "SGSEG": "  Egress",
            "SGSPROT": "      [{}] From: {} -> {} ({})",
            "SGSGP":   "        [{}]  {:<19} ({})",
            "SGSIP":   "        [{}]  {:<19} {}",
            "TGS": "   Target Group: {}",
            "VOL": "{:.<20}...State: {:<12} AZ: {:<15} Type: {:<12}",
            "VOLinst": "  {:<30}  Delete: {:<8}  Device: {:<10}  Attach date: {}",
            "Snap": "{:.30}..Owner: {:<20} State: {:<12} Size: {:<10} Date: {:<}",
            }

    def __init__(self):
        self.formatKey = None

    def printDirect(self, fmt, val):
        print(fmt.format(*vals))

    def print(self, *args): 
        """Output the requested standard format line"""
        if self.formatKey is None:
            raise ValueError("You cannot print without calling a format")
        print(printer.formats[self.formatKey].format(*args))

    def __getattr__(self, item):
        if item not in printer.formats:
            raise NotImplementedError("Output format ({}), is not implemented".format(item))
        self.formatKey = item
        return self.print

class outputManager():

    container_2_image = { "docserver": 'doc',
                          "frontend" : 'frontend',
                          "dbloader" : 'dbloader',
                          "affordability": 'affordability',
                          "scorecard": 'scorecard',
                          "pvm" : 'pvm'
                        }

    validDataTypes = [ "rds" ]

    def __init__(self, dataCollector=None, log=None):
        self.log = log
        self.adc = dataCollector

        # a bunch of regexps for various tasks
        self.dockerPsRe = re.compile(r'([^/]+)/([^/]+)\n', re.MULTILINE)
        self.dockerNameRe = re.compile(r'^[^_]+_([^_]+)_')
        self.dockerTimeRe = re.compile(r'^([^ ]+) ([^ ]+) ([-+][0-9][0-9])([0-9][0-9])')
        self.OutRe = re.compile(r'(.*)\n', re.MULTILINE)
        self.cloudInitSS = re.compile(r'(^\S+ \S+ \S+) .*---User Data ([^-]+)----.*$')
        self.cloudInit = re.compile(r'(^\S+ \S+ \S+) .*===>(Starting|Completed) (.*)<====$')

        # message output, to provide a single place for format configurations
        # and output so that it can be modified to do different things in future

        self.print = printer()

        # asg output control

        self.user_data = False
        self.allAsgs = None
        self.deployAsgs = None

        # ssh writing config

        self.config = dict()
        self.IdentityFile = None
        self.ProxyHost = None
        self.ProxyMatch = None
        self.ec2user = None

        # internal state indicators

        self.configLoaded = False
        self.builtConnections = False

        # terse output

        self.terse = False

        # formating control

        self.dataType = None
        self.formatArgs = None
        self.formatValues = []

    def setDataType(self, dataType):
        if str(dataType).lower() not in self.validDataTypes:
            raise ValueError("Invalid dataType: {}".format(dataType))
        self.dataType = str(dataType).lower

    def setFormatArgs(self, args):
        if not isInstance(args, str):
            raise TypeError("Format args must be a string")
        self.formatArgs = args

    def setFormatValues(self, values):
        if not isInstance(values, list):
            raise TypeError("Format values must be encased in a list")
        self.formatValues = values

    def outputByFormat(self):
        objectState = True
        if self.DataType is None:
            objectState = False
            self.log.error("Datatype must be set to use outputByFormat")

        if self.formatArgs is None:
            objectState = False
            self.log.error("FormatArgs must be set to use outputByFormat")

        if len(self.formatValues)==0:
            objectState = False
            self.log.error("FormatValues must be set to use outputByFormat")

        if objectState is False:
            raise ValueError("Cannot output, please supply the missing values")

    def __validateArgs(self):
        printFormat = str(self.DataType)+'Custom'
        self.print.printDirect(self.formatArgs, self.formatValues)

    def __validatePrintArgs(self):
        pass


    def setTerse(self, value):
        self.terse = value

    def displayAMI(self, description=False):
        for ami in sorted(self.adc.ami, key=lambda ami: dp.parse(ami.CreationDate).timestamp()):
            if not description:
                self.print.AMI(ami.ImageId,
                               dp.parse(ami.CreationDate).strftime("%Y-%m-%d %H:%M:%S"),
                               ami.OwnerId,
                               ami.Name)
                continue
            if (description):
                self.print.AMIshort(ami.ImageId,
                               dp.parse(ami.CreationDate).strftime("%Y-%m-%d %H:%M:%S"),
                               ami.OwnerId)
                self.print.AMIname(ami.Name)
                self.print.AMIdesc(ami.Description)

    def displaySpot(self, session):

        filters = { 'Location': 'EU (London)',
                    'instanceType': 'db.m5.2xlarge',
                    'databaseEngine': 'MySQL',
                    'deploymentOption': 'Multi-AZ', }
        pricer = awsDataCollector.awsPrice('AmazonRDS', session, self.log)
        pricer.setFilter(filters)
        pricer.getPrices()

        #print(pricer.prices.prettyString(leader="."))
        #print(pricer.prices.get(0).terms.OnDemand.prettyString(leader="."))

        #pricer = awsDataCollector.awsPrice('AmazonEC2', session, self.log)
        #filters = { 'Location': 'EU (London)',
        #            'instanceType': 't3.large',
        #            'operatingSystem': 'Linux',
        #            'preinstalledsw': 'NA',
        #            'capacitystatus': 'used',
        #            'tenancy': 'shared'
        #           }
        #pricer.setFilter(filters)
        #pricer.getPrices()
        #print(pricer.prices.prettyString(leader="."))
        print(pricer.prices.len())
        for price in pricer.prices:
            print(price.terms.OnDemand.get(0).priceDimensions.get(0).description)
            print(price.terms.OnDemand.get(0).priceDimensions.get(0).pricePerUnit.USD)
            #print(price.product.attributes.capacitystatus)
            #print(price.terms.OnDemand.get(0).sku)

        
        return

        for service in self.adc.services:
            print(service)
            for attributeName in service.AttributeNames:
                print(attributeName)


        print(self.adc.prices)
        print(self.adc.prices.prettyString(leader="."))
        #for price in self.adc.prices:
        #    print(price)
        #    print("---------")
        #print(self.adc.spotHistory)
        #for p in self.adc.spotHistory:
        #    print(p)

    def displayCacheClusters(self, raw=False):
        if (raw):
            print(self.adc.cacheClusters.prettyString())
        for cc in self.adc.cacheClusters:
            if self.terse:
                self.print.Terse(cc.CacheClusterId, cc.CacheClusterStatus)
                continue

            self.print.CacheCluster(cc.CacheClusterId,
                                    cc.CacheClusterStatus,
                                    cc.CacheNodeType,
                                    cc.Engine,
                                    cc.EngineVersion)

    def displayReplGroups(self, raw=False):
        """Display information about detected Elasticache or redis replicationGroups"""
        if (raw):
            print(self.adc.replicationGroups.prettyString())
        for rg in self.adc.replicationGroups:
            if self.terse:
                self.print.Terse(g.ReplicationGroupId, rg.Status)
                continue

            self.print.ReplGroup(g.ReplicationGroupId,
                                             rg.Status,
                                             rg.AutomaticFailover,
                                             rg.ConfigurationEndpoint.Address,
                                             rg.ConfigurationEndpoint.Port)

            no_node_groups = rg.NodeGroups.len()

            # display the members in node groups

            every = rg.MemberClusters.len()/no_node_groups
            count = 0 
            for member in rg.MemberClusters:
                if count%every == 0:
                    print("    ", end="")
                print( "{} ".format(member), end="")
                count += 1
                if count%every == 0:
                    print("")

    def displayLoadBalancers(self, sg=False, tg=False):
        for lbs in self.adc.v2lbs + self.adc.lbs:
            self.print.LB(lbs.LoadBalancerName, lbs.Type, lbs.DNSName)
            if sg:
                for sgid in lbs.SecurityGroups:
                    self.print.SG(self.adc.sgsByGroupId[sgid].GroupName)
            if (tg and lbs.LoadBalancerArn in self.adc.lbsByArn):
                for tg in self.adc.lbsByArn[lbs.LoadBalancerArn].targetGroups:
                    self.print.TGS(tg.TargetGroupName)


    def displayHostedZones(self):
        for hz in self.adc.dns:
            self.print.HostedZones(hz.Id, hz.Name, str(hz.Config.PrivateZone), hz.Config.Comment)

    def prepareRE(self, reList):
        """If an passed re doesn't look like an re then encase it to 
           make it work more like grep """
        results = list()
        for candRE in reList:
            if (re.match('^[0-9A-Za-z-._=:/@]+$', candRE)):
                outRE='.*{}.*'.format(candRE)
            else:
                outRE=candRE
            try:
                resRE = re.compile(outRE)
            except re.error as ree:
                self.log.error('RE "{}" failed to compile'.format(outRE))
                continue
            results.append(resRE)
        return results

    def displayAsgs(self, LaunchConfig=False, Instances=False, asgnames=[]):
        """Display the matching asgs"""
        if (len(asgnames) > 0):
            asgREs = self.prepareRE(asgnames)

        for asg in self.adc.deployAsgs:
            if (len(asgnames) > 0):
                skip = True
                for asgnameRE in asgREs:
                    #if re.match(".*{}.*".format(asgname), asg.name):
                    if asgnameRE.match(asg.name):
                        skip = False
                        break
                if skip:
                    continue
            self.printAsg(asg, LaunchConfig=LaunchConfig, Instances=Instances)

    def displayVols(self, attach=False):
        for vol in self.adc.volumes:
            self.print.VOL(vol.VolumeId, vol.State, vol.AvailabilityZone, vol.VolumeType)
            if attach:
                found = False
                for att in vol.Attachments:
                    found = True
                    attachdate = self.toISO8601(att.AttachTime)
                    if att.InstanceId in self.adc.ec2hostsById:
                        self.print.VOLinst(self.adc.ec2hostsById[att.InstanceId].name,
                                           "True" if att.DeleteOnTermination else "False",
                                           att.Device,
                                           attachdate)
                if found:
                    self.print.MinorSep()

    def displaySnaps(self):
        for snap in self.adc.snapshots:
            self.print.Snap(snap.ShapshotId, snap.OwnerId, snap.State, snap.VolumeSize,
                            self.toISO8601(snap.StartTime))


    def printInstanceIds(self):
        """Print out instanceIds only"""
        #self.adc.loadConfig()
        for host in self.adc.getHosts(running=True):
            print(host.instance.id)

    def displayInstances(self, writessh=False, listContainers=False, 
                         contDetail=False, showSG=False, rDNS=False, price=False, details=False):
        """ Parse the detected instances so that they can be displayed"""

        doneCon = False

        if (listContainers):
            self.adc.loadConfig()
            self.adc.buildConnections()
            doneCon = True

        for host in self.adc.getHosts(running=True):
            self.printInstance(host)
            if rDNS:
                self.displayHostRdns(host)
            if doneCon:
                conn = host.connection
            if (listContainers):
                self.listContainers(conn, contDetail)
            if (showSG):
                self.displayInstanceSGs(host.instance)
            if (price):
                self.displayInstancePrice(host)
            if (details):
                self.displayInstanceDetails(host)


        self.print.MajorSep()
        for host in self.adc.getHosts(running=False):
            self.printInstance(host)

        if writessh:
            self.adc.loadConfig("./config.json")
            self.writeSSHconfig()

    def displayHostRdns(self, host):
        """Display Host Reverse DNS lookup information"""
        if host.instance.private_ip_address in self.adc.ipRRCrossRef:
            for rr in self.adc.ipRRCrossRef[host.instance.private_ip_address]:
                self.print.EC2rdns("priv-rDNS", rr.Name)
        if host.instance.public_ip_address in self.adc.ipRRCrossRef:
            for rr in self.adc.ipRRCrossRef[host.instance.public_ip_address]:
                self.print.EC2rdns("pub-rDNS", rr.Name)

    def displayInstanceSGs(self, instance):
        """Display host security group information"""
        for sg in instance.security_groups:
            self.print.EC2SG("Security Group", sg['GroupName'])

    def displayInstancePrice(self, host):
        uphours = (int(host.uptime)/3600.00)
        totalprice = uphours * float(host.price)
        self.print.EC2Price("Price/Hr", float(host.price), host.instance.instance_type,
                            uphours, totalprice)

    def displayInstanceDetails(self, host):
        self.print.EC2xtra("Root Device", host.instance.root_device_type)
        self.print.EC2xtra("Instance Type", host.instance.instance_type)
    
    def printInstance(self, host):
        """ Print information on the passed host object"""
        if host.running:
            uptime = self.toDHMS(host.uptime, 'string')
            self.print.EC2(host.name, host.instance.id, self.getStateString(host.instance),
                           str(host.instance.private_ip_address), str(host.instance.public_ip_address),
                           uptime)
            return

        if not host.running:
            lt_datetime = dp.parse(str(host.instance.launch_time))
            self.print.EC2N(host.name, host.instance.id, self.getStateString(host.instance),
                            lt_datetime.strftime("%Y-%m-%d %H:%M:%S"))
            return

    def printAsg(self, asg, LaunchConfig=False, Instances=False):
        """Print information about an autoscaling group"""

        uptime = self.adc.upTime(asg.CreatedTime)
        uptimeStr = self.toDHMS(uptime, 'string')

        stateStr = 'Suspended' if self.adc.isAsgSuspended(asg) else 'Normal'

        if self.terse:
            self.print.Terse(asg.name, stateStr)
            return

        self.print.ASG(asg.name, stateStr, asg.MinSize, asg.DesiredCapacity, asg.Instances.len(),
                       asg.MaxSize, uptimeStr)
        if (LaunchConfig):
            self.printLaunchConfig(asg)
        if (Instances):
            self.printAsgInstances(asg, LaunchConfig)

    def printLaunchConfig(self, asg):
        if asg.LaunchConfiguration.len() == 0:
            self.print.NOLC()
            return
        lc=asg.LaunchConfiguration.get(0)
        ud = self.adc.getUserDataData(lc.UserData)
        ct = lc.CreatedTime.strftime("%Y-%m-%d %H:%M:%S")
        imgid = lc.ImageId
        pubIP = "False" if lc.AssociatePublicIpAddress is None else "True"
        self.print.LC(ct, imgid, pubIP, " ",ud.md5)

    def printAsgInstances(self, asg, LaunchConfig=False):
        """ Print out data about Instances in a particular ASG """
        for instance in asg.Instances:
            host = self.adc.ec2hostsById[instance.InstanceId]
            host = instance + host
            flw = fl.fluentWrap(host.instance.describe_attribute(Attribute='userData'))
            ud = self.adc.getUserDataData(flw.UserData.Value)
            args = [ host.name, 
                     host.instance.id,
                     self.getStateString(host.instance),
                     host.LifecycleState,
                     host.HealthStatus ]
            if LaunchConfig:
                args.append(ud.md5)
                self.print.LCINSTMD5(*args)
            else:
                self.print.LCINST(*args)

    def writeSSHconfig(self):
        """ builds a sshconfig file for the detected hosts with the configuration supplied by the user """

        configfile = os.path.abspath("./sshconfig")
        with open(configfile, mode="w", newline=None) as configFile:
            configFile.write("host *\n")
            configFile.write("  ServerAliveInterval 240\n")
            configFile.write("\n")

            # is there a jump host configuration, if so write it

            if (self.adc.jump is not None):
                jdentity = None
                juser = None
                jhost = None
                if ('IdentityFile' in self.adc.jump):
                    jdentity = self.adc.jump['IdentityFile']

                if ('jumpuser' in self.adc.jump):
                    juser = self.adc.jump['jumpuser']

                if ('jumphost' in self.adc.jump):
                    jhost = self.adc.jump['jumphost']

                if jhost is not None:
                    configFile.write("host jumpHost\n")
                    configFile.write("  hostname {}\n".format(jhost))

                    if jdentity is not None:
                        configFile.write("  IdentityFile {}\n".format(jdentity))

                    if juser is not None:
                        configFile.write("  user {}\n".format(juser))
                
                    configFile.write("\n")

            # search for the proxy host, it has to have a public ip

            localProxyHost = None
            for host in self.adc.getHosts(running=True):
                if re.match('^.*{}.*$'.format(self.adc.ProxyMatch), host.name, re.IGNORECASE):
                    if host.instance.public_ip_address is not None:
                        localProxyHost = host
                        break

            for host in self.adc.getHosts(running=True):

                # check if the host has a public ip                 
                if host.instance.public_ip_address is not None:
                    ip = host.instance.public_ip_address
                    entryType = 'public'
                elif host.instance.private_ip_address is not None:
                    ip = host.instance.private_ip_address
                    entryType = 'private'
                else:
                    next

                # can't connect to hosts without a public ip if the
                # ProxyMatch setting wasn't given for this group

                if entryType == 'private' and localProxyHost is None:
                     continue

                # write the config for this host

                configFile.write("host {}\n".format(host.name))
                configFile.write("  # {}\n".format(host.instance.id))
                configFile.write("  hostname {}\n".format(str(ip)))
                if (self.adc.ec2user is not None):
                    configFile.write("  user {}\n".format(self.adc.ec2user))
                if (self.adc.IdentityFile is not None):
                    configFile.write("  IdentityFile {}\n".format(self.adc.IdentityFile))

                if entryType == 'private':
                    configFile.write("  ProxyCommand ssh -F {} -W %h:%p {}\n".format(configfile, localProxyHost.name))
                else:
                    if self.adc.ProxyHost is not None:
                        configFile.write("  ProxyCommand ssh -W %h:%p {}\n".format(self.adc.ProxyHost))
                    elif jhost is not None:
                        configFile.write("  ProxyCommand ssh -F {} -W %h:%p jumpHost\n".format(configfile))

                configFile.write("  UserKnownHostsFile=/dev/null\n")
                configFile.write("  StrictHostKeyChecking=no\n")
                configFile.write("\n")

    def toDHMS(self, seconds, return_type='list'):
        """Utility function to convert seconds to days, hours, minutes and seconds """
        remainder = int(seconds)
        days  = divmod(remainder, 86400)[0]
        remainder = remainder - (86400 * days)

        hours  = divmod(remainder, 3600)[0]
        remainder = remainder - (3600 * hours)

        minutes  = divmod(remainder, 60)[0]
        seconds = remainder - (60 * minutes)

        if return_type == 'string':
            return "{:4d}-{:02d}:{:02d}:{:02d}".format(days, hours, minutes, seconds)

        return([days, hours, minutes, seconds])

    def toISO8601(self, awsDateTime):
        """Utility to convert aws date-time formats to ISO8601"""
        return dp.parse(str(awsDateTime)).strftime("%Y-%m-%d %H:%M:%S")

    def displayRepos(self, tagged=True, untagged=False):
        """Display gathered ECR repo data"""
        for repo in sorted(self.adc.repos, key=lambda repo: repo.repositoryName):
            cr_datetime = dp.parse(str(repo.createdAt)).strftime("%Y-%m-%d %H:%M:%S")
            self.print.ECR(repo.repositoryName, cr_datetime, repo.imageTagMutability.lower()+ " tags")
            for image in sorted(repo.imageIds, key=lambda repo: dp.parse(str(repo.imagePushedAt)).timestamp()):
                pushDate = dp.parse(str(image.imagePushedAt)).strftime("%Y-%m-%d %H:%M:%S")
                size = image.imageSizeInBytes/1000000
                if untagged:
                    imageprint=self.print.ECRimagesUntagged
                else:
                    imageprint=self.print.ECRimages

                if image.imageTag is not None:
                    if tagged:
                        imageprint(image.imageTag, pushDate, size)
                elif untagged:
                    imageprint(image.imageDigest, pushDate, size)

    def displayRecordSets(self, hostzoneid, RE=None, TYPE=None):
        if not hostzoneid in self.adc.rr:
            self.log.error("Unknown hosted zone {}".format(hostedzoneid))
            return

        if RE is not None:
            try:
                valueRE = re.compile(RE)
            except re.error as ree:
                self.log.warn("RE value of '{}' ignored, it will not complile".format(RE))
                valueRE = re.comple(".*")
        else:
            valueRE = re.compile(".*")


        self.print.HostedZone(hostzoneid)
        self.print.MajorSep()

        for rr in self.adc.rr[hostzoneid]:
            if not valueRE.match(rr.Name):
                continue

            if TYPE is not None and rr.Type != TYPE:
                continue

            self.print.RR(rr.Type, rr.Name)
            for rrs in rr.ResourceRecords:
                self.print.RRvalues(rrs.Value)
            self.print.MinorSep()

    def displayVPCs(self):
        for name in self.adc.vpc:
            vpc = self.adc.vpc[name]
            self.print.VPC(name, vpc.cidr, vpc.default, vpc.id) 

            for hz in vpc.hostedZones:
                print("  HostedZone: {:<30} FQDN:{:<20}".format(hz.HostedZoneId, hz.Name))

            for subnet in vpc.subnets:
                print("      subnet: {:<25}      cidr: {:<15}".format(subnet.name,
                                                  subnet.cidr))
                for ngw in subnet.ngws:
                    print("              Ngw: {:<15}".format(ngw.name))

                    for address in ngw.addresses:
                        print("                                          Private: {:<14}  Public: {:<14}".
                                format(address.private, address.public))
            self.print.MajorSep()


    def displaySecurityGroups(self, sgNames):

        if ( len(sgNames) == 0 ):
            for sg in self.adc.sgs:
                self.__displaySecurityGroup(sg)
            return

        for sgname in sgNames:
            self.__displaySecurityGroup(self.adc.getSgByName(sgname))


    def __displaySecurityGroup(self, sg):

        if sg is None:
            return

        tagname = self.adc.getNameTag(sg.Tags)
        self.print.SGS(sg.GroupName, sg.GroupId)
        self.print.SGSIN()
        self.__displayIpPerms(sg.IpPermissions, self.adc.sgsByGroupId)
        self.print.SGSEG()
        self.__displayIpPerms(sg.IpPermissionsEgress, self.adc.sgsByGroupId)
        self.print.MinorSep()

    def __displayIpPerms(self, permissions, byGroupId):

            permCount = 0 
            for perm in permissions:
                permCount += 1
                self.print.SGSPROT( permCount, perm.FromPort, perm.ToPort, perm.IpProtocol)
                itemCount = 0
                for iprange in perm.IpRanges:
                    itemCount += 1
                    if iprange.Description is None:
                        desc = ""
                    else:
                        desc = "({})".format(iprange.Description)

                    self.print.SGSIP( itemCount, iprange.CidrIp, desc)
                for udip in perm.UserIdGroupPairs:
                    itemCount += 1
                    if udip.GroupId in self.adc.sgsByGroupId:
                        name = self.adc.sgsByGroupId[udip.GroupId].GroupName
                    else:
                        name = "Unknown"

                    self.print.SGSGP(itemCount, name, udip.GroupId)

    def isReplica(self, db):
        return db.checkPath("ReadReplicaSourceDBInstanceIdentifier")

    def displayRDS(self, details=False, cost=False, raw=False, noRep=False, rdsNames=[]):

        for db in self.adc.db:
            if (len(rdsNames) != 0 and 
                    db.DBInstanceIdentifier not in rdsNames):
                continue

            if noRep and self.isReplica(db):
                continue

            if self.terse:
                self.print.Terse(db.DBInstanceIdentifier, db.DBInstanceStatus)
                continue

            self.__displayRDS(db) 
            if details:
                self.displayRDSdetails(db)
            if cost:
                self.displayRDScost(db)
            if raw:
                print(db.prettyString(leader='.'))


    def __displayRDS(self, db):
            upSeconds = self.adc.upTime(db.InstanceCreateTime)
            uptime = self.toDHMS(upSeconds, 'string')
            rr = "True" if self.isReplica(db) else "False"
            self.print.RDS(db.DBInstanceIdentifier[:30],
                           db.DBInstanceStatus,
                           db.DBInstanceClass,
                           db.AllocatedStorage,
                           rr)

    def displayRDSdetails(self, db):
        self.print.RDSEngine("Engine", db.MasterUsername, db.EngineVersion)
        self.print.RDSIndent("Master User", db.Engine)
        self.print.RDSIndent("Placement", "Multi-AZ" if db.MultiAZ else "Single-AZ" )

    def displayRDScost(self, db):
        upSeconds = self.adc.upTime(db.InstanceCreateTime)
        dbPrice = float(upSeconds/3600.00) * db.price
        self.print.RDSPrice("CPU Cost", dbPrice)

    def displayServices(self, details=False, match=None):
        
        if match is not None:
            try:
                matchRE = re.compile(match, re.IGNORECASE)
            except re.error as ree:
                self.log.error("Match regular expression ({}) will not compile".format(match))
                return

        for service in self.adc.services:
            if match is not None:
                latch = True
                for attribute in service.AttributeNames:
                    if matchRE.match(attribute):
                        if latch:
                            print(service.ServiceCode)
                            latch = False
                        print("  {}".format(attribute))
                continue

            print(service.ServiceCode)
            if details:
                for attribute in service.AttributeNames:
                    print("  {}".format(attribute))


    def getStateString(self, instance):
        s = instance.state['Code'] & 255
        state = "Unknown"
        if s == 0:
            state='Pending'
        elif s == 16:
            state='Running'
        elif s == 32:
            state='Shutting-Down'
        elif s == 48:
            state='Terminated'
        elif s == 64:
            state='Stopping'
        elif s == 80:
            state='Stopped'
        return state

    def hostUserDataStatus(self, c):

            dockerInstalled = None

            result = c.sudo("cat /proc/uptime | cut -d ' ' -f1 | cut -d '.' -f1", hide=True, warn=True)
            if ( result.exited == 0 ):
                uptime = result.stdout

            if (int(uptime) >= 41000):
                dockerInstalled = True
            else:
                result = c.sudo("grep cloud-init /var/log/messages | egrep '(----User|====>)'", hide=True, warn=True)
                UDtime = dict()
                if ( result.exited == 0 ):
                    dockerInstalled = False
                    for line in self.OutRe.findall(result.stdout):
                        SSmatch = self.cloudInitSS.match(line)
                        if (SSmatch):
                            UDtime[SSmatch.group(2).lower()]=SSmatch.group(1)
                            continue

                        CImatch = self.cloudInit.match(line)
                        if not CImatch:
                            continue
                        if not dockerInstalled:
                            dockerInstalled = ( "installdocker()" == str(CImatch.group(3)).lower() and str(CImatch.group(2)).lower() == "completed" ) 

                    if ( "end" in UDtime ):
                        print("  {:28}: {:<}".format("User Data Complete", UDtime['end']))
                    elif ( "start" in UDtime ):
                        print("  {:28}: {:<}".format("User Data still running", UDtime['start']))


    def listContainers(self, c, detail=False):
        if c is None:
            self.log.warning("No connection established cannot list containers")
            return

        result = c.sudo(r'docker ps --format "{{.Names}}/{{.CreatedAt}}"', hide=True, warn=True)
        if ( result.exited == 0 ):
            output = self.dockerPsRe.findall(result.stdout)
            for line in output:
                container_name = line[0]
                time_match = self.dockerTimeRe.match(line[1])
                if ( time_match ):
                    start = dp.parse(time_match.group(1)+'T'+time_match.group(2)+time_match.group(3)+':'+time_match.group(4))
                    delta = datetime.datetime.now(start.tzinfo) - start
                    seconds = int(delta.total_seconds())
                    container_start = self.toDHMS(seconds, return_type='string')
                    message="Uptime"
                else:
                    message="Started"
                    container_start = line[1]

                built_from = ""
                raw_name_match = self.dockerNameRe.match(container_name)
                if raw_name_match :
                    build_name = raw_name_match.group(1)
                    if build_name in self.container_2_image:
                        build_name = self.container_2_image[build_name]

                    image_result = c.sudo('docker image ls | grep '+build_name+' | grep ecr | ( while read line; do set $line; echo $2; done)', hide=True, warn=True)
                    if ( image_result.exited == 0 ):
                        built_from_match = self.OutRe.match(image_result.stdout)
                        if built_from_match :
                            built_from = built_from_match.group(1)


                if detail:
                    print("{:>30}".format('---'))

                leader = 59 * "."
                print("{:>30}: From: {:<20} {:<59} {}: {:<}".format(container_name, built_from, leader, message, container_start))

                if detail:
                    self.inspectContainer(c, container_name)
        else:
            print("  Docker not Installed")
        print("")



    def inspectContainer(self, c, name):

        if c is None:
            self.log.warning("No connection established cannot inspect containers")
            return

        result = c.sudo("docker inspect {}".format(name), hide=True, warn=True)
        if ( result.exited == 0 ):
            cData = json.loads(result.stdout)
            for bind in cData[0]['HostConfig']['Binds']:
                print("{:>30}: {}".format("Mount", bind))
            for port in cData[0]['NetworkSettings']['Ports']:
                hostport = cData[0]['NetworkSettings']['Ports'][port][0]['HostPort']
                print("{:>30}: {}->{}".format("Port", hostport, port))


class genController():

    def __init__(self, dataCollector=None, log=None, timeOut=600, loopTime=5):
        self.adc = dataCollector 
        self.log = log

        # all in seconds

        self.timeout = timeOut
        self.loopTime = loopTime

class ecrControllerException(Exception):
    pass

class ecrController():

    def __init__(self, dataCollector, log, repoName):
        self.adc = dataCollector 
        self.log = log
        self.repoName = repoName
        self.repo = None
        self.imageTags = list()
        self.imageDigests = list()

        self.__setRepo()

        if (self.repo is None):
            raise ecrControllerException("Repo ({}) is not present in the passed aws data controller".format(repoName))

    def __setRepo(self):
        for repo in self.adc.repos:
            if repo.repositoryName == self.repoName:
                self.repo = repo
                return

    def addTags(self, images):
        addImages = images

        # only add images for deletion that are actually in the repo

        for candImage in addImages:
            foundIt = False
            for image in self.repo.imageIds: 
                if image.imageTag is not None and image.imageTag == candImage:
                    self.imageTags.append(candImage)
                    foundIt = True
                    break
            if not foundIt:
                self.log.warning("Image tag({}), not found in repo({})".format(candImage, self.repoName))


    def addDigests(self, images, untagged=False):

        if untagged:
            images=list()
            for image in self.repo.imageIds:
                if image.imageTag is None:
                    images.append(image.imageDigest)


        addImages = images

        # only add images for deletion that are actually in the repo

        for candImage in addImages:
            foundIt = False
            for image in self.repo.imageIds: 
                if image.imageDigest is not None and image.imageDigest == candImage:
                    self.imageDigests.append(candImage)
                    foundIt = True
                    break
            if not foundIt:
                self.log.warning("Image digest({}), not found in repo({})".format(candImage, self.repoName))

    def deleteImages(self):
        self.imageIds = list()
        if (len(self.imageTags) > 0):
            for imageTag in self.imageTags:
                self.imageIds.append({ 'imageTag': imageTag })

        if (len(self.imageDigests) > 0):
            for imageDigest in self.imageDigests:
                self.imageIds.append({ 'imageDigest': imageDigest })
        
        if (len(self.imageIds) == 0):
            self.log.error("You must supply at least one image to delete")
            return
            
        response = self.adc.ecr.batch_delete_image(repositoryName=self.repoName,
                                                   imageIds = self.imageIds)
        if 'failures' in response:
            failures = fl.fluentWrap(response['failures'])
        else:
            failures = fl.fluentWrap()

        if 'imageIds' in response:
            success = fl.fluentWrap(response['imageIds'])
        else:
            success = fl.fluentWrap()

        for good in success:
            if good.checkPath('imageTag'):
                imageid = good.imageTag
            else:
                imageid = good.imageDigest
            self.log.info("Deleted image({})".format(imageid))

        for bad in failures:
            if bad.checkPath('imageTag'):
                imageid = bad.ImageTag
            else:
                imageid = bad.ImageDigest
            self.log.error("Failed to delete image({}), code({}), reason({})".format(imageid, 
                                                                                     bad.failureCode,
                                                                                     bad.failureReason))


class rdsController(genController):

# Rds Status strings
# ------------------
# available
# backing-up
# backtracking
# configuring-enhanced-monitoring
# configuring-iam-database-auth
# configuring-log-exports
# converting-to-vpc
# creating
# deleting
# failed
# inaccessible-encryption-credentials
# incompatible-network
# incompatible-option-group
# incompatible-parameters
# incompatible-restore
# maintenance
# modifying
# moving-to-vpc
# rebooting
# renaming
# resetting-master-credentials
# restore-error
# starting
# stopped
# stopping
# storage-full
# storage-optimization
# upgrading

    def __init__(self, norep=False, **kwargs):
        super().__init__(**kwargs)
        self.norep = norep


    def isReplica(self, db):
        return db.checkPath("ReadReplicaSourceDBInstanceIdentifier")

    def stop(self, wait=False):
        """Stop all rds instances defined by passed controller"""
        db = fl.fluentWrap()
        for inst in self.adc.db:
            if (inst.DBInstanceStatus != "available"):
                self.log.info("Cannot stop {}, as status is \"{}\"".format(
                                                                       inst.DBInstanceIdentifier,
                                                                       inst.DBInstanceStatus
                                                                       ))
                continue
            if (self.isReplica(inst)):
                self.log.info("Ignoring {}, as it is a replica".format(
                                                                       inst.DBInstanceIdentifier,
                                                                       ))
                continue
            db.append(inst)
            self.log.info("Stopping {}".format(inst.DBInstanceIdentifier))
            response = self.adc.rds.stop_db_instance(DBInstanceIdentifier=inst.DBInstanceIdentifier)
        if (wait):
            self.adc.db = db
            self.waitFor("stopped")
            #self.waitStop()

    def waitFor(self, status):
        startTime = datetime.datetime.now()
        self.log.info("Waiting for RDS instances to transition to state: {}".format(status))

        watch_adc = self.adc
        elapsed = (datetime.datetime.now() - startTime).total_seconds() 

        while(elapsed < self.timeout):

            om = outputManager(watch_adc, log=self.log)
            om.displayRDS(noRep=self.norep)

            time.sleep(self.loopTime)

            watch_adc = awsDataCollector.awsDataCollector(session=adc.session, log=adc.log)
            watch_adc.setFilter(adc.filter)
            watch_adc.getRDSinstances()

            count = 0 
            match_count = 0
            for inst in watch_adc.db:
                if self.norep and self.isReplica(watch_adc.db):
                    continue
                count += 1
                if (str(inst.DBInstanceStatus).lower() != str(status).lower()):
                    continue
                match_count += 1

            if match_count == count:
                self.log.info("Complete - all RDS instances are in state: {}".format(status))
                return True




            elapsed = (datetime.datetime.now() - startTime).total_seconds() 
            remaining = max(self.timeout - elapsed, 0)
            (junk1, junk2, eM, eS) = om.toDHMS(elapsed)
            (junk3, junk4, rM, rS) = om.toDHMS(remaining)
            self.log.info("After {}:{:02d}s elapsed, ({}:{:02}s remaining)".format(eM, eS, rM, rS))
        self.log.error("Timeout exceeded before all RDS instances transistioned to state: {}".format(status))
        return False 

    def start(self, wait=False):
        """Start all rds instances defined by passed controller"""
        db = fl.fluentWrap()
        for inst in self.adc.db:
            if (inst.DBInstanceStatus != "stopped"):
                self.log.info("Cannot start {}, as status is \"{}\"".format(
                                                                       inst.DBInstanceIdentifier,
                                                                       inst.DBInstanceStatus
                                                                       ))
                continue
            db.append(inst)
            self.log.info("Starting {}".format(inst.DBInstanceIdentifier))
            response = self.adc.rds.start_db_instance(DBInstanceIdentifier=inst.DBInstanceIdentifier)
        if (wait):
            self.adc.db = db
            self.waitFor('available')
            #self.waitStart()

    def waitStart(self):

        startTime = datetime.datetime.now()
        self.log.info("Waiting for RDS instances to start")

        watch_adc = self.adc
        elapsed = (datetime.datetime.now() - startTime).total_seconds() 

        while(elapsed < self.timeout):
            om = outputManager(watch_adc, log=self.log)
            om.displayRDS()

            time.sleep(self.loopTime)

            watch_adc = awsDataCollector.awsDataCollector(session=adc.session, log=adc.log)
            watch_adc.setFilter(adc.filter)
            watch_adc.getRDSinstances()

            count = 0 
            available_count = 0
            for inst in watch_adc.db:
                count += 1
                if (inst.DBInstanceStatus != "available"):
                    continue
                available_count += 1

            if available_count == count:
                self.log.info("Complete - all RDS instances are available")
                return True

            elapsed = (datetime.datetime.now() - startTime).total_seconds() 
            remaining = max(self.timeout - elapsed, 0)
            (junk1, junk2, eM, eS) = om.toDHMS(elapsed)
            (junk3, junk4, rM, rS) = om.toDHMS(remaining)
            self.log.info("After {}:{:02d}s elapsed, ({}:{:02}s remaining)".format(eM, eS, rM, rS))
        self.log.error("Timeout exceeded before all RDS instances are available")
        return False 

    def waitStop(self):

        startTime = datetime.datetime.now()
        self.log.info("Waiting for RDS instances to stop")

        watch_adc = self.adc
        elapsed = (datetime.datetime.now() - startTime).total_seconds() 

        while(elapsed < self.timeout):
            om = outputManager(watch_adc, log=self.log)
            om.displayRDS()

            time.sleep(self.loopTime)

            watch_adc = awsDataCollector.awsDataCollector(session=adc.session, log=adc.log)
            watch_adc.setFilter(adc.filter)
            watch_adc.getRDSinstances()

            count = 0 
            stopped_count = 0
            for inst in watch_adc.db:
                count += 1
                if (inst.DBInstanceStatus != "stopped"):
                    continue
                stopped_count += 1

            if stopped_count == count:
                self.log.info("Complete - all RDS instances are stopped")
                return True

            elapsed = (datetime.datetime.now() - startTime).total_seconds() 
            remaining = max(self.timeout - elapsed, 0)
            (junk1, junk2, eM, eS) = om.toDHMS(elapsed)
            (junk3, junk4, rM, rS) = om.toDHMS(remaining)
            self.log.info("After {}:{:02d}s elapsed, ({}:{:02}s remaining)".format(eM, eS, rM, rS))
        self.log.error("Timeout exceeded before all RDS instances could be stopped")
        return False 


class asgController(genController):
    """A class that uses the aws Data Collector to control ASGs"""

    def startAll(self, wait):
        asgnames = list()
        for asg in self.adc.deployAsgs:
            self.start(asg)
            asgnames.append(asg.name)
        if wait:
            return self.waitStart(asgnames)
        return True

    def suspendAll(self, wait=False):
        asgnames = list()
        for asg in self.adc.deployAsgs:
            self.suspend(asg)
            asgnames.append(asg.name)
        if wait:
            return(self.waitTerminate(asgnames))
        return True

    def terminateAll(self, wait=False):
        asgnames = list()
        for asg in self.adc.deployAsgs:
            self.terminateAsgInstances(asg)
            asgnames.append(asg.name)
        if wait:
            return(self.waitTerminate(asgnames))

    def waitStart(self, theseAsgNames):
        self.instByAsg = self.__collectInstanceData(self.adc, theseAsgNames)
        startTime = datetime.datetime.now()

        self.log.info("Waiting for ASG Instances to start")

        watch_adc = self.adc
        instByAsg = self.instByAsg

        elapsed = (datetime.datetime.now() - startTime).total_seconds() 
        while(elapsed < self.timeout):
            om = outputManager(watch_adc, log=self.log)
            om.displayAsgs(Instances=True, asgnames=theseAsgNames)

            time.sleep(self.loopTime)

            watch_adc = awsDataCollector.awsDataCollector(session=adc.session, log=adc.log)
            watch_adc.setFilter(adc.filter)
            watch_adc.collectInstanceData()
            watch_adc.collectAsgData()
            instByAsg = self.__collectInstanceData(watch_adc, theseAsgNames)

            toremove = list()
            for asgname in instByAsg:
                if len(instByAsg[asgname]) > 0 :
                    toremove.append(asgname)

            for asgname in toremove:
                instByAsg.pop(asgname, None)

            if (len(instByAsg.keys()) == 0):
                self.log.info("Complete - all ASGs have at least one instance")
                return True

            elapsed = (datetime.datetime.now() - startTime).total_seconds() 
            remaining = max(self.timeout - elapsed, 0)
            (junk1, junk2, eM, eS) = om.toDHMS(elapsed)
            (junk3, junk4, rM, rS) = om.toDHMS(remaining)
            self.log.info("After {}:{:02d}s elapsed, ({}:{:02}s remaining)".format(eM, eS, rM, rS))
        self.log.error("Timeout exceeded before all ASGs have running instances")
        return False 

    def waitTerminate(self, theseAsgNames):
        # remember the running instances
        self.instByAsg = self.__collectInstanceData(self.adc, theseAsgNames)
        if len(self.instByAsg) == 0:
            self.log.error("No ASGs found")
            return True

        startTime = datetime.datetime.now()

        self.log.info("Waiting for ASG Instances to terminate")

        watch_adc = self.adc
        instByAsg = self.instByAsg

        # now loop, display, wait, collect and test
        elapsed = (datetime.datetime.now() - startTime).total_seconds() 
        while(elapsed < self.timeout):
            om = outputManager(watch_adc, log=self.log)
            om.displayAsgs(Instances=True, asgnames=self.instByAsg.keys())

            time.sleep(self.loopTime)

            watch_adc = awsDataCollector.awsDataCollector(session=adc.session, log=adc.log)
            watch_adc.setFilter(adc.filter)
            watch_adc.collectInstanceData()
            watch_adc.collectAsgData()
            instByAsg = self.__collectInstanceData(watch_adc, theseAsgNames)
            self.__removeInstances(self.instByAsg, instByAsg)

            if (len(self.instByAsg.keys()) == 0):
                self.log.info("Complete - all original instances have terminated")
                return True

            elapsed = (datetime.datetime.now() - startTime).total_seconds() 
            remaining = max(self.timeout - elapsed, 0)
            (junk1, junk2, eM, eS) = om.toDHMS(elapsed)
            (junk3, junk4, rM, rS) = om.toDHMS(remaining)
            self.log.info("After {}:{:02d}s elapsed, ({}:{:02}s remaining)".format(eM, eS, rM, rS))

        self.log.error("Timeout exceeded before all instances terminated")
        return False 

    def __removeInstances(self, first, second):
        size = dict()
        for asgname in first:
            if asgname not in second:
                first.pop(asgname, None)
                continue
            toremove = list()
            for instanceId in first[asgname]:
                if instanceId not in second[asgname]:
                    toremove.append(instanceId)

            for instanceId in toremove:
                first[asgname].remove(instanceId)

            size[asgname] = len(first[asgname])

        # remove empty asgnames

        for asgname in size:
            if size[asgname] == 0:
                first.pop(asgname, None)


    def __collectInstanceData(self, adc, theseAsgNames):
        instByAsg=dict()
        for asg in adc.deployAsgs:
            instByAsg = dict()
            for asg in adc.deployAsgs:
                if asg.name not in theseAsgNames:
                    continue
                if asg.name not in instByAsg:
                    instByAsg[asg.name] = list()
                for instance in asg.Instances:
                    instByAsg[asg.name].append(instance.InstanceId)
        return instByAsg

    def suspend(self, candAsg):
        """Suspend the passed asg, either by name or object"""

        if (isinstance(candAsg, str)):
            asg = self.adc.getAsgByName(candAsg)
        elif(isinstance(candAsg, fl.fluentWrap)):
            asg = candAsg
        else:
            self.log.error("Asg({}) is unknown".format(type(candAsg)))
            return

        if not self.adc.isAsgSuspended(asg):
            self.__suspend(asg)
        else:
            self.log.warning("ASG '{}' is already suspended, checking instances".format(asg.name))
            self.terminateAsgInstances(asg)
            
    def __suspend(self, asg):
        """Suspend the asg represented by the passed asg object"""
        self.log.info("Suspending Processes in {}".format(asg.name))
        self.adc.asg.suspend_processes(AutoScalingGroupName=asg.AutoScalingGroupName)
        self.terminateAsgInstances(asg)

    def terminateAsgInstances(self, asg):
        """Terminate the instances in the supplied asg"""
        self.log.info("Terminating Instances in {}".format(asg.name))
        for instance in asg.Instances:
            self.log.info("Terminating {} ({})".format(self.adc.ec2hostsById[instance.InstanceId].name,
                                                       instance.InstanceId))
            try:
                self.adc.asg.terminate_instance_in_auto_scaling_group(
                    InstanceId=instance.InstanceId,
                    ShouldDecrementDesiredCapacity=False
                 )
            except ClientError as exc:
                self.log.warning("Got client error({})".format(exc))
                canSafelyIgnore(exc)
    
    def start(self, candAsg):
        """Bring processes out of suspension for the passed asg object"""

        if (isinstance(candAsg, str)):
            asg = self.adc.getAsgByName(candAsg)
        elif(isinstance(candAsg, fl.fluentWrap)):
            asg = candAsg
        else:
            self.log.error("Asg({}) is unknown".format(str(candAsg)))
            return

        if self.adc.isAsgSuspended(asg):
            print("{:<32}: ({:^32}) - Staring Processes".format(asg.name, asg.AutoScalingGroupName))
            self.adc.asg.resume_processes(AutoScalingGroupName=asg.AutoScalingGroupName)
        else:
            self.log.warning("ASG '{}' has already been started".format(asg.name))
            
class cacheClusterController(genController):
    """A class for controlling redis cache clusters"""

    def waitFor(self, state):
        self.log.info("Waiting for CacheClusters to enter state: {}".format(state))
        startTime = datetime.datetime.now()
        watch_adc = self.adc

        # now loop, display, wait, collect and test
        elapsed = (datetime.datetime.now() - startTime).total_seconds() 
        while(elapsed < self.timeout):
            om = outputManager(watch_adc, log=self.log)
            om.displayCacheClusters(raw=False)

            time.sleep(self.loopTime)

            watch_adc = awsDataCollector.awsDataCollector(session=adc.session, log=adc.log)
            watch_adc.setFilter(adc.filter)
            watch_adc.getCacheClusters()

            # test

            count=0
            state_count=0
            for cc in watch_adc.cacheClusters:
                count += 1
                if (str(cc.CacheClusterStatus).lower() == str(state).lower()):
                    state_count +=1

            if (state_count == count):
                self.log.info("Complete all clusters are now in state: {}".format(state))
                return True

            elapsed = (datetime.datetime.now() - startTime).total_seconds() 
            remaining = max(self.timeout - elapsed, 0)
            (junk1, junk2, eM, eS) = om.toDHMS(elapsed)
            (junk3, junk4, rM, rS) = om.toDHMS(remaining)
            self.log.info("After {}:{:02d}s elapsed, ({}:{:02}s remaining)".format(eM, eS, rM, rS))

        self.log.error("Timeout exceeded before all clusters entered state: {}".format(state))
        return False 


class sgController():
    """A class for controlling Security Groups"""

    def __init__(self, dataCollector=None, log=None):
        self.adc = dataCollector
        self.log = log

    def deleteSG(self, sgNames):

        for sgName in sgNames:
            sg = self.adc.getSgByName(sgName)
            if sg is None:
                self.log.error("No such security group ({})".format(sgName))
                return
            try:
                self.adc.ec2Client.delete_security_group(GroupId=sg.GroupId)
                self.log.info("Deleted security group({})".format(sgName))
            except ClientError as exc:
                self.log.error("Security group({}) not deleted, error: {}".format(sgName, exc))


    def deleteSgRule(self, sgName, entrySpec):
        """Deletes the specfied rule from the specified security group"""

        sg = self.adc.getSgByName(sgName)
        
        if sg is None:
            self.log.error("Security group ({}) is does not exist".format(sgName))
            return

        # make sure the spec definition is correct

        result = re.match("^(ingress|egress):(\d+),(\d+)", entrySpec, re.IGNORECASE)
        if not result:
            self.log.error("Invalid delete entry format ({})".format(entrySpec))
            return

        # a is the rule group, and b the rule number

        direction = result[1].lower()
        a = int(result[2])
        b = int(result[3])

        if direction == 'ingress':
            ipPerms = sg.IpPermissions
            client = self.adc.ec2Client.revoke_security_group_ingress
        else:
            ipPerms = sg.IpPermissionsEgress
            client = self.adc.ec2Client.revoke_security_group_egress
        
        # get ready to search for the rule

        permCount = 0
        itemPerm = None
        itemUIDpair = None
        itemIpRange = None

        messagePorts = ""
        messageDeatil = ""

        # search for the rule

        for perm in ipPerms:
            permCount += 1
            if (a == permCount):
                itemPerm = perm
                messagePorts = "[{}] From: {} -> {} ({})".format( permCount,
                                                    perm.FromPort,
                                                    perm.ToPort,
                                                    perm.IpProtocol)
                desc = ""
                itemCount = 0
                for iprange in perm.IpRanges:
                    itemCount += 1
                    if ( b == itemCount ):
                        itemIpRange = iprange
                        messageDetail = "[{}] {} {}".format( itemCount, iprange.CidrIp, desc)


                for udip in perm.UserIdGroupPairs:
                    itemCount += 1
                    if ( b == itemCount ):
                        itemUIDpair = udip
                        if udip.GroupId in self.adc.sgsByGroupId:
                            name = self.adc.sgsByGroupId[udip.GroupId].GroupName
                        else:
                            name = "Unknown"

                        messageDetail="[{}] {} ({})".format( itemCount, name, udip.GroupId)

        if (itemPerm is not None):
            print("Deleting")
            print(messagePorts)
            print(messageDetail)
            if (itemIpRange is not None):
                if itemPerm.FromPort is None and itemPerm.ToPort is None:
                    ipperms = IpPermissions = [ { 'IpProtocol': itemPerm.IpProtocol,
                                            'IpRanges': [ {
                                                'CidrIp': itemIpRange.CidrIp
                                                }]
                                            }]
                else:
                       ipperms = [ { 'FromPort': itemPerm.FromPort,
                                            'ToPort': itemPerm.ToPort,
                                                'IpProtocol': itemPerm.IpProtocol,
                                            'IpRanges': [ {
                                                'CidrIp': itemIpRange.CidrIp
                                                }]
                                            }]

                client(GroupId=sg.GroupId, IpPermissions = ipperms )
            if (itemUIDpair is not None):
                client(GroupId=sg.GroupId,
                       IpPermissions = [ { 'FromPort': itemPerm.FromPort,
                                            'ToPort': itemPerm.ToPort,
                                            'IpProtocol': itemPerm.IpProtocol,
                                            'UserIdGroupPairs': [{ 
                                                'GroupId': itemUIDpair.GroupId
                                                }]
                                            }])

global_options = [
    click.option('--filter', required=True, type=click.STRING, help="Filter on artefact names")
]

global_optional_options = [
    click.option('--filter', required=False, type=click.STRING, help="Filter on artefact names"),
]
terse_options = [
    click.option('--terse', is_flag=True, default=False, help="Terse minimal ouput for easy scripting"),
]

waitTimeOut_options = [
        click.option('--timeout', required=False, default=600, help="Set total wait timeout in seconds, default 600s"),
        click.option('--looptime', required=False, default=5,  help="Set loop wait time in seconds, default=5s")
]

@click.command(name='config', short_help='experimental')
def config():
    """Just load the config file, to check all is well"""
    em = __setup()
    em.loadConfig()

show_options = [
    click.option('--writessh', is_flag=True, default=False, help="Do the writeSsh action also"),
    click.option('--listContainers', is_flag=True, default=False, help="List container status on each host"),
    click.option('--contDetail', is_flag=True, default=False, help="List container detail"),
    click.option('--sg', is_flag=True, default=False, help="List Security Group Information"),
    click.option('--writeconfig', is_flag=True, default=False, hidden=True, help="Write out internal instance state"),
    click.option('--rdns', is_flag=True, default=False, help="Lookup up rdns values in hosted zones"),
    click.option('--price', is_flag=True, default=False, help="Estimate total price for instance"),
    click.option('--details', is_flag=True, default=False, help="Provide more instance details")
]

@click.command(name='showEC2', short_help='Display data about ec2 instances')
@add_options(global_options)
@add_options(show_options)
def showEC2(filter, details, price, rdns, writeconfig, sg, contdetail, listcontainers, writessh):
    """Display details about EC2 instances from the selected build env"""
    global om, adc
    adc.setFilter(filter)
    #adc.getInstanceData()

    if contdetail:
        listcontainers = True

    adc.collectInstanceData(collectRdns=rdns, getPrice=price)

    if (writeconfig):
        adc.writeInternalConfig()

    om = outputManager(dataCollector=adc, log=logger)
    om.displayInstances(writessh=writessh,
                        listContainers=listcontainers,
                        contDetail=contdetail,
                        showSG=sg,
                        rDNS=rdns,
                        price=price,
                        details=details)

showVol_options = [
    click.option('--attach', required=False, is_flag=True, default=False, help="Show volume attachment details"),
    ]

@click.command(name="showVol", short_help='Volume explorer')
@add_options(showVol_options)
def showVol(attach):
    global adc, session
    adc.getVolumes()
    om = outputManager(adc, log=logger)
    om.displayVols(attach=attach)


@click.command(name="showSnapshot", short_help='Snapshot explorer')
def showSnapshot():
    global adc, session
    adc.getSnapshots()
    om = outputManager(adc, log=logger)
    om.displaySnaps()

asg_options = [
    click.argument('asgnames', type=click.STRING, nargs=-1),
    click.option('--lc', is_flag=True, default=False, help="Display Launch Configuration Data"),
    click.option('--instance', is_flag=True, default=False, help="Display ASG instances"),
    click.option('--param_path', required=False, type=click.STRING, help="Perform action on environment names below the provided parameter store path")
]


parsed_filter = list()
def param_parser(path, value):
    """Extracts the basename from path and puts the value in parsed_filter"""
    # just extract the environment from the basename of the path
    parsed_filter.append(os.path.basename(path))

@click.command(name='showASG', short_help='Display data about ASGs')
@add_options(asg_options)
@add_options(global_optional_options)
@add_options(terse_options)
def showASG(terse, filter, param_path, instance, lc, asgnames):
    """Display details about autoscaling groups from the selected build env"""
    global adc, session

    if filter is None and param_path is None:
        logger.error("You must provide either --filter or --param_path")
        return False

    if param_path is not None and len(asgnames) > 0:
        logger.warning("--param_path causes all ASGs to be displayed")
        asgnames = list()

    if param_path is not None:
        params = spm.ssmParameterManager(log=logger, session=session)
        params.getParameters(param_path, callBack=param_parser)
    else:
        parsed_filter.append(filter)

    for this_filter in parsed_filter:
        if not terse:
            logger.info("---show:{}---".format(this_filter))
        adc = awsDataCollector.awsDataCollector(session=session, log=logger)
        adc.setFilter(this_filter)
        adc.collectInstanceData()
        adc.collectAsgData()
        om = outputManager(adc, log=logger)
        om.setTerse(terse)
        om.displayAsgs(LaunchConfig=lc,
                       Instances=instance,
                       asgnames=asgnames)

suspendASG_options = [
    click.argument('asgNames', type=click.STRING, nargs=-1),
    click.option('--all', required=False, is_flag=True, help="Operate on all ASGs in the filter"),
    click.option('--param_path', required=False, type=click.STRING, help="Perform action on environment names below the provided parameter store path"),
    click.option('--wait', required=False, is_flag=True, help="Wait for the suspend to complete")
]
@click.command(name='suspendASG', short_help='Suspend a running ASG')
@add_options(suspendASG_options)
@add_options(global_optional_options)
def suspendASG(filter, wait, param_path, all, asgnames):
    """ Suspend and terminate the supplied asg names """
    global adc, session

    if filter is None and param_path is None:
        logger.error("You must provide either --filter or --param_path")
        return False

    if param_path is not None and len(asgnames) > 0:
        logger.error("--param_path operates on all ASGs in the environment, you cannot pass asgnames")
        return False

    if param_path is not None:
        all = True
        params = spm.ssmParameterManager(log=logger, session=session)
        params.getParameters(param_path, callBack=param_parser)
    else:
        parsed_filter.append(filter)

    if not all and len(asgnames) == 0:
        logger.error("You must provide at least one asg name to suspend")
        return

    for this_filter in parsed_filter:
        logger.info("---suspend:{}---".format(this_filter))
        adc = awsDataCollector.awsDataCollector(session=session, log=logger)
        adc.setFilter(this_filter)
        adc.collectInstanceData()
        adc.collectAsgData()
    
        asgc = asgController(dataCollector=adc, log=logger)

        if all: 
            if ( asgc.suspendAll(wait)):
                sys.exit(0)
            else:
                sys.exit(1)
        else:
            for asgname in asgnames:
                asgc.suspend(asgname)
            if wait:
                if asgc.waitTerminate(asgnames):
                    sys.exit(0)
                else:
                    sys.exit(1)

@click.command(name='startASG', short_help='Start a suspended ASG')
@add_options(suspendASG_options)
@add_options(global_optional_options)
def startASG(filter, wait, param_path, all, asgnames):
    """ Start the supplied suspended asg names """
    global adc, session

    if filter is None and param_path is None:
        logger.error("You must provide either --filter or --param_path")
        return False

    if param_path is not None and len(asgnames) > 0:
        logger.error("--param_path operates on all ASGs in the environment, you cannot pass asgnames")
        return False

    if param_path is not None:
        all = True
        params = spm.ssmParameterManager(log=logger, session=session)
        params.getParameters(param_path, callBack=param_parser)
    else:
        parsed_filter.append(filter)

    if not all and len(asgnames) == 0:
        logger.error("You must provide at least one asg name to start")
        return

    for this_filter in parsed_filter:
        logger.info("---start:{}---".format(this_filter))
        adc = awsDataCollector.awsDataCollector(session=session, log=logger)
        adc.setFilter(this_filter)
        adc.collectInstanceData()
        adc.collectAsgData()
    
        asgc = asgController(dataCollector=adc, log=logger)

        if all: 
            if asgc.startAll(wait):
                sys.exit(0)
            else:
                sys.exit(1)
        else:
            for asgname in asgnames:
                asgc.start(asgname)
            if wait:
                if asgc.waitStart(asgnames):
                    sys.exit(0)
                else:
                    sys.exit(1)

@click.command(name='terminateASGinstances', short_help='Terminate instances in ASGs')
@add_options(suspendASG_options)
@add_options(global_optional_options)
def terminateASGinstances(filter, wait, param_path, all, asgnames):
    """Terminate the instances in the defined asg"""
    global adc, session

    if filter is None and param_path is None:
        logger.error("You must provide either --filter or --param_path")
        return False

    if param_path is not None and len(asgnames) > 0:
        logger.error("--param_path operates on all ASGs in the environment, you cannot pass asgnames")
        return False

    if param_path is not None:
        all = True
        params = spm.ssmParameterManager(log=logger, session=session)
        params.getParameters(param_path, callBack=param_parser)
    else:
        parsed_filter.append(filter)

    if not all and len(asgnames) == 0:
        logger.error("You must provide at least one asg name")
        return

    for this_filter in parsed_filter:
        logger.info("---terminate instances:{}---".format(this_filter))
        adc = awsDataCollector.awsDataCollector(session=session, log=logger)
        adc.setFilter(this_filter)
        adc.collectInstanceData()
        adc.collectAsgData()
    
        asgc = asgController(dataCollector=adc, log=logger)

        if all: 
            asgc.terminateAll(wait)
        else:
            for asgname in asgnames:
                asg = adc.getAsgByName(asgname)
                if asg is not None:
                    asgc.terminateAsgInstances(asg)
            if wait:
                asgc.waitTerminate(asgnames)

@click.command(name='writeSsh', short_help='Write a ssh file for access to instances on the estate')
@add_options(global_options)
def writeSsh(filter):
    """Write a ssh config file capable of connecting to detected EC2 instances by name"""
    global adc 
    adc.setFilter(filter)
    adc.collectInstanceData()
    adc.loadConfig()
    om = outputManager(adc)
    om.writeSSHconfig()

buildCon_options = [
    click.option('--testHost', required=False, type=click.STRING, help="Test connection to this host")
]
@click.command(name='buildCon', short_help='build fabric connections to the running hosts')
@add_options(buildCon_options)
@add_options(global_options)
def buildCon(filter, testhost):
    """Load the config file and build the connections, then check connecting to the testHost if defined """
    global adc
    adc.setFilter(filter)
    adc.collectInstanceData()
    adc.loadConfig()
    adc.buildConnections(debug=True)
    if ( testhost is not None):
        found = False
        for host in adc.getHosts(running=True):
            if host.name == testhost:
                found = True
                try:
                    adc.log.info("Listing containers on host({})".format(testhost))
                    adc.listContainers(host.connection)
                except IndexError:
                    adc.log.error("No connection created for host {}",format(testhost))
                break
        if not found:
            adc.log.error("Host {} is not known".format(testhost))

@click.command(name='showInstanceIds', short_help='Just get the instance ids from the specified filter')
@add_options(global_options)
def showInstanceIds(filter):
    global adc
    adc.setFilter(filter)
    adc.collectInstanceData()
    om = outputManager(adc, log=logger)
    om.printInstanceIds()

@click.command(name='showHostedZones', short_help='List the hosted zones configured in the environment')
def showHostedZones():
    global adc 
    adc.getHostedZones()
    om = outputManager(adc, log=logger)
    om.displayHostedZones()

showLB_options = [
    click.option('--sg', required=False, is_flag=True, default=False, help="Display LB security groups"),
    click.option('--tg', required=False, is_flag=True, default=False, help="Display LB target groups"),
]
@click.command(name='showLB', short_help='Show the load balancers configured in the environment')
@add_options(showLB_options)
@add_options(global_optional_options)
def showLB(filter, tg, sg):
    global adc 

    if (filter is not None):
        adc.setFilter(filter)

    adc.getLoadBalancers()
    if tg:
        adc.getTargetGroups()

    if sg:
        adc.getSecurityGroups()

    om = outputManager(adc, log=logger)
    om.displayLoadBalancers(sg, tg)

    #print(adc.tgs.prettyString())

showVPCs_options = [
    click.option('--HostedZones', required=False, is_flag=True, default=False, help="List Hosted Zone ids"),
    click.option('--Subnets', required=False, is_flag=True, default=False, help="Get subnet information for each vpc"),
    click.option('--natGWs', required=False, is_flag=True, default=False, help="Get NAT GW information for each subnet"),
    click.option('--All', required=False, is_flag=True, default=False, help="Get hostedzones, subnets and NAT gateways ")
    ]
@click.command(name='showVPC', short_help='Show the VPCs')
@add_options(showVPCs_options)
def showVPC(all, natgws, subnets, hostedzones):
    global adc 
    if all:
        natgws = True
        subnets = True
        hostedzones = True
    adc.getVPCs(getSubnets=subnets, getNATGWs=natgws, getHostedZones=hostedzones)
    om = outputManager(adc)
    om.displayVPCs()

showSG_options = [
    click.argument('securitygroups', type=click.STRING, nargs=-1),
    click.option('--delete', required=False, is_flag=True, default=False, help="Delete the specfified security groups"),
    click.option('--deleteEntry', required=False, type=click.STRING, help="Delete the specfified security group entry in the form "
                                                                          "ingress:a,b or egress:a,b where a,b are then numbers from "
                                                                          "the showSG output"),
]

@click.command(name='showSG', short_help='list security groups')
@add_options(showSG_options)
@add_options(global_options)
def showSG(filter, deleteentry, delete, securitygroups):
    global adc
    adc.setFilter(filter)
    adc.getSecurityGroups()
    if delete:
        if (deleteentry is not None):
            logger.error("You cannot use --delete and --deleteEntry together")
            return
        sgc = sgController(adc, log=logger)
        sgc.deleteSG(securitygroups)
        return
    if deleteentry:
        if len(securitygroups) != 1:
            logger.error("You must supply one and only one security group name from which to delete an entry")
            return
        sgc = sgController(adc, log=logger)
        sgc.deleteSgRule(securitygroups[0], deleteentry)
        return
    om = outputManager(adc, log=logger)
    om.displaySecurityGroups(securitygroups)

showRR_options = [
    click.argument('hostedzones', type=click.STRING, nargs=-1),
    click.option('--re', required=False, type=click.STRING, default=None, help="Select values matching RE"),
    click.option('--type', required=False, type=click.STRING, default=None, help="Only show records of the indicated type"),
]
@click.command(name='showRR', short_help='List resource records')
@add_options(showRR_options)
def showRR(type, re, hostedzones):
    global adc 
    if len(hostedzones) == 0:
        logger.error("You must provide at least one hosted zone id, use showHostedZones")
        return 1

    om = outputManager(adc, log=logger)
    for hostzoneid in hostedzones:
        adc.getRecordSets(hostzoneid)
        om.displayRecordSets(hostzoneid, re, type)

showECR_options = [
    click.argument('reponames', type=click.STRING, nargs=-1),
    click.option('--images', required=False, is_flag=True, default=False, help="Show image data for each repo selected"),
    click.option('--untagged', required=False, is_flag=True, default=False, help="Show untagged images"),
    ] 

@click.command(name='showECR', short_help='List ECR repositories')
@add_options(showECR_options)
def showECR(untagged, images, reponames):
    global adc
    adc.getECRrepos(reponames, images)
    om=outputManager(adc, log=logger)
    om.displayRepos(tagged=True, untagged=untagged)

deleteECRImages_options = [
    click.argument('images', type=click.STRING, nargs=-1),
    click.option('--repoName', type=click.STRING, required=True, help="reponame from which to delete"),
    click.option('--imageTags', required=False, default=False, is_flag=True, help="Image tags to delete"),
    click.option('--imageDigests', required=False, default=False, is_flag=True, help="Image Digests to delete"),
    click.option('--untagged', required=False, default=False, is_flag=True, help="delete all untagged images"),
    ] 
@click.command(name='deleteECRImages', short_help='Delete images from ECR repositories')
@add_options(deleteECRImages_options)
def deleteECRImages(untagged, imagedigests, imagetags, reponame, images):
    """Supply a list of imagestags or imagedigests to delete from the specified ECR repo"""
    global adc
    if untagged and imagedigests is False:
        logger.error("You must supply --imagedigests with --untagged")
        return False
    if imagedigests is None and imagetags is None:
        logger.error("You must supply --imageTags or --imageDigests")
        return False
    if (untagged and len(images)>0):
        logger.error("You must not supply specific image digests when using --untagged")
        return False
    adc.getECRrepos([reponame], True)
    #om=outputManager(adc, log=logger)
    #om.displayRepos()
    ecrc = ecrController(dataCollector=adc, log=logger, repoName=reponame)
    if (imagetags):
        ecrc.addTags(images)
    if (imagedigests):
        ecrc.addDigests(images, untagged=untagged)
    ecrc.deleteImages()

showRedis_options = [
    click.option('--clusters', required=False, is_flag=True, default=False, help="Show clusters"),
    click.option('--replgroups', required=False, is_flag=True, default=False, help="Show replication groups"),
    click.option('--raw', required=False, is_flag=True, default=False, help="Show raw output"),
    click.option('--wait', required=False, default='', type=click.STRING, help="Wait for the indicated state"),
        ]

@click.command(name='showRedis', short_help='List redis replication groups')
@add_options(waitTimeOut_options)
@add_options(showRedis_options)
@add_options(global_optional_options)
@add_options(terse_options)
def showRedis(terse, filter, wait, raw, replgroups, clusters, looptime, timeout):
    global adc
    if not clusters and not replgroups:
        logger.error("You must provide at least one of --clusters or --replgroups")
        return
    adc.setFilter(filter)
    om=outputManager(adc, log=logger)
    om.setTerse(terse)

    if replgroups:
        adc.getRedisReplGroups()
        om.displayReplGroups(raw)
    if clusters:
        adc.getCacheClusters()
        if (len(wait) > 0):
            ccc = cacheClusterController(dataCollector=adc, log=logger, timeOut=timeout, loopTime=looptime)
            if (ccc.waitFor(wait)):
                return 0
            else:
                return 1
        else:
            om.displayCacheClusters(raw)


showAMI_options = [
    click.argument('amifilter', required=False, type=click.STRING, nargs=-1),
    click.option('--desc', required=False, is_flag=True, default=False, help="Show description and full name of AMI"),
    ]
@click.command(name="showAMI", short_help='List AMIs')
@add_options(showAMI_options)
def showAMI(desc, amifilter):
    global adc
    adc.getAMIData(amifilter)
    om=outputManager(adc, log=logger)
    om.displayAMI(desc)

@click.command(name="showSpotPrice", short_help='Get spot price history')
def showSpotPrice():
    global adc, session
    #adc.getSpotPrice()
    #adc.getServices()
    om=outputManager(adc, log=logger)
    om.displaySpot(session)

showRDS_options = [
    click.argument('rdsnames', type=click.STRING, nargs=-1),
    click.option('--details', required=False, is_flag=True, default=False, help="Show Engine and Master User"),
    click.option('--cost', required=False, is_flag=True, default=False, help="Show running total costs"),
    click.option('--raw', required=False, is_flag=True, default=False, help="Show raw fluentWrap structure"),
    click.option('--filter', required=False, default='', type=click.STRING, help="Filter on database name"),
    click.option('--wait', required=False, default='', type=click.STRING, help="Wait for the indicated state"),
    click.option('--norep', required=False, is_flag=True, default=False, help="Don't display read replicas"),
        ]
@click.command(name="showRDS", short_help='Get information about rds instances')
@add_options(waitTimeOut_options)
@add_options(showRDS_options)
@add_options(terse_options)
def showRDS(terse, norep, wait, filter, raw, cost, details, rdsnames, looptime, timeout):
    global adc
    adc.setFilter(filter)
    adc.getRDSinstances(cost=cost)

    if (len(wait) > 0):
        rdc = rdsController(dataCollector=adc, log=logger, timeOut=timeout, loopTime=looptime)
        rdc.norep = True
        sys.exit(0) if rdc.waitFor(wait) else sys.exit(1)
    else:
        om = outputManager(adc, log=logger)
        om.setTerse(terse)
        om.displayRDS(details=details, cost=cost, raw=raw, rdsNames=rdsnames, noRep=norep)


stopStartRDS_options = [
    click.argument('rdsnames', type=click.STRING, nargs=-1),
    click.option('--wait', required=False, is_flag=True, help="Wait for the action to complete"),
    click.option('--filter', required=False, default='', type=click.STRING, help="Filter on database name")
        ]
@click.command(name="stopRDS", short_help='Stop rds instances')
@add_options(waitTimeOut_options)
@add_options(stopStartRDS_options)
def stopRDS(filter, wait, rdsnames, looptime, timeout):
    global adc
    adc.setFilter(filter)
    adc.getRDSinstances()
    rdc = rdsController(dataCollector=adc, log=logger, timeOut=timeout, loopTime=looptime)
    if rdc.stop(wait):
        return 0
    else:
        return 1

@click.command(name="startRDS", short_help='Stop rds instances')
@add_options(waitTimeOut_options)
@add_options(stopStartRDS_options)
def startRDS(filter, wait, rdsnames, looptime, timeout):
    global adc
    adc.setFilter(filter)
    adc.getRDSinstances()
    rdc = rdsController(dataCollector=adc, log=logger, timeOut=timeout, loopTime=looptime)
    if rdc.start(wait):
        return 0
    else:
        return 1

showServices_options = [
    click.argument('servicecodes', type=click.STRING, nargs=-1),
    click.option('--details', required=False, is_flag=True, default=False, help="Show service attribute details"),
    click.option('--re', required=False, type=click.STRING, default=None, help="Select attribute values matching RE"),
    ]

@click.command(name="showServices", short_help='Get information about Amazon services')
@add_options(showServices_options)
def showServices(re, details, servicecodes):
    global adc
    adc.getServices(serviceCodes=servicecodes)
    om = outputManager(adc, log=logger)
    om.displayServices(details, re)

showPricing_options = [
    click.argument('attributeValuePair', type=click.STRING, nargs=-1),
    click.option('--serviceCode', required=True, type=click.STRING, help="ServiceCode to explore"),
    ]

@click.command(name="showPricing", short_help='Raw Pricing explorer')
@add_options(showPricing_options)
def showPricing(servicecode,attributevaluepair):
    global adc, session
    pricer = awsDataCollector.awsPrice(servicecode, session, logger)
    filters = dict()
    for pair in attributevaluepair:
        (f,v) = pair.split(':')
        filters[f] = v
    pricer.setFilter(filters)
    pricer.getPrices(noTreat=True)
    print(pricer.prices.prettyString(leader="."))


@click.group()
def cli():
    global dm, adc, session
    session = boto3.Session()
    adc = awsDataCollector.awsDataCollector(session=session, log=logger)


cli.add_command(writeSsh)
cli.add_command(config)
cli.add_command(showEC2)
cli.add_command(showASG)
cli.add_command(buildCon)
cli.add_command(showInstanceIds)
cli.add_command(showHostedZones)
cli.add_command(suspendASG)
cli.add_command(startASG)
cli.add_command(terminateASGinstances)
cli.add_command(showVPC)
cli.add_command(showLB)
cli.add_command(showSG)
cli.add_command(showRR)
cli.add_command(showECR)
cli.add_command(deleteECRImages)
cli.add_command(showAMI)
cli.add_command(showRedis)
cli.add_command(showSpotPrice)
cli.add_command(showRDS)
cli.add_command(stopRDS)
cli.add_command(startRDS)
cli.add_command(showServices)
cli.add_command(showPricing)
cli.add_command(showVol)
cli.add_command(showSnapshot)



if __name__ == '__main__':
    cli()

