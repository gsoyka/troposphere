# Copyright (c) 2012-2013, Mark Peek <mark@peek.org>
# All rights reserved.
#
# See LICENSE file for full license.

from . import AWSObject, AWSProperty, If, Tags
from .validators import (
    elb_name, exactly_one, network_port,
    tg_healthcheck_port, integer
)


class LoadBalancerAttributes(AWSProperty):
    props = {
        'Key': (basestring, False),
        'Value': (basestring, False)
    }


class Certificate(AWSProperty):
    props = {
        'CertificateArn': (basestring, False)
    }

class Action(AWSProperty):
    props = {
        'AuthenticateCognitoConfig': (AuthenticateCognitoActionConfig, False),
        'AuthenticateOidcConfig': (AuthenticateOidcActionConfig, False),
        'FixedResponseConfig': (FixedResponseActionConfig, False)
        'Order': (basestring, False),
        'RedirectConfig' (RedirectActionConfig, False),
        'TargetGroupArn': (basestring, False),
        'Type': (basestring, True)
    }

    def validate(self):
        valid_types = [
            'forward',
            'authenticate-oidc',
            'authenticate-cognito',
            'redirect',
            'fixed-response'
        ]
        if self.properties['Type'] not in valid_types:
            raise ValueError(
                "Type must be one of: %s"
                % ", ".join(valid_actions)
            )

        if (self.properties.get("Order") and
                self.properties["Order"] not in range(1, 50001):
            raise ValueError(
                "Order of length: %s is out of range 1-50000"
                % self.properties["Order"]
            )


class AuthenticateCognitoActionConfig(AWSProperty):
    props = {
        'AuthenticationRequestExtraParams': (basestring, False)
        'OnUnauthenticatedRequest': (basestring, False)
        'Scope': (basestring, False)
        'SessionCookieName': (basestring, False)
        'SessionTimeout': (integer, False)
        'UserPoolArn': (basestring, True)
        'UserPoolClientId': (basestring, True)
        'UserPoolDomain': (basestring, True)
    }

    def validate(self):
        valid_actions = ['deny', 'allow', 'authenticate']
        if (self.properties.get('OnUnauthenticatedRequest', None) and
            self.properties['OnUnauthenticatedRequest'] not in valid_actions):

            raise ValueError(
                "OnUnauthenticatedRequest must be one of: %s"
                % ", ".join(valid_actions)
            )


class AuthenticateOidcActionConfig(AWSProperty):
    props = {
        'AuthenticationRequestExtraParams': (basestring, False)
        'AuthorizationEndpoint': (basestring, True)
        'ClientId': (basestring, True)
        'ClientSecret': (basestring, True)
        'Issuer': (basestring, True)
        'OnUnauthenticatedRequest': (basestring, False)
        'Scope': (basestring, False)
        'SessionCookieName': (basestring, False)
        'SessionTimeout': (integer, False)
        'TokenEndpoint': (basestring, True)
        'UserInfoEndpoint': (basestring, True)
    }

    def validate(self):
        valid_actions = ['deny', 'allow', 'authenticate']
        if (self.properties.get('OnUnauthenticatedRequest', None) and
            self.properties['OnUnauthenticatedRequest'] not in valid_actions):

            raise ValueError(
                "OnUnauthenticatedRequest must be one of: %s"
                % ", ".join(valid_actions)
            )


class FixedResponseActionConfig(AWSProperty):
    props = {
        'ContentType': (basestring, False)
        'MessageBody': (basestring, True)
        'StatusCode': (basestring, True)
    }

    def validate(self):
        valid_types = [
            'text/plain',
            'text/css',
            'test/html',
            'application/javascript',
            'application/json'
        ]
        if (self.properties.get('ContentType', None) and
            self.properties['ContentType'] not in valid_types):

            raise ValueError(
                "ContentType must be one of: %s"
                % ", ".join(valid_actions)
            )

        if len(self.properties.get('MessageBody', "")) > 1024:
            raise ValueError(
                "MessageBody of length: %s is greater than maximum
                allowed length of 1024"
                % len(self.properties.get('MessageBody', ""))
            )


class RedirectActionConfig(AWSProperty):
    props = {
        'Host': (basestring, False)
        'Path': (basestring, False)
        'Port': (integer, False)
        'Protocol': (basestring, False)
        'Query': (basestring, False)
        'StatusCode': (basestring, True)
    }

    def validate(self):
        valid_codes = ['HTTP_301', 'HTTP_302']

        if (self.properties['StatusCode'] not in valid_codes):

            raise ValueError(
                "StatusCode must be one of: %s"
                % ", ".join(valid_codes)
            )

        for prop in ['Host', 'Path']:
            if len(self.properties.get(prop, "")) not in range(1, 129):
                raise ValueError(
                    "%s of length: %s is out of range 1-128"
                    % (prop, len(self.properties.get(prop, "")))

        if len(self.properties.get('Query', "")) > 128:
            raise ValueError(
                "Query of length: %s is greater than maximum
                allowed length of 128"
                % len(self.properties.get('Query', ""))
            )


class Condition(AWSProperty):
    props = {
        'Field': (basestring, True),
        'Values': ([basestring], True)
    }


class Matcher(AWSProperty):
    props = {
        'HttpCode': (basestring, False)
    }


class SubnetMapping(AWSProperty):
    props = {
        'AllocationId': (basestring, True),
        'SubnetId': (basestring, True)
    }


class TargetGroupAttribute(AWSProperty):
    props = {
        'Key': (basestring, False),
        'Value': (basestring, False)
    }


class TargetDescription(AWSProperty):
    props = {
        'AvailabilityZone': (basestring, False),
        'Id': (basestring, True),
        'Port': (network_port, False)
    }


class Listener(AWSObject):
    resource_type = "AWS::ElasticLoadBalancingV2::Listener"

    props = {
        'Certificates': ([Certificate], False),
        'DefaultActions': ([Action], True),
        'LoadBalancerArn': (basestring, True),
        'Port': (network_port, True),
        'Protocol': (basestring, True),
        'SslPolicy': (basestring, False)
    }


class ListenerCertificate(AWSObject):
    resource_type = "AWS::ElasticLoadBalancingV2::ListenerCertificate"

    props = {
        'Certificates': ([Certificate], True),
        'ListenerArn': (basestring, True),
    }


class ListenerRule(AWSObject):
    resource_type = "AWS::ElasticLoadBalancingV2::ListenerRule"

    props = {
        'Actions': ([Action], True),
        'Conditions': ([Condition], True),
        'ListenerArn': (basestring, True),
        'Priority': (integer, True)
    }


TARGET_TYPE_INSTANCE = 'instance'
TARGET_TYPE_IP = 'ip'


class TargetGroup(AWSObject):
    resource_type = "AWS::ElasticLoadBalancingV2::TargetGroup"

    props = {
        'HealthCheckIntervalSeconds': (integer, False),
        'HealthCheckPath': (basestring, False),
        'HealthCheckPort': (tg_healthcheck_port, False),
        'HealthCheckProtocol': (basestring, False),
        'HealthCheckTimeoutSeconds': (integer, False),
        'HealthyThresholdCount': (integer, False),
        'Matcher': (Matcher, False),
        'Name': (basestring, False),
        'Port': (network_port, True),
        'Protocol': (basestring, True),
        'Tags': ((Tags, list), False),
        'TargetGroupAttributes': ([TargetGroupAttribute], False),
        'Targets': ([TargetDescription], False),
        'TargetType': (basestring, False),
        'UnhealthyThresholdCount': (integer, False),
        'VpcId': (basestring, True),
    }


class LoadBalancer(AWSObject):
    resource_type = "AWS::ElasticLoadBalancingV2::LoadBalancer"

    props = {
        'LoadBalancerAttributes': ([LoadBalancerAttributes], False),
        'Name': (elb_name, False),
        'Scheme': (basestring, False),
        'IpAddressType': (basestring, False),
        'SecurityGroups': (list, False),
        'SubnetMappings': ([SubnetMapping], False),
        'Subnets': (list, False),
        'Tags': ((Tags, list), False),
        'Type': (basestring, False),
    }

    def validate(self):
        conds = [
            'SubnetMappings',
            'Subnets',
        ]

        def check_if(names, props):
            validated = []
            for name in names:
                validated.append(name in props and isinstance(props[name], If))
            return all(validated)

        if check_if(conds, self.properties):
            return

        exactly_one(self.__class__.__name__, self.properties, conds)
