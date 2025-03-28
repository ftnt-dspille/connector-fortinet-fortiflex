"""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""

import json
from datetime import datetime
from time import time, ctime

import requests
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config

logger = get_logger('fortinet-fortiflex')

REFRESH_TOKEN_FLAG = False
REFRESH_TOKEN = 'refresh_token'


class FortiFlex:
    def __init__(self, config):
        self.username = config.get("username")
        self.password = config.get("password")
        self.client_id = config.get("client_id")
        self.verify_ssl = config.get('verify_ssl')
        self.host = config.get("server")
        # Initialize refresh_token from config if available
        self.refresh_token = config.get("refreshToken")

        if self.host[:7] == "http://":
            self.host = "https://{0}".format(self.host[7:])
        elif self.host[:8] == "https://":
            self.host = "{0}".format(self.host)
        else:
            self.host = "https://{0}".format(self.host)

    def convert_ts_epoch(self, ts):
        datetime_object = datetime.strptime(ctime(ts), "%a %b %d %H:%M:%S %Y")
        return datetime_object.timestamp()

    def generate_token(self, REFRESH_TOKEN_FLAG):
        try:
            token_resp = acquire_token(self, REFRESH_TOKEN_FLAG)
            ts_now = time()
            token_resp['expiresOn'] = (ts_now + token_resp['expires_in']) if token_resp.get("expires_in") else None
            token_resp['accessToken'] = token_resp.get("access_token")
            token_resp['refreshToken'] = token_resp.get("refresh_token")

            # Make sure to update the instance refresh_token for future refreshes
            if token_resp.get("refresh_token"):
                self.refresh_token = token_resp.get("refresh_token")

            token_resp.pop("access_token", None)
            token_resp.pop("refresh_token", None)
            return token_resp
        except Exception as err:
            logger.error("{0}".format(err))
            raise ConnectorError("{0}".format(err))

    def validate_token(self, connector_config, connector_info):
        try:
            ts_now = time()
            if not connector_config.get('accessToken'):
                logger.error('Error occurred while connecting server: Unauthorized')
                raise ConnectorError('Error occurred while connecting server: Unauthorized')

            expires = connector_config['expiresOn']
            expires_ts = self.convert_ts_epoch(expires)

            if ts_now > float(expires_ts):
                logger.info("Token expired at {0}".format(expires))

                # Make sure refresh_token is available
                if not self.refresh_token and connector_config.get('refreshToken'):
                    self.refresh_token = connector_config['refreshToken']

                if not self.refresh_token:
                    logger.error("No refresh token available for renewal")
                    raise ConnectorError("No refresh token available. Please reconfigure the connector.")

                token_resp = self.generate_token(True)  # Always pass True for REFRESH_TOKEN_FLAG when refreshing

                connector_config['accessToken'] = token_resp['accessToken']
                connector_config['expiresOn'] = token_resp['expiresOn']

                if token_resp.get('refreshToken'):
                    connector_config['refreshToken'] = token_resp['refreshToken']

                update_connnector_config(
                    connector_info['connector_name'],
                    connector_info['connector_version'],
                    connector_config,
                    connector_config['config_id']
                )

                return "Bearer {0}".format(connector_config.get('accessToken'))
            else:
                logger.info("Token is valid till {0}".format(expires))
                return "Bearer {0}".format(connector_config.get('accessToken'))
        except Exception as err:
            logger.error("{0}".format(str(err)))
            raise ConnectorError("{0}".format(str(err)))


def acquire_token(self, REFRESH_TOKEN_FLAG):
    try:
        headers = {
            'Content-Type': 'application/json'
        }

        if not REFRESH_TOKEN_FLAG:
            data = {
                "username": self.username,
                "password": self.password,
                "client_id": self.client_id,
                "grant_type": "password"
            }
        else:
            if not self.refresh_token:
                raise ConnectorError("No refresh token available")

            data = {
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
                "client_id": self.client_id
            }

        logger.debug(
            "Payload: {0}".format({k: '***' if k in ['password', 'refresh_token'] else v for k, v in data.items()}))
        endpoint = 'https://customerapiauth.fortinet.com/api/v1/oauth/token/'
        logger.debug("Endpoint: {0}".format(endpoint))

        response = requests.post(endpoint, data=json.dumps(data), headers=headers, verify=self.verify_ssl, timeout=60)
        logger.debug("Response Status: {0}".format(response.status_code))

        if response.status_code in [200, 204, 201]:
            return response.json()
        else:
            error_msg = ''
            if response.text:
                try:
                    err_resp = response.json()
                    if err_resp and 'error' in err_resp:
                        failure_msg = err_resp.get('error_description', '')
                        error_msg = 'Response {0}: {1} \n Error Message: {2}'.format(
                            response.status_code, response.reason, failure_msg
                        )
                    else:
                        error_msg = 'Response {0}: {1} \n Error Message: {2}'.format(
                            response.status_code, response.reason, response.text
                        )
                except ValueError:
                    error_msg = 'Response {0}: {1} \n Error Message: {2}'.format(
                        response.status_code, response.reason, response.text
                    )
            else:
                error_msg = 'Response {0}: {1}'.format(response.status_code, response.reason)

            logger.error(error_msg)
            raise ConnectorError(error_msg)

    except requests.exceptions.RequestException as e:
        error_msg = f"Request error: {str(e)}"
        logger.error(error_msg)
        raise ConnectorError(error_msg)
    except Exception as err:
        error_msg = f"Unexpected error: {str(err)}"
        logger.error(error_msg)
        raise ConnectorError(error_msg)


def check(config, connector_info):
    try:
        co = FortiFlex(config)
        if 'accessToken' not in config:
            token_resp = co.generate_token(False)  # Pass False for initial token generation
            config['accessToken'] = token_resp.get('accessToken')
            config['expiresOn'] = token_resp.get('expiresOn')
            config['refreshToken'] = token_resp.get('refreshToken')
            update_connnector_config(
                connector_info['connector_name'],
                connector_info['connector_version'],
                config,
                config['config_id']
            )
            return True
        else:
            co.validate_token(config, connector_info)
            return True
    except Exception as err:
        logger.error(f"Health check failed: {str(err)}")
        raise ConnectorError(str(err))
