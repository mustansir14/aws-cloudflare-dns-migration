import os
from typing import Union, get_type_hints

from dotenv import load_dotenv

load_dotenv()


class AppEnvError(Exception):
    pass


def _parse_bool(val: Union[str, bool]) -> bool:  # pylint: disable=E1136
    return val if type(val) == bool else val.lower() in ["true", "yes", "1"]


# AppEnv class with required fields, default values, type checking, and typecasting for int and bool values


class AppEnv:
    SCENARIO: int
    AWS_ACCESS_KEY_ID: str
    AWS_SECRET_ACCESS_KEY: str
    CLOUDFLARE_EMAIL: str
    CLOUDFLARE_API_KEY: str
    SKIP_DNS_SYNC: bool = False
    PRIMARY_IP: str = ""
    SECONDARY_IP: str = ""
    HEALTH_CHECK_ID: str = ""
    CREATE_FAILOVER_RECORDS: bool = True
    LOAD_BALANCER_IP: str = ""

    """
    Map environment variables to class fields according to these rules:
      - Field won't be parsed unless it has a type annotation
      - Field will be skipped if not in all caps
      - Class field and environment variable name are the same
    """

    def __init__(self, env):
        for field in self.__annotations__:
            if not field.isupper():
                continue

            # Raise AppEnvError if required field not supplied
            default_value = getattr(self, field, None)
            if default_value is None and env.get(field) is None:
                raise AppEnvError("The {} field is required".format(field))

            # Cast env var value to expected type and raise AppEnvError on failure
            try:
                var_type = get_type_hints(AppEnv)[field]
                if var_type == bool:
                    value = _parse_bool(env.get(field, default_value))
                else:
                    value = var_type(env.get(field, default_value))

                self.__setattr__(field, value)
            except ValueError:
                raise AppEnvError(
                    'Unable to cast value of "{}" to type "{}" for "{}" field'.format(
                        env[field], var_type, field
                    )
                )

        if self.SCENARIO not in [1, 2, 3]:
            raise AppEnvError("SCENARIO must be one of 1, 2, 3")

        if self.SCENARIO == 1 and (
            self.PRIMARY_IP == ""
            or self.SECONDARY_IP == ""
            or self.LOAD_BALANCER_IP == ""
        ):
            raise AppEnvError(
                "PRIMARY_IP, SECONDARY_IP and LOAD_BALANCER_IP are required for SCENARIO 1"
            )

        if (
            self.SCENARIO == 3
            and self.CREATE_FAILOVER_RECORDS
            and self.PRIMARY_IP == ""
        ):
            raise AppEnvError(
                "PRIMARY_IP is required for SCENARIO 3 and CREATE_FAILOVER_RECORDS=1"
            )

        if (
            self.SCENARIO == 3
            and self.CREATE_FAILOVER_RECORDS
            and self.SECONDARY_IP == ""
        ):
            raise AppEnvError(
                "SECONDARY_IP is required for SCENARIO 3 and CREATE_FAILOVER_RECORDS=1"
            )

        if (
            self.SCENARIO == 3
            and self.CREATE_FAILOVER_RECORDS
            and self.HEALTH_CHECK_ID == ""
        ):
            raise AppEnvError(
                "HEALTH_CHECK_ID is required for SCENARIO 3 and CREATE_FAILOVER_RECORDS=1"
            )

        print(f"Env loaded: {self.__dict__}")

    def __repr__(self):
        return str(self.__dict__)


# Expose Env object for app to import
Env = AppEnv(os.environ)
