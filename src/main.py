import traceback

from pycti import OpenCTIConnectorHelper
from opentip import OpenTIPConnector
from opentip.models.configs.config_loader import ConfigLoader

if __name__ == "__main__":
    try:
        config = ConfigLoader()
        helper = OpenCTIConnectorHelper(
            config=config.model_dump_pycti(), playbook_compatible=True
        )
        connector = OpenTIPConnector(config, helper)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
